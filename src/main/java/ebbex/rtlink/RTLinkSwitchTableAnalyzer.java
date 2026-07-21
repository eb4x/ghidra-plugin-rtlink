/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the CS-relative switch tables in RTLink/Plus resident code, which the stock
 * decompiler-driven switch analysis gets wrong.
 * <p>
 * <b>Why the stock path fails.</b> A resident logical segment is based at a paragraph that is not a
 * 64KB-page boundary (e.g. {@code 1aea:000b}). The x86 {@code currentCS} subconstructor
 * ({@code ia.sinc}) does not read the CS register; it recomputes a code segment from the program
 * counter as {@code (inst_next >> 4) & 0xf000}, which for such a block yields the enclosing page
 * ({@code 0x1000}) instead of the real paragraph. That recompute exists on purpose — {@code CALLF}
 * ({@code ptr1616}) writes the callee's segment into CS and nothing restores it on return, so CS is
 * untrustworthy — but it is correct only when a code segment happens to start on a page boundary.
 * The write-back also lands <i>before</i> the memory operand's address is built, so both the table
 * load and the jump target resolve against the page segment: {@code JMP word ptr CS:[BX+0x22]} at
 * {@code 1aea:001d} reads its table at {@code 1000:0022} rather than {@code 1aea:0022} and scatters
 * computed-jump references across unrelated segments.
 * <p>
 * <b>What this does.</b> It matches the dispatch idiom, reads the table at the block's true
 * paragraph, and lays down the correct {@code COMPUTED_JUMP} references itself. That both fixes the
 * flow and — because {@link DecompilerSwitchAnalyzer} skips any computed branch that already carries
 * computed references — stops the stock analyzer from ever disassembling the bogus targets. It must
 * therefore run <i>before</i> {@code CODE_ANALYSIS}: once the wrong references and their wrong
 * disassembly exist, nothing rewrites them.
 * <p>
 * Fixing the references leaves the decompiler's own p-code still reading the table at the page
 * segment. {@link RTLinkSwitchOverrideAnalyzer} completes the repair once functions exist.
 * <p>
 * <b>The formatter FSM</b> fails for a third reason: its switch index is produced by
 * {@code XLAT}, so no {@code CMP} in the instruction stream bounds it and the decompiler
 * fabricates cases for the whole byte range. The bound lives in the FSM's own state table;
 * see {@link #recoverFormatterFsmTable}.
 * <p>
 * <b>Overlay blocks</b> fail differently. They are based at {@code 1000:0000}, so the paragraph
 * {@code currentCS} synthesises is right — but only for the page's <i>first</i> module. RTLink
 * packs several link-time modules into one page, and each executes with CS = page frame + its own
 * base paragraph, so a dispatch in a later module reads its table (and interprets every entry)
 * relative to that module base, which nothing in the address stream reveals. The bases are
 * recorded per block by {@link RTLinkOverlayAnalyzer} when the overlay is created; the module
 * containing the dispatch is the one whose base is nearest at or below it.
 */
public class RTLinkSwitchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Switch Table";
	private static final String DESCRIPTION =
		"Recovers CS-relative jump tables in resident code whose segment is not 64KB-page " +
			"aligned, which the x86 currentCS constructor resolves against the wrong paragraph, " +
			"and module-relative jump tables in overlay pages.";

	/** {@code JMP word ptr CS:[BX + disp16]} — CS prefix, opcode FF /4, mod=10 r/m=111. */
	private static final byte[] DISPATCH_OPCODE = { 0x2e, (byte) 0xff, (byte) 0xa7 };
	private static final int DISPATCH_LENGTH = 5;

	/** Instructions to look back over for the {@code CMP} that bounds the switch index. */
	private static final int GUARD_SCAN_LIMIT = 8;

	/** Refuse absurd tables rather than trusting a mis-parsed guard. */
	private static final int MAX_TABLE_ENTRIES = 512;

	/** {@code JMP word ptr [reg]} — opcode FF, reg field 4, for the DGROUP-table form. */
	private static final byte DATA_DISPATCH_OPCODE = (byte) 0xFF;
	private static final int DATA_DISPATCH_REG_OPCODE = 4;

	/**
	 * A DGROUP table is bounded by its entries rather than by a guard, so a single valid
	 * entry proves nothing — that is one plausible word, which data is full of. Two
	 * consecutive ones landing inside the dispatching function is already a strong signal.
	 */
	private static final int MIN_DATA_TABLE_ENTRIES = 2;

	/**
	 * Instructions to scan above the formatter FSM's second {@code XLAT} for the
	 * {@code CMP} class bound and the {@code MOV BX,imm} table base.
	 */
	private static final int FSM_PROLOGUE_SCAN_LIMIT = 10;

	/** The FSM's next state is a nibble ({@code SHR AL,4}), so 16 states bound everything. */
	private static final int MAX_FSM_STATES = 16;

	public RTLinkSwitchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Before CODE_ANALYSIS, which is where DecompilerSwitchAnalyzer runs. It ignores any
		// computed branch that already has computed references, so winning this race is what
		// keeps the bogus targets from being disassembled into other segments.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ReferenceManager refManager = program.getReferenceManager();
		AddressSet targets = new AddressSet();
		List<Instruction> dispatches = new ArrayList<>();

		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();

			List<Address> destinations = recoverTable(program, instruction);
			if (destinations == null || hasComputedReference(refManager, instruction)) {
				continue;
			}
			for (Address destination : destinations) {
				refManager.addMemoryReference(instruction.getMinAddress(), destination,
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
				targets.addRange(destination, destination);
			}
			dispatches.add(instruction);
		}

		int recovered = dispatches.size();
		if (recovered == 0) {
			return true;
		}
		// Disassemble the real targets now; leaving them undefined would let a later pass drift
		// back into the table bytes.
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);

		// The references above extend flows that existing function bodies do not yet
		// cover, and nothing downstream recomputes them for switches resolved here
		// (DecompilerSwitchAnalyzer performs this fixup only for its own). Left alone,
		// a case region discovered late stays outside its owner's body — in
		// NEBULAR.EXE OVERLAY_19 an entire case chain, containing a second dispatch,
		// was orphaned that way. Fixups run after the whole recovery loop so a body
		// absorbs the case flows of every dispatch it reaches, not just the first.
		for (Instruction dispatch : dispatches) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, dispatch, monitor);
		}

		// Msg.info only — see RTLinkSwitchOverrideAnalyzer: a success count in the analysis
		// MessageLog pops the "warnings/errors issued during analysis" dialog.
		Msg.info(this,
			String.format("RTLink/Plus: Recovered %d switch table(s)", recovered));
		return true;
	}

	/**
	 * Returns the switch destinations for {@code instruction} if it is a CS-relative
	 * dispatch whose table can be read with confidence, otherwise null.
	 * <p>
	 * Shared with {@link RTLinkSwitchOverrideAnalyzer} so both passes agree, byte for byte, on
	 * which sites are dispatchers and where they go.
	 */
	static List<Address> recoverTable(Program program, Instruction instruction) {
		MemoryBlock block = program.getMemory().getBlock(instruction.getMinAddress());
		if (block == null || !block.isExecute()) {
			return null;
		}
		if (block.isOverlay()) {
			return recoverOverlayTable(program, instruction, block);
		}
		List<Address> dataTable = recoverDataTable(program, instruction, block);
		if (dataTable != null) {
			return dataTable;
		}
		int displacement = dispatchDisplacement(instruction);
		if (displacement < 0) {
			return null;
		}
		// The formatter FSM is matched regardless of segment alignment: its dispatch is
		// unbounded for the decompiler even where currentCS resolves correctly, so it
		// needs the references (and the override) either way.
		List<Address> fsmTable = recoverFormatterFsmTable(program, instruction, block,
			displacement);
		if (fsmTable != null) {
			return fsmTable;
		}
		if (!isUnalignedSegment(block)) {
			return null;
		}
		int entries = tableEntryCount(instruction, block);
		if (entries < 0) {
			return null;
		}

		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		int segment = ((SegmentedAddress) block.getStart()).getSegment();

		// The table and every entry must live inside the segment they are addressed from; a
		// 16-bit offset that would wrap means the guard was misread, so give up rather than
		// invent targets.
		long lastByte = (long) displacement + 2L * entries - 1;
		if (lastByte > 0xffffL) {
			return null;
		}
		Address table = space.getAddress(segment, displacement);
		if (!block.contains(table) || !block.contains(space.getAddress(segment, (int) lastByte))) {
			return null;
		}

		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < entries; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				Address destination = space.getAddress(segment, offset);
				if (!block.contains(destination)) {
					return null;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * Recover the dispatch of the MSC {@code _output} formatter state machine — the printf
	 * engine every binary in this corpus carries, and the one computed jump whose index is
	 * produced by {@code XLAT} rather than bounded by a {@code CMP}:
	 * <pre>
	 *   MOV BX,0x2a56        ; combined class/transition table, a DS offset
	 *   SUB AL,0x20          ; c - ' '
	 *   CMP AL,0x58
	 *   JA  +5               ; out of range: class 0
	 *   XLAT                 ; AL = table[c-' ']
	 *   AND AL,0xF           ; low nibble = character class
	 *   JMP +2
	 *   MOV AL,0x0
	 *   MOV CL,3
	 *   SHL AL,CL            ; class * 8
	 *   ADD AL,[BP-x]        ; + current state
	 *   XLAT                 ; same BX — same table
	 *   INC CL
	 *   SHR AL,CL            ; high nibble = next state
	 *   MOV [BP-x],AL
	 *   CBW
	 *   MOV BX,AX
	 *   SHL BX,1
	 *   JMP word ptr CS:[BX + disp16]      ; VICEROY 1d1d:19c0
	 * </pre>
	 * No instruction bounds the final index, so {@link #tableEntryCount} cannot count this
	 * and the decompiler, left to itself, fabricates cases for the full byte range of the
	 * {@code XLAT} load (its range analysis honors only {@code INT_AND} masks, not the
	 * {@code SHR}). But the bound is in the FSM's own data: the table serves two purposes at
	 * once — the low nibble of {@code table[c-' ']} classifies the character, and the high
	 * nibble of {@code table[class*8 + state]} is the next state, the two regions sharing
	 * the same bytes by design — so the reachable states, and with them the jump table's
	 * entry count, follow from a fixpoint over the table ({@link #fsmStateCount}).
	 * <p>
	 * The prologue is matched instruction-for-instruction and the match is deliberately
	 * tight: this is one known library routine (byte-identical across all four corpus
	 * binaries), and a miss merely reproduces the old behavior — the dispatch stays
	 * unresolved — while a false positive would plant wrong flow. The {@code MOV CL,3} /
	 * {@code INC CL} pair is what proves the two shift widths, and with them both the
	 * {@code class*8} table layout and the nibble ceiling of {@value #MAX_FSM_STATES}
	 * states. Both {@code XLAT}s must be bare {@code D7} — a segment override would mean a
	 * different table entirely. The derived count is then held against the jump table
	 * itself: every entry must be a case target of the dispatching function (the
	 * {@link #dispatchRange} test the DGROUP form already relies on), and none may point
	 * back into the table.
	 */
	private static List<Address> recoverFormatterFsmTable(Program program, Instruction dispatch,
			MemoryBlock block, int displacement) {
		Register al = program.getLanguage().getRegister("AL");
		Register ax = program.getLanguage().getRegister("AX");
		Register bx = program.getLanguage().getRegister("BX");
		Register cl = program.getLanguage().getRegister("CL");
		if (al == null || ax == null || bx == null || cl == null) {
			return null;
		}

		// SHL BX,1 (or ADD BX,BX)
		Instruction scale = previousInBlock(dispatch, block);
		if (scale == null || !isDoublingOf(scale, bx)) {
			return null;
		}
		// MOV BX,AX
		Instruction widen = previousInBlock(scale, block);
		if (widen == null || !"MOV".equals(widen.getMnemonicString()) ||
			!bx.equals(widen.getRegister(0)) || !ax.equals(widen.getRegister(1))) {
			return null;
		}
		// CBW
		Instruction extend = previousInBlock(widen, block);
		if (extend == null || !"CBW".equals(extend.getMnemonicString())) {
			return null;
		}
		// MOV [BP-x],AL — the state variable's slot
		Instruction store = previousInBlock(extend, block);
		Scalar stateSlot = store == null ? null : bpDisplacement(store, 0);
		if (stateSlot == null || !"MOV".equals(store.getMnemonicString()) ||
			!al.equals(store.getRegister(1))) {
			return null;
		}
		// SHR AL,CL
		Instruction shift = previousInBlock(store, block);
		if (shift == null || !"SHR".equals(shift.getMnemonicString()) ||
			!al.equals(shift.getRegister(0)) || !cl.equals(shift.getRegister(1))) {
			return null;
		}
		// INC CL
		Instruction bump = previousInBlock(shift, block);
		if (bump == null || !"INC".equals(bump.getMnemonicString()) ||
			!cl.equals(bump.getRegister(0))) {
			return null;
		}
		// XLAT — the transition lookup
		Instruction translate = previousInBlock(bump, block);
		if (translate == null || !isPlainXlat(translate)) {
			return null;
		}
		// ADD AL,[BP-x] — same slot the next state is stored back to
		Instruction stateIn = previousInBlock(translate, block);
		Scalar indexSlot = stateIn == null ? null : bpDisplacement(stateIn, 1);
		if (indexSlot == null || !"ADD".equals(stateIn.getMnemonicString()) ||
			!al.equals(stateIn.getRegister(0)) ||
			indexSlot.getSignedValue() != stateSlot.getSignedValue()) {
			return null;
		}
		// SHL AL,CL
		Instruction classScale = previousInBlock(stateIn, block);
		if (classScale == null || !"SHL".equals(classScale.getMnemonicString()) ||
			!al.equals(classScale.getRegister(0)) || !cl.equals(classScale.getRegister(1))) {
			return null;
		}
		// MOV CL,3
		Instruction three = previousInBlock(classScale, block);
		if (three == null || !"MOV".equals(three.getMnemonicString()) ||
			!cl.equals(three.getRegister(0)) || !isScalar(three.getScalar(1), 3)) {
			return null;
		}

		// Above the join sit the class lookup, its CMP bound, and the table base. Their
		// order is fixed in the corpus but the JA/JMP join makes strict sequencing brittle,
		// so within a small window: find them all, and let nothing redefine BX — it carries
		// the table base into both XLATs.
		int classLimit = -1;
		int tableOffset = -1;
		boolean sawClassLookup = false;
		boolean sawClassMask = false;
		Instruction instruction = previousInBlock(three, block);
		for (int i = 0; i < FSM_PROLOGUE_SCAN_LIMIT && instruction != null; i++) {
			String mnemonic = instruction.getMnemonicString();
			if ("MOV".equals(mnemonic) && bx.equals(instruction.getRegister(0))) {
				Scalar table = instruction.getScalar(1);
				if (table == null) {
					return null;
				}
				tableOffset = (int) table.getUnsignedValue();
				break; // the table base is the far anchor; the walk is done
			}
			if (defines(instruction, bx)) {
				return null;
			}
			if ("XLAT".equals(mnemonic)) {
				if (!isPlainXlat(instruction)) {
					return null;
				}
				sawClassLookup = true;
			}
			else if ("AND".equals(mnemonic) && al.equals(instruction.getRegister(0)) &&
				isScalar(instruction.getScalar(1), 0xf)) {
				sawClassMask = true;
			}
			else if ("CMP".equals(mnemonic) && al.equals(instruction.getRegister(0))) {
				Scalar bound = instruction.getScalar(1);
				// The compared value is c-' ', a byte; a bound past 0xdf could not be one.
				if (bound == null || bound.getUnsignedValue() > 0xdf) {
					return null;
				}
				classLimit = (int) bound.getUnsignedValue();
			}
			instruction = previousInBlock(instruction, block);
		}
		if (tableOffset < 0 || classLimit < 0 || !sawClassLookup || !sawClassMask) {
			return null;
		}

		// The table is at DS:tableOffset; the CMP proves bytes 0..classLimit of it. This
		// reads memory directly, not p-code, so it does not depend on XLAT's p-code
		// getting the segment right.
		Register ds = program.getLanguage().getRegister("DS");
		if (ds == null) {
			return null;
		}
		RegisterValue dsValue =
			program.getProgramContext().getRegisterValue(ds, dispatch.getMinAddress());
		if (dsValue == null || !dsValue.hasValue()) {
			return null;
		}
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Address table = space.getAddress(dsValue.getUnsignedValue().intValue() & 0xffff,
			tableOffset);
		MemoryBlock tableBlock = program.getMemory().getBlock(table);
		if (tableBlock == null || !tableBlock.isInitialized()) {
			return null;
		}
		byte[] tableBytes = new byte[classLimit + 1];
		try {
			if (program.getMemory().getBytes(table, tableBytes) != tableBytes.length) {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}

		int states = fsmStateCount(tableBytes);
		if (states < MIN_DATA_TABLE_ENTRIES) {
			return null; // covers -1 too: a transition escaped the proven table region
		}

		// The jump table is CS-relative at the dispatch's own paragraph. Hold the derived
		// state count against it: every entry must be a case target.
		AddressSetView range = dispatchRange(program, dispatch, block);
		if (range == null) {
			return null;
		}
		int segment = ((SegmentedAddress) block.getStart()).getSegment();
		long lastByte = (long) displacement + 2L * states - 1;
		if (lastByte > 0xffffL) {
			return null;
		}
		Address jumpTable = space.getAddress(segment, displacement);
		if (!block.contains(jumpTable) ||
			!block.contains(space.getAddress(segment, (int) lastByte))) {
			return null;
		}
		Listing listing = program.getListing();
		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < states; i++) {
				int offset = program.getMemory().getShort(jumpTable.add(2L * i)) & 0xffff;
				if (offset >= displacement && offset <= lastByte) {
					return null; // a case target inside the table: the count is wrong
				}
				Address destination = space.getAddress(segment, offset);
				if (!range.contains(destination)) {
					return null;
				}
				Instruction existing = listing.getInstructionContaining(destination);
				if (existing != null && !existing.getMinAddress().equals(destination)) {
					return null;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * The number of jump-table entries the formatter FSM can reach — {@code max reachable
	 * state + 1} — or -1 when the table does not hold together.
	 * <p>
	 * Fixpoint: every low nibble in the table is a reachable class (plus class 0, which the
	 * {@code JA} maps out-of-range characters to), state 0 is the start state, and each
	 * reachable {@code (class, state)} pair yields the state in the high nibble of
	 * {@code table[class*8 + state]}. A transition index past the table's proven extent
	 * means the layout assumption is wrong, so no count is claimed at all rather than a
	 * partial one.
	 */
	private static int fsmStateCount(byte[] table) {
		boolean[] classes = new boolean[MAX_FSM_STATES];
		classes[0] = true;
		for (byte classified : table) {
			classes[classified & 0xf] = true;
		}
		boolean[] states = new boolean[MAX_FSM_STATES];
		states[0] = true;
		boolean grew = true;
		while (grew) {
			grew = false;
			for (int clazz = 0; clazz < classes.length; clazz++) {
				if (!classes[clazz]) {
					continue;
				}
				for (int state = 0; state < states.length; state++) {
					if (!states[state]) {
						continue;
					}
					int transition = clazz * 8 + state;
					if (transition >= table.length) {
						return -1;
					}
					int next = (table[transition] >> 4) & 0xf;
					if (!states[next]) {
						states[next] = true;
						grew = true;
					}
				}
			}
		}
		int highest = 0;
		for (int state = 0; state < states.length; state++) {
			if (states[state]) {
				highest = state;
			}
		}
		return highest + 1;
	}

	/**
	 * The previous instruction if it exists and is still inside {@code block}, else null.
	 */
	private static Instruction previousInBlock(Instruction instruction, MemoryBlock block) {
		Instruction previous = instruction.getPrevious();
		if (previous == null || !block.contains(previous.getMinAddress())) {
			return null;
		}
		return previous;
	}

	/**
	 * True for a bare one-byte {@code XLAT} ({@code D7}). A segment override changes which
	 * table the lookup reads, so an overridden {@code XLAT} must not match the FSM idiom.
	 */
	private static boolean isPlainXlat(Instruction instruction) {
		if (!"XLAT".equals(instruction.getMnemonicString())) {
			return false;
		}
		try {
			byte[] bytes = instruction.getBytes();
			return bytes.length == 1 && bytes[0] == (byte) 0xd7;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * The constant displacement of a {@code [BP + disp]} memory operand at {@code opIndex},
	 * or null if the operand is anything else.
	 */
	private static Scalar bpDisplacement(Instruction instruction, int opIndex) {
		Register bp = null;
		Scalar displacement = null;
		for (Object object : instruction.getOpObjects(opIndex)) {
			if (object instanceof Register register && "BP".equals(register.getName())) {
				bp = register;
			}
			else if (object instanceof Scalar scalar) {
				if (displacement != null) {
					return null;
				}
				displacement = scalar;
			}
			else {
				return null;
			}
		}
		return bp == null ? null : displacement;
	}

	private static boolean isScalar(Scalar scalar, long value) {
		return scalar != null && scalar.getUnsignedValue() == value;
	}

	/**
	 * Recover a switch table that lives in <b>DGROUP data</b> rather than after the code,
	 * dispatched through {@code JMP word ptr [reg]}:
	 * <pre>
	 *   MOV DI,0xb26a          ; table base — a DS offset, not a CS one
	 *   XOR CX,CX
	 *   MOV CL,[BX + SI + 5]   ; the index, straight out of a struct field
	 *   ADD DI,CX
	 *   JMP word ptr [DI]      ; ROE2MAIN.EXE 122e:5280
	 * </pre>
	 * Nothing bounds this table the way a {@code CMP} bounds the CS-relative form — the
	 * index is a byte read from memory, already scaled — so the entries themselves have to
	 * settle where the table ends: read words until one is not a plausible case target.
	 * <p>
	 * A case target lies inside the function that dispatches to it, and that is the bound
	 * used — see {@link #dispatchRange}. It is a sharp one here: ROE2MAIN's table is four
	 * entries ({@code 52ae, 5282, 528a, 52a3}, all within {@code FUN_122e_51d5}) followed
	 * immediately by unrelated variables whose first word, {@code 0x0078}, is a perfectly
	 * valid instruction address in the same block — inside a <em>different</em> function.
	 * Only the containing-function test rejects it; "is it code" does not.
	 * <p>
	 * Recovering it matters beyond the table: left alone, {@code DecompilerSwitchAnalyzer}
	 * tries to resolve the branch itself, fails to bound it, and explores — 117 seconds of
	 * analysis and a flood of p-code errors chasing garbage targets into unmapped memory,
	 * all from this one dispatch. Adding computed references is what makes it stand down.
	 */
	private static List<Address> recoverDataTable(Program program, Instruction dispatch,
			MemoryBlock block) {
		Register base = dataDispatchRegister(dispatch);
		if (base == null) {
			return null;
		}

		// Walk back for the two instructions that build the pointer: the index being added
		// in, and the constant table base it is added to. Any other write of the base
		// register in between means this is not the idiom.
		int tableOffset = -1;
		Instruction instruction = dispatch.getPrevious();
		boolean indexAdded = false;
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return null;
			}
			if (!indexAdded) {
				if ("ADD".equals(instruction.getMnemonicString()) &&
					base.equals(instruction.getRegister(0)) &&
					instruction.getRegister(1) != null) {
					indexAdded = true;
				}
				else if (defines(instruction, base)) {
					return null;
				}
			}
			else if ("MOV".equals(instruction.getMnemonicString()) &&
				base.equals(instruction.getRegister(0))) {
				Scalar table = instruction.getScalar(1);
				if (table == null) {
					return null;
				}
				tableOffset = (int) table.getUnsignedValue();
				break;
			}
			else if (defines(instruction, base)) {
				return null;
			}
			instruction = instruction.getPrevious();
		}
		if (tableOffset < 0) {
			return null;
		}

		// The table is at DS:offset. DS is only set over code by RTLinkOverlayAnalyzer's
		// DGROUP pass, so a value here both names the segment and confirms the assumption
		// holds at this instruction.
		Register ds = program.getLanguage().getRegister("DS");
		if (ds == null) {
			return null;
		}
		RegisterValue dsValue =
			program.getProgramContext().getRegisterValue(ds, dispatch.getMinAddress());
		if (dsValue == null || !dsValue.hasValue()) {
			return null;
		}

		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Address table = space.getAddress(dsValue.getUnsignedValue().intValue() & 0xffff,
			tableOffset);
		if (!program.getMemory().contains(table)) {
			return null;
		}

		AddressSetView range = dispatchRange(program, dispatch, block);
		if (range == null) {
			Msg.debug(RTLinkSwitchTableAnalyzer.class,
				String.format("RTLink: data dispatch at %s reads a table at %s, but nothing calls "
					+ "into the code around it — cannot bound the table",
					dispatch.getMinAddress(), table));
			return null;
		}
		int segment = ((SegmentedAddress) block.getStart()).getSegment();

		Listing listing = program.getListing();
		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < MAX_TABLE_ENTRIES; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				Address destination = space.getAddress(segment, offset);
				// The first entry that is not a case target of this function ends the
				// table — there is nothing else to say where it stops. "Case target"
				// cannot mean "already an instruction": these targets are reachable only
				// through the table, so nothing has disassembled them yet. It means
				// inside the dispatching function and not splitting an instruction that
				// is already there — the same test the overlay path makes.
				if (!range.contains(destination)) {
					break;
				}
				Instruction existing = listing.getInstructionContaining(destination);
				if (existing != null && !existing.getMinAddress().equals(destination)) {
					break;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}

		// One entry is not a switch; it is a coincidence.
		if (destinations.size() < MIN_DATA_TABLE_ENTRIES) {
			Msg.debug(RTLinkSwitchTableAnalyzer.class,
				String.format("RTLink: data dispatch at %s reads a table at %s that yields only "
					+ "%d target(s) in %s — not taken as a switch", dispatch.getMinAddress(),
					table, destinations.size(), range));
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * The base register of a {@code JMP word ptr [reg]} — a computed jump through memory
	 * with no segment override and no displacement — or null if {@code dispatch} is not one.
	 * A {@code CS:} override means the CS-relative form, which {@link #recoverTable}
	 * handles; a displacement means a single function pointer, not a table.
	 */
	private static Register dataDispatchRegister(Instruction dispatch) {
		if (!dispatch.getFlowType().isComputed() || !dispatch.getFlowType().isJump()) {
			return null;
		}
		byte[] bytes;
		try {
			bytes = dispatch.getBytes();
		}
		catch (MemoryAccessException e) {
			return null;
		}
		// FF /4 with mod=00 and no SIB/disp16: exactly [BX], [SI], [DI] or [BX+SI]-style.
		if (bytes.length != 2 || bytes[0] != DATA_DISPATCH_OPCODE) {
			return null;
		}
		int modrm = bytes[1] & 0xff;
		if ((modrm >> 6) != 0 || ((modrm >> 3) & 0x7) != DATA_DISPATCH_REG_OPCODE) {
			return null;
		}
		// The operand is memory, not a register, so getRegister() does not answer this —
		// the base register has to be picked out of the operand's objects.
		for (Object operand : dispatch.getOpObjects(0)) {
			if (operand instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	/**
	 * The address range of the function containing {@code dispatch} — the region its case
	 * targets must lie in — or null when it cannot be established.
	 * <p>
	 * Bounded by <b>call targets</b>, not by the {@link FunctionManager} and not by a
	 * {@link Function#getBody() body}, because neither is usable here:
	 * <ul>
	 * <li>The body is derived by following flow, and the case targets of an unresolved
	 * computed jump are reachable only <em>through</em> the table — they are precisely the
	 * addresses the body leaves out. Bounding by it asks the switch to be resolved before
	 * it can be resolved.
	 * <li>The functions themselves may not exist yet. {@code FunctionAnalyzer} ("Create
	 * Function") sits at the same {@code CODE_ANALYSIS.before()} priority as this analyzer,
	 * and equal priorities run first-queued-first, so whether the dispatching function has
	 * been created when we look is not ours to decide. In ROE2MAIN.EXE it has not been:
	 * {@code FUN_122e_51d5} does not exist when {@code 122e:5280} is examined.
	 * </ul>
	 * What does exist by then is the disassembler's own call references. A function begins
	 * where something calls it, which is what {@code FunctionAnalyzer} keys on too, so the
	 * nearest call target at or below the dispatch starts the range and the nearest one
	 * above it ends the range — the same answer, one pass earlier.
	 */
	private static AddressSetView dispatchRange(Program program, Instruction dispatch,
			MemoryBlock block) {
		Address at = dispatch.getMinAddress();
		Address start = nearestCallTarget(program, block, at, false);
		if (start == null) {
			return null;
		}
		Address after = at.next();
		Address above =
			after == null ? null : nearestCallTarget(program, block, after, true);
		Address end = above == null ? block.getEnd() : above.subtract(1);
		return start.compareTo(end) > 0 ? null : new AddressSet(start, end);
	}

	/**
	 * The nearest address in {@code block} that something calls, searching from {@code from}
	 * (inclusive) in the given direction, or null if the block runs out first.
	 */
	private static Address nearestCallTarget(Program program, MemoryBlock block, Address from,
			boolean forward) {
		ReferenceManager references = program.getReferenceManager();
		AddressIterator targets = references.getReferenceDestinationIterator(from, forward);
		while (targets.hasNext()) {
			Address target = targets.next();
			if (!block.contains(target)) {
				return null; // left the block: no call target this side of it
			}
			for (Reference reference : references.getReferencesTo(target)) {
				if (reference.getReferenceType().isCall()) {
					return target;
				}
			}
		}
		return null;
	}

	/**
	 * Overlay variant of {@link #recoverTable}. The dispatch's module is the one whose
	 * recorded base paragraph is nearest at or below it, ending at the next base (or the
	 * block end); the table displacement and every table entry are offsets from that
	 * base, mirroring the module's runtime CS.
	 * <p>
	 * The recorded base set is not exhaustive — a module referenced by no relocation
	 * does not appear — and a missing base would make this resolve against the previous
	 * module. Two things guard against that: an entry may not land in the middle of an
	 * existing instruction (overlay code reachable from dispatch stubs is already
	 * disassembled when this runs), and none may land inside the table's own bytes.
	 * <p>
	 * <b>What the bases do not do is bound anything.</b> They are paragraph anchors taken
	 * from relocation seg_index values and stub module words, not module boundaries, and
	 * real module content crosses them — so the <i>entries</i> are bounded by the block
	 * (NEBULAR.EXE OVERLAY_78: dispatch at 0x31a anchored at base 0x30 has its default and
	 * one case at 0x356, past the recorded anchor 0x35), and so is an <i>adjacent</i>
	 * table. A table that begins at the byte right after the dispatch — the inline form
	 * the compiler emits — <b>proves its own anchor</b>: an anchor error is a nonzero
	 * multiple of 16, so a wrong base could not have put the table there. Only a
	 * non-adjacent table, which has nothing but the anchor behind it, still has to fit in
	 * the window up to the next base.
	 * <p>
	 * That distinction is not academic: NEBULAR's OVERLAY_25 (dispatch 0x321, table 0x326,
	 * 10 entries) and OVERLAY_26 (dispatch 0xa15, table 0xa1a, 6 entries) both anchor
	 * correctly and then run a few bytes past the next anchor — 0x330 and 0xa20 — because
	 * that anchor sits inside their table. Rejecting them on it handed both to
	 * DecompilerSwitchAnalyzer, which scattered their cases across resident segments
	 * 1f95, 2078 and 2000 and left a dozen p-code errors chasing the result.
	 */
	private static List<Address> recoverOverlayTable(Program program, Instruction instruction,
			MemoryBlock block) {
		int displacement = dispatchDisplacement(instruction);
		if (displacement < 0) {
			return null;
		}
		int entries = tableEntryCount(instruction, block);
		if (entries < 0) {
			return null;
		}
		List<Integer> bases = moduleBases(program, block);
		if (bases == null) {
			return null; // no record (block predates it and no re-analysis ran) — leave alone
		}

		Address start = block.getStart();
		long blockSize = block.getEnd().subtract(start) + 1;
		long dispatchOffset = instruction.getMinAddress().subtract(start);
		long moduleStart = -1;
		long moduleEnd = blockSize;
		for (int base : bases) {
			long paragraphOffset = base * 16L;
			if (paragraphOffset <= dispatchOffset) {
				moduleStart = paragraphOffset;
			}
			else {
				moduleEnd = Math.min(paragraphOffset, blockSize);
				break;
			}
		}
		if (moduleStart < 0) {
			return null;
		}

		if ((long) displacement + 2L * entries - 1 > 0xffffL) {
			return null;
		}
		long tableOffset = moduleStart + displacement;
		long tableEnd = tableOffset + 2L * entries;
		// An adjacent table vouches for its own anchor, so the block is bound enough; a
		// table anywhere else has only the anchor behind it and must fit the module window.
		long limit = tableOffset == dispatchOffset + DISPATCH_LENGTH ? blockSize : moduleEnd;
		if (tableEnd > limit) {
			return null;
		}
		Address table = start.add(tableOffset);

		Set<Address> destinations = new LinkedHashSet<>();
		Listing listing = program.getListing();
		try {
			for (int i = 0; i < entries; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				long destinationOffset = moduleStart + offset;
				if (destinationOffset >= blockSize) {
					return null;
				}
				if (destinationOffset >= tableOffset && destinationOffset < tableEnd) {
					return null; // a case target inside its own table: the base is wrong
				}
				Address destination = start.add(destinationOffset);
				Instruction existing = listing.getInstructionContaining(destination);
				if (existing != null && !existing.getMinAddress().equals(destination)) {
					return null; // mid-instruction target: the base resolution is wrong
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * The module base paragraphs {@link RTLinkOverlayAnalyzer} recorded for {@code block}
	 * when it created the overlay, sorted ascending, or null if there is no (valid) record.
	 */
	private static List<Integer> moduleBases(Program program, MemoryBlock block) {
		String recorded = program.getOptions(Program.PROGRAM_INFO).getString(
			RTLinkOverlayAnalyzer.MODULE_BASES_PREFIX + block.getName(), null);
		if (recorded == null || recorded.isEmpty()) {
			return null;
		}
		List<Integer> bases = new ArrayList<>();
		for (String base : recorded.split(",")) {
			try {
				bases.add(Integer.parseInt(base.trim(), 16));
			}
			catch (NumberFormatException e) {
				return null;
			}
		}
		return bases;
	}

	/**
	 * True if {@code block} is based at a paragraph that is not a 64KB-page boundary —
	 * exactly the case {@code currentCS} gets wrong. Page-aligned blocks already resolve
	 * correctly and must not be touched.
	 */
	private static boolean isUnalignedSegment(MemoryBlock block) {
		if (!(block.getStart() instanceof SegmentedAddress start)) {
			return false;
		}
		int pageSegment = (int) ((start.getOffset() >> 4) & 0xf000L);
		return start.getSegment() != pageSegment;
	}

	/** The {@code disp16} of a {@code JMP word ptr CS:[BX + disp16]}, or -1 if not one. */
	private static int dispatchDisplacement(Instruction instruction) {
		if (!instruction.getFlowType().isComputed() || !instruction.getFlowType().isJump()) {
			return -1;
		}
		byte[] bytes;
		try {
			bytes = instruction.getBytes();
		}
		catch (MemoryAccessException e) {
			return -1;
		}
		if (bytes.length != DISPATCH_LENGTH) {
			return -1;
		}
		for (int i = 0; i < DISPATCH_OPCODE.length; i++) {
			if (bytes[i] != DISPATCH_OPCODE[i]) {
				return -1;
			}
		}
		return (bytes[3] & 0xff) | ((bytes[4] & 0xff) << 8);
	}

	/**
	 * Table length from the {@code CMP index,N} guard that bounds the switch, or -1 when the idiom
	 * does not match.
	 * <p>
	 * The scaling pair is required, not incidental: a doubling of the index followed by
	 * {@code XCHG index,BX} is what proves the index addresses a table of <i>words</i>, which is
	 * the whole basis for reading {@code N + 1} shorts. The guard is then the nearest preceding
	 * {@code CMP} of that same index register.
	 * <p>
	 * The doubling is written either {@code SHL index,1} or {@code ADD index,index} — the same
	 * operation, and which one appears is a property of the compiler, not of the switch.
	 * ROE2MAIN.EXE uses {@code ADD} at every one of its 60 table dispatches and {@code SHL} at
	 * none, so requiring {@code SHL} recovered nothing at all there, and left the decompiler to
	 * mis-recover the tables itself (it read a string table as a jump table and chased ASCII
	 * pairs into unmapped segments).
	 * <p>
	 * Following the value rather than the instruction layout matters. Both
	 * {@code CMP AX,N; JA default} and {@code CMP AX,N; JBE body; JMP default} occur, and the
	 * latter puts an unconditional {@code JMP} between the guard and the scaling — skipping over
	 * it is safe, because any redefinition of the index register in between aborts the match.
	 * <p>
	 * Dispatches with no {@code CMP} at all are rejected: this matcher counts from the guard
	 * and declines rather than guess. The one such family in the corpus — the formatter FSM,
	 * whose index comes out of an {@code XLAT} — is handled by
	 * {@link #recoverFormatterFsmTable}, which derives the count from the FSM's own state
	 * table instead.
	 * <p>
	 * One transformation of the index is allowed between the guard and the scaling: a
	 * byte divide by a constant. Borland emits it for switches over strided case values
	 * ({@code SUB AX,base; CMP AX,span; JA default; MOV BL,stride; DIV BL; OR AH,AH;
	 * JNZ default; SHL AX,1; ...} — NEBULAR.EXE OVERLAY_27::0100ff, cases 0x14,0x1e,..,0x8c),
	 * so the {@code CMP} bounds the pre-divide value and the table has
	 * {@code span/stride + 1} entries. The divisor must resolve to a {@code MOV reg,imm}
	 * in the scanned window; a divide whose constant is not found rejects the site
	 * rather than guessing.
	 */
	private static int tableEntryCount(Instruction dispatch, MemoryBlock block) {
		Instruction exchange = dispatch.getPrevious();
		if (exchange == null || !"XCHG".equals(exchange.getMnemonicString())) {
			return -1;
		}
		Register index = otherRegister(exchange, "BX");
		if (index == null) {
			return -1;
		}
		Instruction scale = exchange.getPrevious();
		if (scale == null) {
			return -1;
		}
		if (!isDoublingOf(scale, index)) {
			// No doubling before the exchange: BX carries the byte offset into the word
			// table directly, not a case index awaiting a scale.
			return countFromByteOffsetIndex(scale, index, block);
		}

		long divisor = 1;
		Register pendingDivisor = null; // divide crossed, its constant not yet seen
		Instruction instruction = scale.getPrevious();
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return -1;
			}
			if ("CMP".equals(instruction.getMnemonicString()) &&
				index.equals(instruction.getRegister(0))) {
				Scalar bound = instruction.getScalar(1);
				if (bound == null || pendingDivisor != null) {
					return -1;
				}
				long entries = bound.getUnsignedValue() / divisor + 1;
				return entries > MAX_TABLE_ENTRIES ? -1 : (int) entries;
			}
			if (pendingDivisor != null && "MOV".equals(instruction.getMnemonicString()) &&
				pendingDivisor.equals(instruction.getRegister(0))) {
				Scalar value = instruction.getScalar(1);
				if (value == null || value.getUnsignedValue() == 0) {
					return -1;
				}
				divisor = value.getUnsignedValue();
				pendingDivisor = null;
			}
			else if (isByteDivideOf(instruction, index)) {
				if (divisor != 1 || pendingDivisor != null) {
					return -1; // a second divide: not an idiom this understands
				}
				pendingDivisor = instruction.getRegister(0);
			}
			else if (defines(instruction, index)) {
				return -1; // the compared value is not the value that indexes the table
			}
			instruction = instruction.getPrevious();
		}
		return -1;
	}

	/**
	 * Count a dispatch whose index is <i>already</i> the byte offset into the word table —
	 * no doubling precedes the exchange, because {@code BX} carries the byte offset itself
	 * rather than a case index yet to be scaled. Since the entry is a word and {@code BX}
	 * steps by 2, the {@code CMP} bounds the byte offset and the table holds
	 * {@code bound/2 + 1} entries, not {@code bound + 1}. RETURN.EXE has two spellings of
	 * this: an index halved back down ({@code SHR AX,1; CMP AX,0x12; XCHG AX,BX} at
	 * {@code OVERLAY_43::02ecf5}) and one merely required even ({@code TEST AL,1;
	 * CMP AX,0x16; XCHG AX,BX} at {@code OVERLAY_38::02e25b}) — both leave {@code BX} an
	 * even byte offset. Read as a case index the count is doubled, sending the surplus
	 * entries out of the block and aborting recovery, so {@code DecompilerSwitchAnalyzer}
	 * takes over and scatters cases into DGROUP.
	 * <p>
	 * The dispatch opcode ({@link #DISPATCH_OPCODE}) is always a {@code word ptr} read, so a
	 * valid table indexed by a bare register is necessarily byte-offset (a case index would
	 * have to be doubled first, which the caller already checked for). An unusual doubling
	 * this misses would under-count, and {@link #recoverOverlayTable} validates every
	 * resolved entry, so a wrong count can only fail to recover, never plant flow.
	 */
	private static int countFromByteOffsetIndex(Instruction before, Register index,
			MemoryBlock block) {
		Instruction instruction = before;
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return -1;
			}
			if ("CMP".equals(instruction.getMnemonicString()) &&
				index.equals(instruction.getRegister(0))) {
				Scalar bound = instruction.getScalar(1);
				if (bound == null) {
					return -1;
				}
				long entries = bound.getUnsignedValue() / 2 + 1;
				return entries > MAX_TABLE_ENTRIES ? -1 : (int) entries;
			}
			if (defines(instruction, index)) {
				return -1; // the index is redefined before the guard: the bound is not on BX
			}
			instruction = instruction.getPrevious();
		}
		return -1;
	}

	/**
	 * True if {@code instruction} doubles {@code index} — {@code SHL index,1} or the
	 * equivalent {@code ADD index,index}. Which form a compiler picks says nothing about
	 * the switch; both prove the index is about to address a table of words.
	 */
	private static boolean isDoublingOf(Instruction instruction, Register index) {
		String mnemonic = instruction.getMnemonicString();
		if (!index.equals(instruction.getRegister(0))) {
			return false;
		}
		if ("SHL".equals(mnemonic)) {
			return isOne(instruction.getScalar(1));
		}
		return "ADD".equals(mnemonic) && index.equals(instruction.getRegister(1));
	}

	/**
	 * True for {@code DIV r8} where {@code index} is AX — the only 8-bit divide form,
	 * quotient in AL/AX. The remainder lands in AH, so the {@code OR AH,AH; JNZ}
	 * exactness check between the divide and the scaling never writes the index
	 * register and needs no special handling here.
	 */
	private static boolean isByteDivideOf(Instruction instruction, Register index) {
		if (!"DIV".equals(instruction.getMnemonicString()) || !"AX".equals(index.getName())) {
			return false;
		}
		Register divisor = instruction.getRegister(0);
		return divisor != null && divisor.getMinimumByteSize() == 1;
	}

	/** The register operand of {@code instruction} that is not {@code name}, or null. */
	private static Register otherRegister(Instruction instruction, String name) {
		Register first = instruction.getRegister(0);
		Register second = instruction.getRegister(1);
		if (first == null || second == null) {
			return null;
		}
		if (name.equals(first.getName())) {
			return second;
		}
		return name.equals(second.getName()) ? first : null;
	}

	private static boolean isOne(Scalar scalar) {
		return scalar != null && scalar.getUnsignedValue() == 1;
	}

	/** True if {@code instruction} writes {@code register}. */
	private static boolean defines(Instruction instruction, Register register) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register written && written.equals(register)) {
				return true;
			}
		}
		return false;
	}

	/** True if Ghidra already recorded a computed flow from this branch. */
	private static boolean hasComputedReference(ReferenceManager refManager,
			Instruction instruction) {
		for (Reference reference : refManager.getReferencesFrom(instruction.getMinAddress())) {
			if (reference.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}
}
