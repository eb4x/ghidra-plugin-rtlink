package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

/**
 * The switch of the MSC {@code _output} formatter state machine, whose index comes out of
 * an {@code XLAT} and is bounded by the FSM's own state table rather than by a {@code CMP}.
 */
final class FormatterFsm {

	/**
	 * Instructions to scan above the formatter FSM's second {@code XLAT} for the
	 * {@code CMP} class bound and the {@code MOV BX,imm} table base.
	 */
	private static final int FSM_PROLOGUE_SCAN_LIMIT = 10;

	/** The FSM's next state is a nibble ({@code SHR AL,4}), so 16 states bound everything. */
	private static final int MAX_FSM_STATES = 16;

	private FormatterFsm() {
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
	 * No instruction bounds the final index, so {@link CsSwitchTables#entryCount} cannot
	 * count this and the decompiler, left to itself, fabricates cases for the full byte range
	 * of the {@code XLAT} load (its range analysis honors only {@code INT_AND} masks, not the
	 * {@code SHR}). But the bound is in the FSM's own data: the table serves two purposes at
	 * once — the low nibble of {@code table[c-' ']} classifies the character, and the high
	 * nibble of {@code table[class*8 + state]} is the next state, the two regions sharing
	 * the same bytes by design — so the reachable states, and with them the jump table's
	 * entry count, follow from a fixpoint over the table ({@link #stateCount}).
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
	 * {@link CaseRange} test the DGROUP form already relies on), and none may point
	 * back into the table.
	 */
	static List<Address> recover(Program program, Instruction dispatch, MemoryBlock block,
			int displacement) {
		Register al = program.getLanguage().getRegister("AL");
		Register ax = program.getLanguage().getRegister("AX");
		Register bx = program.getLanguage().getRegister("BX");
		Register cl = program.getLanguage().getRegister("CL");
		if (al == null || ax == null || bx == null || cl == null) {
			return null;
		}

		// SHL BX,1 (or ADD BX,BX)
		Instruction scale = previousInBlock(dispatch, block);
		if (scale == null || !CsSwitchTables.isDoublingOf(scale, bx)) {
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
			!cl.equals(three.getRegister(0)) || !X86.isScalar(three.getScalar(1), 3)) {
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
			if (X86.changes(instruction, bx)) {
				return null;
			}
			if ("XLAT".equals(mnemonic)) {
				if (!isPlainXlat(instruction)) {
					return null;
				}
				sawClassLookup = true;
			}
			else if ("AND".equals(mnemonic) && al.equals(instruction.getRegister(0)) &&
				X86.isScalar(instruction.getScalar(1), 0xf)) {
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

		int states = stateCount(tableBytes);
		if (states < DataSwitchTables.MIN_DATA_TABLE_ENTRIES) {
			return null; // covers -1 too: a transition escaped the proven table region
		}

		// The jump table is CS-relative at the dispatch's own paragraph. Hold the derived
		// state count against it: every entry must be a case target.
		AddressSetView range = CaseRange.of(program, dispatch, block);
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
	private static int stateCount(byte[] table) {
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
}
