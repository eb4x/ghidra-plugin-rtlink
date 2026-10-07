package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates the cross-references that Ghidra's stock {@code OperandReferenceAnalyzer}
 * never produces for RTLink/Plus programs (its {@code canAnalyze} checks
 * {@code bitSize > 16}, so 16-bit address spaces are skipped entirely).  Two
 * independent passes share one instruction scan:
 * <ul>
 * <li><b>Overlay far calls/jumps</b> &mdash; instructions in overlay blocks with an
 * immediate far call ({@code 9A}) or far jump ({@code EA}) opcode get explicit
 * references to their targets in the main program's address space.  Active once
 * {@link RTLinkOverlayAnalyzer} has created the overlay blocks.</li>
 * <li><b>DS-relative data reads/writes</b> &mdash; DS-relative memory operands such
 * as {@code MOV AX,[0x540e]} or {@code MOV [0x540e],DX} get references to their
 * DGROUP globals.  {@link RTLinkOverlayAnalyzer} has already assumed
 * {@code DS = DGROUP} over executable memory (see its
 * {@code assumeDataSegmentRegister}), so the target {@code DGROUP:offset} is fully
 * known, and {@link Instruction#getOperandRefType(int)} distinguishes READ from
 * WRITE from the operand p-code.</li>
 * <li><b>Address-of immediates</b> &mdash; {@code PUSH imm16},
 * {@code MOV BX/SI/DI,imm16}, and {@code ADD AX/BX/CX/DX/SI/DI,imm16} whose
 * immediate, resolved against the same assumed DS, lands in a mapped
 * non-executable block get {@link RefType#DATA} references.  Globals only ever
 * passed by address ({@code fread(&g_players, ...)} compiles to
 * {@code PUSH 0x540e}) otherwise show zero xrefs, and for array-typed globals the
 * dominant referent shape is the indexing idiom &mdash; {@code &g_players[i]}
 * compiles to a scaled index plus {@code ADD reg,0x540e} (27 of g_players' 29 real
 * referents).  The block guard rejects every small coincidental constant (they
 * fall below the data block's start offset), but it cannot tell a <i>segment</i>
 * constant from an offset &mdash; real-mode segment values like {@code A000} land
 * inside the data extent.  Two suppressions close that hole:
 * {@link #isRealModeVideoSegment} (a documented constant heuristic for the video
 * segments, which in a VGA game appear everywhere as far-pointer halves) and
 * {@link #flowsIntoSegmentRegister} (straight-line dataflow: the loaded register
 * is copied into ES/DS/SS within a few instructions).  A third dataflow check,
 * {@link #xlatOverrideSegment}, catches {@code MOV BX,imm16} feeding a
 * segment-overridden {@code XLAT}: the immediate is a translate-table offset in
 * <i>that</i> segment — for {@code XLAT CS:BX} (the overlay manager's reg-field
 * tables) the reference is retargeted to the code segment, for {@code SS:}/
 * {@code ES:} it is withdrawn.  Stock analysis never makes
 * these refs &mdash; {@code ConstantPropagationAnalyzer} disables param-constant
 * refs on segmented address spaces and resolves bare constants as segment-0
 * addresses.</li>
 * </ul>
 * Per-shape register whitelists are measured, not assumed (enumerate
 * {@code ADD <reg>,0x}/{@code MOV <reg>,0x} over the program and judge the
 * in-range immediates):
 * <ul>
 * <li>{@code MOV AX,imm16} is excluded &mdash; measured ~90% false positives: DOS
 * int 21h AH:AL function selectors such as {@code 0x3D00}/{@code 0x4200} and low
 * words of 32-bit constants land in the data extent.</li>
 * <li>{@code ADD} takes all general registers including AX/CX/DX: a large
 * immediate added to a register is essentially always base-plus-index address
 * math, and the real g_players referents use CX and DX too.</li>
 * </ul>
 * Two constants are excluded by value, both knowingly heuristic: the real-mode
 * video segments ({@link #isRealModeVideoSegment}) and {@code 0x8000}
 * (INT16_MIN/high-bit sentinel and 32-bit-constant high half; measured only as a
 * constant, never as a global base).  Known accepted residuals on the corpus
 * binary (2 refs of ~350): a rand() LCG addend ({@code ADD AX,0x9EC3}) and one
 * bitmask ({@code MOV BX,0xC000} feeding {@code AND}) &mdash; large constants in
 * genuine arithmetic that no syntactic gate can tell from an offset.  Still out
 * of scope: immediates of comparison and other arithmetic instructions
 * ({@code CMP}/{@code SUB}/{@code AND}/...), non-video segment constants pushed
 * as far-pointer halves (only the video segments are excluded by value),
 * segment-overridden
 * ({@code ES:}/{@code SS:}/{@code CS:}) accesses, fully-computed operands with no
 * displacement ({@code [BX+SI]}), and targets in executable blocks (the
 * initialized low-DGROUP region; stock constant propagation covers those).
 */
public class RTLinkXrefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Xref";
	private static final String DESCRIPTION =
		"Creates the cross-references the stock operand analyzer skips in 16-bit " +
			"address spaces: far call/jump xrefs from overlay code to main program " +
			"routines, DS-relative data read/write xrefs (DGROUP globals), and " +
			"address-of immediate xrefs (PUSH/MOV/ADD of a DGROUP data offset).";

	public RTLinkXrefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	/**
	 * Drop the DGROUP references that other analyzers manufacture inside the RTLink runtime.
	 *
	 * <p>Our own passes already decline the runtime: they are gated on a present DS value, and
	 * {@link RTLinkOverlayAnalyzer} deliberately leaves DS unset over the runtime's blocks
	 * because the runtime owns DS (it reloads it from its own saved-segment slots, and does
	 * {@code MOV DS,CS}). Ghidra's stock constant-propagation reference analyzer is not so
	 * careful: it propagates a DS value through that hand-written assembly anyway and resolves
	 * every DS-relative operand against it, which lands the runtime's *own* pointers in the
	 * game's DGROUP. On VICEROY.EXE that is ~46 references over 24 addresses, and they are
	 * unfounded on the face of the instructions:
	 * <ul>
	 * <li>{@code 210d:4d21} is {@code MOV word ptr CS:[0x4e84],BX} &mdash; a CS override. A
	 * DGROUP reference from it is wrong by definition.</li>
	 * <li>{@code 210d:07c0} is {@code CALLF [0x4e84]}, and the init did {@code MOV AX,CS;
	 * MOV DS,AX} at {@code 210d:0735}: DS is CS there, so it reads {@code 210d:4e84} &mdash;
	 * the EMM entry vector that {@code 4d21} itself wrote.</li>
	 * <li>{@code 210d:2b3a} is {@code CMP word ptr [SI + -0x2]} &mdash; register-indirect off a
	 * propagated SI, not a global.</li>
	 * <li>{@code 210d:4784} loads {@code 0xc000}, which the next two instructions use as a
	 * mask ({@code AND BX,DX; XOR DX,BX}).</li>
	 * </ul>
	 * and not one of the 24 targets is referenced by application code &mdash; they are the
	 * runtime talking to itself, misfiled under the game's globals.
	 *
	 * <p>Swept in {@code analysisEnded} so it runs after every analyzer that could create one,
	 * whatever its priority.
	 */
	@Override
	public void analysisEnded(Program program) {
		int removed = removeRuntimeDgroupRefs(program);
		if (removed > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Removed %d unfounded DGROUP reference(s) from the RTLink runtime " +
					"(DS is not DGROUP there)",
				removed));
		}
	}

	/**
	 * @return how many references from the runtime's code blocks into DGROUP were deleted.
	 *         Package-private so tests can drive it directly.
	 */
	static int removeRuntimeDgroupRefs(Program program) {
		Register ds = program.getProgramContext().getRegister("DS");
		if (ds == null) {
			return 0;
		}
		Integer dgroup = assumedDgroup(program, ds);
		if (dgroup == null) {
			return 0;
		}
		Set<MemoryBlock> runtime = RTLinkOverlayAnalyzer.findRuntimeCodeBlocks(program, dgroup);
		if (runtime.isEmpty()) {
			return 0;
		}

		AddressSet runtimeCode = new AddressSet();
		for (MemoryBlock block : runtime) {
			runtimeCode.addRange(block.getStart(), block.getEnd());
		}

		ReferenceManager refs = program.getReferenceManager();
		List<Reference> doomed = new ArrayList<>();
		AddressIterator sources = refs.getReferenceSourceIterator(runtimeCode, true);
		while (sources.hasNext()) {
			Address from = sources.next();
			for (Reference ref : refs.getReferencesFrom(from)) {
				Address to = ref.getToAddress();
				if (to instanceof SegmentedAddress seg && seg.getSegment() == dgroup) {
					doomed.add(ref);
				}
			}
		}
		for (Reference ref : doomed) {
			refs.delete(ref);
		}
		return doomed.size();
	}

	/**
	 * The DGROUP segment, read back from the DS context the overlay analyzer asserted over
	 * compiler-generated code. Null if DS was never assumed (nothing to clean up).
	 */
	private static Integer assumedDgroup(Program program, Register ds) {
		ProgramContext context = program.getProgramContext();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isExecute()) {
				continue;
			}
			RegisterValue value = context.getRegisterValue(ds, block.getStart());
			if (value != null && value.hasValue()) {
				return value.getUnsignedValue().intValue() & 0xffff;
			}
		}
		return null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean doOverlayXrefs = RTLinkOverlayAnalyzer.isOverlayAnalyzed(program);

		ProgramContext context = program.getProgramContext();
		Register ds = context.getRegister("DS");
		boolean doDataXrefs =
			RTLinkOverlayAnalyzer.isDataSegmentAssumed(program) && ds != null;

		if (!doOverlayXrefs && !doDataXrefs) {
			return false;
		}

		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();

		int overlayCount = 0;
		Counts counts = new Counts();
		AddressSet undefinedFarTargets = new AddressSet();

		InstructionIterator instrIter = listing.getInstructions(set, true);
		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			if (doOverlayXrefs) {
				overlayCount += addOverlayFarXref(instr, memory, listing, refManager, space,
					undefinedFarTargets);
			}
			if (doDataXrefs) {
				addDataXrefs(instr, context, ds, memory, refManager, space, counts);
			}
		}

		// A far-call/jump reference into undefined bytes is a husk factory: the
		// reference alone makes the stock subroutine pass plant a function there,
		// and with no instruction at the entry its body is fabricated as a single
		// byte. These targets are reachable only from overlay code (anything with a
		// resident-side flow is already disassembled), so disassemble them now.
		// A function may already sit on the target -- the overlay pass's committed
		// CALLF instructions carry flow references, and the subroutine pass reacts
		// to those long before this analyzer runs -- so recompute its body from the
		// new code; a 1-byte husk body would otherwise persist forever.
		if (!undefinedFarTargets.isEmpty()) {
			new DisassembleCommand(undefinedFarTargets, null, true).applyTo(program, monitor);
			FunctionManager funcMgr = program.getFunctionManager();
			for (Address target : undefinedFarTargets.getAddresses(true)) {
				monitor.checkCancelled();
				Instruction instr = listing.getInstructionAt(target);
				if (instr != null && funcMgr.getFunctionAt(target) != null) {
					CreateFunctionCmd.fixupFunctionBody(program, instr, monitor);
				}
			}
			Msg.info(this, "RTLink/Plus: Disassembled " +
				undefinedFarTargets.getNumAddresses() +
				" far call/jump target(s) reachable only from overlay code");
		}

		if (overlayCount > 0) {
			Msg.info(this,
				"RTLink/Plus: Created " + overlayCount + " overlay far call/jump xrefs");
		}
		if (counts.deref > 0) {
			Msg.info(this, "RTLink/Plus: Created " + counts.deref + " DS-relative data xrefs");
		}
		if (counts.addressOf > 0) {
			Msg.info(this,
				"RTLink/Plus: Created " + counts.addressOf + " address-of immediate xrefs");
		}
		return true;
	}

	/**
	 * Far call/jump pass: create a reference from an overlay-block far call/jump
	 * to its main-program target.  Returns the number of references created (0 or 1).
	 * A target still made of undefined bytes is added to {@code undefinedTargets}
	 * for the caller to disassemble in one batch.
	 */
	private static int addOverlayFarXref(Instruction instr, Memory memory, Listing listing,
			ReferenceManager refManager, SegmentedAddressSpace mainSpace,
			AddressSet undefinedTargets) {
		MemoryBlock instrBlock = memory.getBlock(instr.getAddress());
		if (instrBlock == null || !instrBlock.isOverlay()) {
			return 0;
		}

		try {
			byte[] bytes = instr.getBytes();
			if (bytes.length < 5) {
				return 0;
			}

			boolean isFarCall = bytes[0] == RTLinkOverlayAnalyzer.OPCODE_CALLF;
			boolean isFarJump = bytes[0] == RTLinkOverlayAnalyzer.OPCODE_JMPF;

			if (!isFarCall && !isFarJump) {
				return 0;
			}

			int offset = (bytes[1] & 0xFF) | ((bytes[2] & 0xFF) << 8);
			int segment = (bytes[3] & 0xFF) | ((bytes[4] & 0xFF) << 8);

			Address targetAddr = mainSpace.getAddress(segment, offset);
			MemoryBlock targetBlock = memory.getBlock(targetAddr);
			if (targetBlock != null && !targetBlock.isOverlay()) {
				RefType refType = isFarCall
					? RefType.UNCONDITIONAL_CALL
					: RefType.UNCONDITIONAL_JUMP;
				refManager.addMemoryReference(instr.getAddress(), targetAddr,
					refType, SourceType.ANALYSIS, 0);
				if (targetBlock.isExecute() && targetBlock.isInitialized() &&
					listing.getUndefinedDataAt(targetAddr) != null) {
					undefinedTargets.add(targetAddr);
				}
				return 1;
			}
		}
		catch (MemoryAccessException e) {
			// skip
		}
		return 0;
	}

	/** Per-run counters for the data pass, reported separately in {@link #added}. */
	static final class Counts {
		int deref; // DS-relative memory-operand READ/WRITE refs
		int addressOf; // address-of immediate DATA refs
	}

	/**
	 * Data pass: create READ/WRITE references for the instruction's DS-relative
	 * memory operands and DATA references for its address-of immediates.
	 * Package-private, with the counters passed in, so tests can drive it directly.
	 */
	static void addDataXrefs(Instruction instr, ProgramContext context, Register ds,
			Memory memory, ReferenceManager refManager, SegmentedAddressSpace space,
			Counts counts) {
		// The DS=DGROUP context is set only over executable blocks, so a present
		// value both confirms we are in code and gives the segment to resolve with.
		RegisterValue dsVal = context.getRegisterValue(ds, instr.getAddress());
		if (dsVal == null || !dsVal.hasValue()) {
			return;
		}
		int dgroup = dsVal.getUnsignedValue().intValue() & 0xffff;

		int numOps = instr.getNumOperands();
		for (int i = 0; i < numOps; i++) {
			int opType = instr.getOperandType(i);
			if (!OperandType.isDynamic(opType)) {
				// Not a memory operand; a pure immediate may still be an address-of.
				if (OperandType.isScalar(opType)) {
					counts.addressOf +=
						addAddressOfXref(instr, i, dgroup, memory, refManager, space);
				}
				continue;
			}

			Object[] opObjects = instr.getOpObjects(i);
			if (hasSegmentOverride(opObjects, ds) ||
				hasSegmentOverride(instr.getDefaultOperandRepresentation(i))) {
				continue;
			}

			Scalar disp = firstScalar(opObjects);
			if (disp == null) {
				continue; // e.g. [BX+SI] with no displacement
			}
			int offset = (int) (disp.getUnsignedValue() & 0xffff);

			RefType rt = instr.getOperandRefType(i);
			if (rt == null || (!rt.isRead() && !rt.isWrite())) {
				continue; // materialise READ / WRITE / READ_WRITE only
			}

			Address target = space.getAddress(dgroup, offset);
			if (!isMappedDataTarget(target, memory)) {
				continue;
			}

			refManager.addMemoryReference(instr.getAddress(), target, rt,
				SourceType.ANALYSIS, i);
			counts.deref++;
		}
	}

	/**
	 * Address-of pass: create a DATA reference for a pure imm16 operand of
	 * {@code PUSH imm16}, {@code MOV BX/SI/DI,imm16}, or
	 * {@code ADD AX/BX/CX/DX/SI/DI,imm16} whose value, resolved against
	 * DS=DGROUP, lands in a mapped non-executable block.  Returns the number of
	 * references created (0 or 1).
	 */
	private static int addAddressOfXref(Instruction instr, int opIndex, int dgroup,
			Memory memory, ReferenceManager refManager, SegmentedAddressSpace space) {
		String mnemonic = instr.getMnemonicString();
		Register destReg = null;
		if (mnemonic.equals("PUSH")) {
			if (opIndex != 0 || instr.getNumOperands() != 1) {
				return 0;
			}
		}
		else if (mnemonic.equals("MOV") || mnemonic.equals("ADD")) {
			// Register whitelists are measured per shape (see the class javadoc).
			// MOV: only registers plausibly used as pointers — CX and DX carry
			// counts and sizes, and AX carries DOS int 21h AH:AL function
			// selectors and the low words of 32-bit constants.  ADD: any general
			// register — a large immediate added to a register is base-plus-index
			// address math (the &g[i] idiom), and the real sites use all of them.
			if (opIndex != 1) {
				return 0;
			}
			Object[] dest = instr.getOpObjects(0);
			if (dest.length != 1 || !(dest[0] instanceof Register reg)) {
				return 0;
			}
			boolean allowed = mnemonic.equals("ADD")
				? isGeneralRegister(reg)
				: isAddressRegister(reg);
			if (!allowed) {
				return 0;
			}
			destReg = reg;
		}
		else {
			return 0;
		}

		Object[] opObjects = instr.getOpObjects(opIndex);
		if (opObjects.length != 1 || !(opObjects[0] instanceof Scalar imm)) {
			return 0;
		}
		long value = imm.getUnsignedValue();
		if (value > 0xffff) {
			return 0;
		}
		if (isRealModeVideoSegment(value)) {
			return 0;
		}
		if (value == 0x8000) {
			// INT16_MIN / high-bit sentinel, or the high half of a 32-bit
			// constant pair (PUSH 0x8000 / PUSH 0x0).  Measured twice as a
			// constant, never as a global base; a documented value exclusion
			// like the video segments.
			return 0;
		}
		if (destReg != null && flowsIntoSegmentRegister(instr, destReg)) {
			return 0;
		}
		if (destReg != null && destReg.getName().equals("BX")) {
			// XLAT reads [seg:BX+AL]. If this immediate feeds an XLAT with a segment
			// override, it is a translate-table offset in that segment, not a DGROUP
			// offset — the overlay manager's reg-field tables (XLAT CS:BX with the
			// table next to the code) got DGROUP refs this way. Only CS resolves
			// statically; any other override just withdraws the claim.
			Register xlatSegment = xlatOverrideSegment(instr, destReg);
			if (xlatSegment != null) {
				if (!xlatSegment.getName().equals("CS")) {
					return 0;
				}
				int codeSegment = ((SegmentedAddress) instr.getAddress()).getSegment();
				Address table = space.getAddress(codeSegment, (int) value);
				if (memory.getBlock(table) == null) {
					return 0;
				}
				refManager.addMemoryReference(instr.getAddress(), table, RefType.DATA,
					SourceType.ANALYSIS, opIndex);
				return 1;
			}
		}

		Address target = space.getAddress(dgroup, (int) value);
		if (!isMappedDataTarget(target, memory)) {
			return 0;
		}

		refManager.addMemoryReference(instr.getAddress(), target, RefType.DATA,
			SourceType.ANALYSIS, opIndex);
		return 1;
	}

	/**
	 * The overriding segment register of an {@code XLAT} that consumes {@code reg}
	 * (BX) within the next few fall-through instructions, or null when no such
	 * consumer is found. A bare {@code XLAT} (or an explicit {@code DS:}) reads
	 * DS:BX, which is exactly what the DGROUP resolution assumes, so those return
	 * null too — only {@code CS:}/{@code SS:}/{@code ES:} ({@code 2E/36/26 D7})
	 * change the answer. Deliberately shallow like
	 * {@link #flowsIntoSegmentRegister}: straight-line code only, stops at any call
	 * or when the register is rewritten.
	 */
	private static Register xlatOverrideSegment(Instruction instr, Register reg) {
		Program program = instr.getProgram();
		Listing listing = program.getListing();
		Instruction cur = instr;
		for (int i = 0; i < 4; i++) {
			Address ft = cur.getFallThrough();
			if (ft == null) {
				return null;
			}
			cur = listing.getInstructionAt(ft);
			if (cur == null || cur.getFlowType().isCall()) {
				return null;
			}
			if (cur.getMnemonicString().equals("XLAT")) {
				byte[] bytes;
				try {
					bytes = cur.getBytes();
				}
				catch (MemoryAccessException e) {
					return null;
				}
				if (bytes.length != 2 || bytes[1] != (byte) 0xd7) {
					return null; // bare XLAT: the DS resolution stands
				}
				return switch (bytes[0]) {
					case 0x2e -> program.getLanguage().getRegister("CS");
					case 0x36 -> program.getLanguage().getRegister("SS");
					case 0x26 -> program.getLanguage().getRegister("ES");
					default -> null; // 3E = explicit DS: — same as no override
				};
			}
			for (Object obj : cur.getResultObjects()) {
				if (obj == reg) {
					return null; // value replaced before any XLAT
				}
			}
		}
		return null;
	}

	/**
	 * Real-mode video memory segments ({@code A000}/{@code B000}/{@code B800}).  A
	 * pure constant exclusion, and knowingly heuristic: these values land inside
	 * the data block, so the block guard cannot reject them, yet in a VGA-era
	 * program they are far-pointer segment halves ({@code PUSH 0xA000} before the
	 * offset push) or segment loads, never DGROUP offsets &mdash; measured 20 of
	 * 20 on the corpus binary.  What this cannot catch: any <i>other</i> constant
	 * used as a segment that happens to fall in the data extent (e.g. arbitrary
	 * far-pointer halves); those are only suppressed when
	 * {@link #flowsIntoSegmentRegister} can see the segment load.
	 */
	private static boolean isRealModeVideoSegment(long value) {
		return value == 0xa000 || value == 0xb000 || value == 0xb800;
	}

	/**
	 * True if the register just loaded with the immediate is copied into a
	 * segment register within the next few fall-through instructions
	 * ({@code MOV DI,0xA000} / {@code MOV ES,DI}) &mdash; the immediate is a
	 * segment, not an offset.  Deliberately shallow: follows straight-line code
	 * only, stops at any flow instruction or when the register is rewritten.
	 */
	private static boolean flowsIntoSegmentRegister(Instruction instr, Register reg) {
		Listing listing = instr.getProgram().getListing();
		Instruction cur = instr;
		for (int i = 0; i < 4; i++) {
			Address ft = cur.getFallThrough();
			if (ft == null) {
				return false;
			}
			cur = listing.getInstructionAt(ft);
			if (cur == null || cur.getFlowType().isCall()) {
				return false;
			}
			if (cur.getMnemonicString().equals("MOV")) {
				// From p-code, not operand indices: stock 12.1.3/12.1.4 swap MOV Sreg's
				// displayed operands (see RTLinkOverlayAnalyzer.movDestination).
				Register dst = RTLinkOverlayAnalyzer.movDestination(cur);
				if (dst != null && isSegmentRegister(dst) &&
					reg.equals(RTLinkOverlayAnalyzer.movSourceRegister(cur))) {
					return true;
				}
			}
			for (Object obj : cur.getResultObjects()) {
				if (obj == reg) {
					return false; // value replaced before any segment load
				}
			}
		}
		return false;
	}

	private static boolean isAddressRegister(Register reg) {
		String name = reg.getName();
		return name.equals("BX") || name.equals("SI") || name.equals("DI");
	}

	/** Any 16-bit general register an {@code ADD reg,imm16} may compute into (not SP/BP). */
	private static boolean isGeneralRegister(Register reg) {
		String name = reg.getName();
		return name.equals("AX") || name.equals("BX") || name.equals("CX") ||
			name.equals("DX") || name.equals("SI") || name.equals("DI");
	}

	/**
	 * True if the target lands in a mapped non-executable block.  DGROUP globals
	 * live in BSS, so uninitialized (rw-) data blocks are valid targets; only
	 * unmapped memory and executable (code) blocks are rejected.
	 */
	private static boolean isMappedDataTarget(Address target, Memory memory) {
		MemoryBlock block = memory.getBlock(target);
		return block != null && !block.isExecute();
	}

	/** True if the operand carries an explicit non-DS segment register (override prefix). */
	private static boolean hasSegmentOverride(Object[] opObjects, Register ds) {
		for (Object obj : opObjects) {
			if (obj instanceof Register reg && reg != ds && isSegmentRegister(reg)) {
				return true;
			}
		}
		return false;
	}

	/** Fallback: detect an {@code ES:}/{@code SS:}/{@code CS:}/{@code FS:}/{@code GS:} prefix. */
	private static boolean hasSegmentOverride(String representation) {
		return representation.contains("ES:") || representation.contains("SS:") ||
			representation.contains("CS:") || representation.contains("FS:") ||
			representation.contains("GS:");
	}

	private static boolean isSegmentRegister(Register reg) {
		String name = reg.getName();
		return name.equals("ES") || name.equals("SS") || name.equals("CS") ||
			name.equals("FS") || name.equals("GS") || name.equals("DS");
	}

	private static Scalar firstScalar(Object[] opObjects) {
		for (Object obj : opObjects) {
			if (obj instanceof Scalar scalar) {
				return scalar;
			}
		}
		return null;
	}
}
