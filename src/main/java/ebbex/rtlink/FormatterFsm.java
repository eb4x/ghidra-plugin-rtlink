package ebbex.rtlink;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

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

	/** A single reachable state is no switch. */
	private static final int MIN_FSM_STATES = 2;

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
	 * No instruction bounds the final index, so {@link CsDispatch#entryCount} cannot
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
		Instruction scale = X86.previousInBlock(dispatch, block);
		if (scale == null || !CsDispatch.isDoublingOf(scale, bx)) {
			return null;
		}
		// MOV BX,AX
		Instruction widen = X86.previousInBlock(scale, block);
		X86.RegisterPair move = widen == null ? null : X86.registerPair(program, widen, X86.MOV);
		if (move == null || !bx.equals(move.destination()) || !ax.equals(move.source())) {
			return null;
		}
		// CBW
		Instruction extend = X86.previousInBlock(widen, block);
		if (extend == null || !"CBW".equals(extend.getMnemonicString())) {
			return null;
		}
		// MOV [BP-x],AL — the state variable's slot
		Instruction store = X86.previousInBlock(extend, block);
		Integer stateSlot = store == null ? null : bpSlot(store, OPCODE_MOV_RM8_R8);
		if (stateSlot == null) {
			return null;
		}
		// SHR AL,CL
		Instruction shift = X86.previousInBlock(store, block);
		if (shift == null || !isShiftByCl(program, shift, X86.SHR, al)) {
			return null;
		}
		// INC CL
		Instruction bump = X86.previousInBlock(shift, block);
		if (bump == null || !cl.equals(X86.incremented(program, bump))) {
			return null;
		}
		// XLAT — the transition lookup
		Instruction translate = X86.previousInBlock(bump, block);
		if (translate == null || !X86.isPlainXlat(translate)) {
			return null;
		}
		// ADD AL,[BP-x] — same slot the next state is stored back to
		Instruction stateIn = X86.previousInBlock(translate, block);
		Integer indexSlot = stateIn == null ? null : bpSlot(stateIn, OPCODE_ADD_R8_RM8);
		if (indexSlot == null || !indexSlot.equals(stateSlot)) {
			return null;
		}
		// SHL AL,CL
		Instruction classScale = X86.previousInBlock(stateIn, block);
		if (classScale == null || !isShiftByCl(program, classScale, X86.SHL, al)) {
			return null;
		}
		// MOV CL,3
		Instruction three = X86.previousInBlock(classScale, block);
		if (three == null || !"MOV".equals(three.getMnemonicString()) ||
			!cl.equals(X86.movDestination(three)) ||
			!Long.valueOf(3).equals(X86.movImmediate(three))) {
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
		Instruction instruction = X86.previousInBlock(three, block);
		for (int i = 0; i < FSM_PROLOGUE_SCAN_LIMIT && instruction != null; i++) {
			String mnemonic = instruction.getMnemonicString();
			if ("MOV".equals(mnemonic) && bx.equals(X86.movDestination(instruction))) {
				Long table = X86.movImmediate(instruction);
				if (table == null) {
					return null;
				}
				tableOffset = table.intValue();
				break; // the table base is the far anchor; the walk is done
			}
			if (X86.changes(instruction, bx)) {
				return null;
			}
			X86.RegisterImmediate mask = X86.aluImmediate(program, instruction, X86.AND);
			X86.RegisterImmediate compare = X86.aluImmediate(program, instruction, X86.CMP);
			if ("XLAT".equals(mnemonic)) {
				if (!X86.isPlainXlat(instruction)) {
					return null;
				}
				sawClassLookup = true;
			}
			else if (mask != null && al.equals(mask.register()) && mask.value() == 0xf) {
				sawClassMask = true;
			}
			else if ("CMP".equals(mnemonic) && readsRegister(instruction, al)) {
				// The compared value is c-' ', a byte; a bound past 0xdf could not be one.
				if (compare == null || !al.equals(compare.register()) || compare.value() > 0xdf) {
					return null;
				}
				classLimit = (int) compare.value();
			}
			instruction = X86.previousInBlock(instruction, block);
		}
		if (tableOffset < 0 || classLimit < 0 || !sawClassLookup || !sawClassMask) {
			return null;
		}

		// The table is at DS:tableOffset; the CMP proves bytes 0..classLimit of it. This
		// reads memory directly, not p-code, so it does not depend on XLAT's p-code
		// getting the segment right.
		Integer ds = X86.dataSegment(program, dispatch.getMinAddress());
		if (ds == null) {
			return null;
		}
		SegmentedAddressSpace space = X86.space(program);
		Address table = space.getAddress(ds, tableOffset);
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
		catch (MemoryAccessException _) {
			return null;
		}

		int states = stateCount(tableBytes);
		if (states < MIN_FSM_STATES) {
			return null; // covers -1 too: a transition escaped the proven table region
		}

		// The jump table is CS-relative at the dispatch's own paragraph. Hold the derived
		// state count against it: every entry must be a case target.
		AddressSetView range = CaseRange.of(program, dispatch, block);
		if (range == null) {
			return null;
		}
		int segment = X86.segment(block);
		if (segment < 0) {
			return null;
		}
		long lastByte = (long) displacement + 2L * states - 1;
		if (lastByte > 0xffffL) {
			return null;
		}
		Address jumpTable = space.getAddress(segment, displacement);
		if (!block.contains(jumpTable) ||
			!block.contains(space.getAddress(segment, (int) lastByte))) {
			return null;
		}
		// A case target inside the table means the count is wrong.
		return CaseTable.readAll(program, jumpTable, states, offset -> {
			Address destination = space.getAddress(segment, offset);
			return range.contains(destination) ? destination : null;
		});
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

	/** {@code MOV r/m8,r8}: the state store {@code MOV [BP-x],AL}. */
	private static final int OPCODE_MOV_RM8_R8 = 0x88;

	/** {@code ADD r8,r/m8}: the state load {@code ADD AL,[BP-x]}. */
	private static final int OPCODE_ADD_R8_RM8 = 0x02;

	/**
	 * The displacement of the {@code [BP + disp]} slot that {@code instruction}, opcode
	 * {@code opcode} with AL as its register operand, reads or writes; null for any other
	 * instruction. Only the bare {@code [BP + disp8/16]} form ({@code rm == 6}, {@code mod} 1
	 * or 2) is accepted, not {@code [BP+SI+disp]}: this is one byte-identical library routine,
	 * and its state variable is a plain local.
	 */
	private static Integer bpSlot(Instruction instruction, int opcode) {
		byte[] b = X86.bytes(instruction);
		int i = X86.opcodeIndex(b);
		if (i < 0 || i + 1 >= b.length || X86.segmentOverride(b) != 0 || (b[i] & 0xff) != opcode) {
			return null;
		}
		X86.ModRm modrm = X86.modRm(b, i + 1);
		if (modrm.rm() != 6 || modrm.reg() != 0 || (modrm.mod() != 1 && modrm.mod() != 2) ||
			i + 1 + modrm.displacementLength() >= b.length) {
			return null;
		}
		return modrm.displacement(b, i + 1);
	}

	/** True for shift {@code /ext} of {@code register} by CL. */
	private static boolean isShiftByCl(Program program, Instruction instruction, int ext,
			Register register) {
		X86.Shift shift = X86.shift(program, instruction);
		return shift != null && shift.ext() == ext && shift.byCl() &&
			register.equals(shift.register());
	}

	/** True if {@code register} is among the instruction's p-code inputs. */
	private static boolean readsRegister(Instruction instruction, Register register) {
		for (Object input : instruction.getInputObjects()) {
			if (register.equals(input)) {
				return true;
			}
		}
		return false;
	}
}
