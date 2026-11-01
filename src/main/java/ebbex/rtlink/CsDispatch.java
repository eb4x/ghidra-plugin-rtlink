package ebbex.rtlink;

import java.util.Arrays;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The CS-relative switch idiom, {@code JMP word ptr CS:[BX + disp16]}: its displacement and
 * the {@code CMP} guard that counts its table. {@link ResidentSwitchTables} and
 * {@link OverlaySwitchTables} read the table itself.
 */
final class CsDispatch {

	/** {@code JMP word ptr CS:[BX + disp16]} — CS prefix, opcode FF /4, mod=10 r/m=111. */
	private static final byte[] DISPATCH_OPCODE = { 0x2e, (byte) 0xff, (byte) 0xa7 };
	static final int DISPATCH_LENGTH = 5;

	/** Instructions to look back over for the {@code CMP} that bounds the switch index. */
	private static final int GUARD_SCAN_LIMIT = 8;

	/** Refuse absurd tables rather than trusting a mis-parsed guard. */
	static final int MAX_TABLE_ENTRIES = 512;

	private CsDispatch() {
	}

	/** The {@code disp16} of a {@code JMP word ptr CS:[BX + disp16]}, or -1 if not one. */
	static int displacement(Instruction instruction) {
		if (!instruction.getFlowType().isComputed() || !instruction.getFlowType().isJump()) {
			return -1;
		}
		byte[] bytes = X86.bytes(instruction);
		if (bytes.length != DISPATCH_LENGTH ||
			!Arrays.equals(bytes, 0, DISPATCH_OPCODE.length, DISPATCH_OPCODE, 0,
				DISPATCH_OPCODE.length)) {
			return -1;
		}
		return X86.word(bytes, 3);
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
	 * whose index comes out of an {@code XLAT} — is handled by {@link FormatterFsm}, which
	 * derives the count from the FSM's own state table instead.
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
	static int entryCount(Instruction dispatch, MemoryBlock block) {
		Program program = dispatch.getProgram();
		Instruction exchange = dispatch.getPrevious();
		Register index = exchange == null ? null : exchangedWithBx(program, exchange);
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
		Instruction instruction = X86.previousInBlock(scale, block);
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (comparesWith(instruction, index)) {
				Long bound = guardBound(program, instruction, index);
				if (bound == null || pendingDivisor != null) {
					return -1;
				}
				long entries = bound / divisor + 1;
				return entries > MAX_TABLE_ENTRIES ? -1 : (int) entries;
			}
			Register byteDivisor = byteDivisorOf(program, instruction, index);
			if (pendingDivisor != null && "MOV".equals(instruction.getMnemonicString()) &&
				pendingDivisor.equals(X86.movDestination(instruction))) {
				Long value = X86.movImmediate(instruction);
				if (value == null || value == 0) {
					return -1;
				}
				divisor = value;
				pendingDivisor = null;
			}
			else if (byteDivisor != null) {
				if (divisor != 1 || pendingDivisor != null) {
					return -1; // a second divide: not an idiom this understands
				}
				pendingDivisor = byteDivisor;
			}
			else if (X86.changes(instruction, index)) {
				return -1; // the compared value is not the value that indexes the table
			}
			instruction = X86.previousInBlock(instruction, block);
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
	 * this misses would under-count, and both readers ({@link ResidentSwitchTables},
	 * {@link OverlaySwitchTables}) validate every resolved entry, so a wrong count can only
	 * fail to recover, never plant flow.
	 */
	private static int countFromByteOffsetIndex(Instruction before, Register index,
			MemoryBlock block) {
		Program program = before.getProgram();
		Instruction instruction = before;
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return -1;
			}
			if (comparesWith(instruction, index)) {
				Long bound = guardBound(program, instruction, index);
				if (bound == null) {
					return -1;
				}
				long entries = bound / 2 + 1;
				return entries > MAX_TABLE_ENTRIES ? -1 : (int) entries;
			}
			if (X86.changes(instruction, index)) {
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
	static boolean isDoublingOf(Instruction instruction, Register index) {
		Program program = instruction.getProgram();
		X86.Shift shift = X86.shift(program, instruction);
		if (shift != null) {
			return shift.ext() == X86.SHL && !shift.byCl() && shift.count() == 1 &&
				index.equals(shift.register());
		}
		X86.RegisterPair add = X86.registerPair(program, instruction, X86.ADD * 8);
		return add != null && index.equals(add.destination()) && index.equals(add.source());
	}

	/**
	 * True for a {@code CMP} that reads {@code index}, from its p-code inputs: the guard, or a
	 * comparison against something other than an immediate that ends the match.
	 */
	private static boolean comparesWith(Instruction instruction, Register index) {
		if (!"CMP".equals(instruction.getMnemonicString())) {
			return false;
		}
		for (Object input : instruction.getInputObjects()) {
			if (index.equals(input)) {
				return true;
			}
		}
		return false;
	}

	/** The bound of a {@code CMP index,imm} guard, or null if {@code instruction} is not one. */
	private static Long guardBound(Program program, Instruction instruction, Register index) {
		X86.RegisterImmediate compare = X86.aluImmediate(program, instruction, X86.CMP);
		return compare != null && index.equals(compare.register()) ? compare.value() : null;
	}

	/**
	 * The divisor of a {@code DIV r8} where {@code index} is AX — the only 8-bit divide form,
	 * quotient in AL/AX — or null. The remainder lands in AH, so the {@code OR AH,AH; JNZ}
	 * exactness check between the divide and the scaling never writes the index register and
	 * needs no special handling here.
	 */
	private static Register byteDivisorOf(Program program, Instruction instruction,
			Register index) {
		return "AX".equals(index.getName()) ? X86.byteDivisor(program, instruction) : null;
	}

	/** The register {@code XCHG} swaps with {@code BX}, or null if {@code instruction} is not that. */
	private static Register exchangedWithBx(Program program, Instruction instruction) {
		X86.RegisterPair pair = X86.exchange(program, instruction);
		if (pair == null) {
			return null;
		}
		if ("BX".equals(pair.destination().getName())) {
			return pair.source();
		}
		return "BX".equals(pair.source().getName()) ? pair.destination() : null;
	}
}
