package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

/**
 * The CS-relative switch idiom, {@code JMP word ptr CS:[BX + disp16]}: its displacement,
 * the {@code CMP} guard that counts its table, and the table itself in a resident block
 * whose segment is not 64KB-page aligned — the case {@code currentCS} resolves against
 * the wrong paragraph (see {@link RTLinkSwitchTableAnalyzer}).
 */
final class CsSwitchTables {

	/** {@code JMP word ptr CS:[BX + disp16]} — CS prefix, opcode FF /4, mod=10 r/m=111. */
	private static final byte[] DISPATCH_OPCODE = { 0x2e, (byte) 0xff, (byte) 0xa7 };
	static final int DISPATCH_LENGTH = 5;

	/** Instructions to look back over for the {@code CMP} that bounds the switch index. */
	static final int GUARD_SCAN_LIMIT = 8;

	/** Refuse absurd tables rather than trusting a mis-parsed guard. */
	static final int MAX_TABLE_ENTRIES = 512;

	private CsSwitchTables() {
	}

	/**
	 * The table of a resident dispatch at {@code displacement}, read at the block's true
	 * paragraph, or null. Page-aligned blocks are left alone: {@code currentCS} already
	 * resolves them correctly.
	 */
	static List<Address> recoverResident(Program program, Instruction instruction,
			MemoryBlock block, int displacement) {
		if (!isUnalignedSegment(block)) {
			return null;
		}
		int entries = entryCount(instruction, block);
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
	static int displacement(Instruction instruction) {
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
			else if (X86.changes(instruction, index)) {
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
	 * this misses would under-count, and {@link OverlaySwitchTables} validates every
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
}
