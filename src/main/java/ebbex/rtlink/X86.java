package ebbex.rtlink;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

/**
 * Facts about 16-bit real-mode x86 instructions that several analyzers need, read the way they
 * all have to read them: from the encoded bytes and the p-code, never from the operands Ghidra
 * displays. Stock Ghidra 12.1.3 and 12.1.4 display {@code MOV Sreg,r/m16} ({@code 8E}) with its
 * operands swapped (GP-7018), and 12.2 reorders them again for {@code mod=3} (GP-7279), while the
 * p-code stays the same throughout: an operand index is not a reliable source or destination.
 */
final class X86 {

	/** {@code CALLF ptr16:16}. */
	static final byte OPCODE_CALLF = (byte) 0x9A;

	/** {@code JMPF ptr16:16}. */
	static final byte OPCODE_JMPF = (byte) 0xEA;

	private X86() {
	}

	// ---------------------------------------------------------------- bytes

	/** True for a legacy prefix: segment override, operand/address size, LOCK, REPNE, REP. */
	static boolean isPrefix(int b) {
		return switch (b) {
			case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3 -> true;
			default -> false;
		};
	}

	/** True for one of the four 8086 segment-override prefixes (ES, CS, SS, DS). */
	static boolean isSegmentOverride(int b) {
		return b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e;
	}

	/** Index of the first opcode byte past any prefixes, or -1 if there are only prefixes. */
	static int opcodeIndex(byte[] bytes) {
		int i = 0;
		while (i < bytes.length && isPrefix(bytes[i] & 0xff)) {
			i++;
		}
		return i < bytes.length ? i : -1;
	}

	/** The last segment-override prefix before the opcode, or 0 if there is none. */
	static int segmentOverride(byte[] bytes) {
		int segment = 0;
		for (int i = 0; i < bytes.length && isPrefix(bytes[i] & 0xff); i++) {
			if (isSegmentOverride(bytes[i] & 0xff)) {
				segment = bytes[i] & 0xff;
			}
		}
		return segment;
	}

	/** The little-endian word at {@code b[at]}. */
	static int word(byte[] b, int at) {
		return (b[at] & 0xff) | ((b[at + 1] & 0xff) << 8);
	}

	/**
	 * A 16-bit ModRM byte: {@code mod} (bits 7-6), {@code reg} (5-3, a register or an opcode
	 * extension {@code /n}) and {@code rm} (2-0).
	 */
	record ModRm(int mod, int reg, int rm) {

		/** True for {@code mod == 3}: {@code rm} names a register, not memory. */
		boolean isRegister() {
			return mod == 3;
		}

		/** True for {@code mod == 0, rm == 6}: a bare {@code [disp16]}, no base register. */
		boolean isDirect() {
			return mod == 0 && rm == 6;
		}

		/**
		 * The signed displacement following the ModRM byte at {@code b[at]}: a disp8 for
		 * {@code mod == 1}, a disp16 for {@code mod == 2}, else 0 (the {@link #isDirect} disp16
		 * is an address, not a displacement).
		 */
		int displacement(byte[] b, int at) {
			return switch (mod) {
				case 1 -> b[at + 1];
				case 2 -> (short) word(b, at + 1);
				default -> 0;
			};
		}

		/** Bytes of displacement (or {@link #isDirect} address) following the ModRM byte. */
		int displacementLength() {
			if (isDirect()) {
				return 2;
			}
			return switch (mod) {
				case 1 -> 1;
				case 2 -> 2;
				default -> 0;
			};
		}
	}

	/** The ModRM byte at {@code b[at]}. */
	static ModRm modRm(byte[] b, int at) {
		return modRm(b[at] & 0xff);
	}

	/** The ModRM byte {@code modrm}. */
	static ModRm modRm(int modrm) {
		return new ModRm((modrm >> 6) & 3, (modrm >> 3) & 7, modrm & 7);
	}

	/** A {@code ptr16:16} far pointer, as {@code CALLF}, {@code JMPF} and a far vector store it. */
	record FarPointer(int segment, int offset) {
		Address in(SegmentedAddressSpace space) {
			return space.getAddress(segment, offset);
		}
	}

	/** The far pointer stored at {@code at}: the offset word, then the segment word. */
	static FarPointer farPointer(Memory memory, Address at) throws MemoryAccessException {
		int offset = Short.toUnsignedInt(memory.getShort(at));
		int segment = Short.toUnsignedInt(memory.getShort(at.add(2)));
		return new FarPointer(segment, offset);
	}

	/** The instruction's bytes, or an empty array if they cannot be read. */
	static byte[] bytes(Instruction instruction) {
		try {
			return instruction.getBytes();
		}
		catch (MemoryAccessException _) {
			return new byte[0];
		}
	}

	/** The previous instruction if it exists and is still inside {@code block}, else null. */
	static Instruction previousInBlock(Instruction instruction, MemoryBlock block) {
		Instruction previous = instruction.getPrevious();
		return previous != null && block.contains(previous.getMinAddress()) ? previous : null;
	}

	// ---------------------------------------------------------------- operands from bytes

	private static final String[] REGISTERS_16 = { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };
	private static final String[] REGISTERS_8 = { "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH" };

	/** The general register numbered {@code n} (0-7) in a ModRM or opcode, {@code size} 1 or 2 bytes. */
	static Register register(Program program, int n, int size) {
		return program.getLanguage().getRegister((size == 1 ? REGISTERS_8 : REGISTERS_16)[n & 7]);
	}

	/** A register and the immediate an instruction combines with it. */
	record RegisterImmediate(Register register, long value) {
	}

	/** The two registers of a register-to-register instruction, destination first. */
	record RegisterPair(Register destination, Register source) {
	}

	/** The opcode and, when present, the ModRM byte of an instruction past its prefixes. */
	private record Opcode(byte[] bytes, int at, int op) {

		/** The ModRM byte after the opcode, or null past the end. */
		ModRm modRm() {
			return at + 1 < bytes.length ? X86.modRm(bytes, at + 1) : null;
		}
	}

	/** The instruction's opcode past its prefixes, or null with a {@code 66} prefix or no opcode. */
	private static Opcode opcode(Instruction instruction) {
		byte[] b = bytes(instruction);
		int i = opcodeIndex(b);
		if (i < 0 || hasOperandSizePrefix(b, i)) {
			return null;
		}
		return new Opcode(b, i, b[i] & 0xff);
	}

	/**
	 * The register and immediate of an ALU instruction with immediate operand {@code /ext}
	 * ({@code 0} ADD, {@code 1} OR, {@code 4} AND, {@code 5} SUB, {@code 6} XOR, {@code 7} CMP)
	 * on a register: the accumulator forms {@code ext*8+4 ib} (AL) and {@code ext*8+5 iw} (AX),
	 * or {@code 80 /ext ib}, {@code 81 /ext iw} and {@code 83 /ext ib} with {@code mod == 3}.
	 * The {@code 83} immediate is sign-extended to 16 bits, as the CPU does. Null for any other
	 * instruction, a memory operand included.
	 */
	static RegisterImmediate aluImmediate(Program program, Instruction instruction, int ext) {
		Opcode o = opcode(instruction);
		if (o == null) {
			return null;
		}
		if (o.op() == ext * 8 + 4 || o.op() == ext * 8 + 5) {
			int size = o.op() == ext * 8 + 4 ? 1 : 2;
			Long value = immediate(o.bytes(), o.at() + 1, size);
			return value == null ? null : new RegisterImmediate(register(program, 0, size), value);
		}
		if (o.op() < 0x80 || o.op() > 0x83 || o.op() == 0x82) {
			return null;
		}
		ModRm modrm = o.modRm();
		if (modrm == null || !modrm.isRegister() || modrm.reg() != ext) {
			return null;
		}
		int size = o.op() == 0x80 ? 1 : 2;
		Long value = immediate(o.bytes(), o.at() + 2, o.op() == 0x81 ? 2 : 1);
		if (value == null) {
			return null;
		}
		if (o.op() == 0x83) {
			value = (long) (byte) value.longValue() & 0xffff;
		}
		return new RegisterImmediate(register(program, modrm.rm(), size), value);
	}

	/**
	 * The registers of a register-to-register ALU or {@code MOV} instruction: opcode
	 * {@code base} to {@code base+3} with {@code mod == 3}, where {@code base} is
	 * {@code ext*8} for the ALU group ({@code 00} ADD, {@code 08} OR, {@code 20} AND, …) or
	 * {@code 0x88} for {@code MOV}. In {@code base} and {@code base+1} the destination is
	 * {@code rm}, in {@code base+2} and {@code base+3} it is {@code reg}; the even opcodes are
	 * byte-sized. Null for any other instruction.
	 */
	static RegisterPair registerPair(Program program, Instruction instruction, int base) {
		Opcode o = opcode(instruction);
		if (o == null || o.op() < base || o.op() > base + 3) {
			return null;
		}
		ModRm modrm = o.modRm();
		if (modrm == null || !modrm.isRegister()) {
			return null;
		}
		int size = (o.op() & 1) == 0 ? 1 : 2;
		Register rm = register(program, modrm.rm(), size);
		Register reg = register(program, modrm.reg(), size);
		return o.op() - base < 2 ? new RegisterPair(rm, reg) : new RegisterPair(reg, rm);
	}

	/** Opcode base of {@code MOV r/m,r} for {@link #registerPair}. */
	static final int MOV = 0x88;

	/** ALU {@code /ext} numbers, for {@link #aluImmediate}; times 8, the {@link #registerPair} base. */
	static final int ADD = 0, OR = 1, AND = 4, CMP = 7;

	/** A shift of a register: {@code /ext} ({@code 4} SHL, {@code 5} SHR, …) by a count or by CL. */
	record Shift(int ext, Register register, int count, boolean byCl) {
	}

	/** Shift {@code /ext} numbers, for {@link Shift#ext}. */
	static final int SHL = 4, SHR = 5;

	/**
	 * The shift of a register in {@code instruction}: {@code D0/D1} by 1, {@code D2/D3} by CL,
	 * {@code C0/C1 ib} by an immediate, all with {@code mod == 3}. Null for any other.
	 */
	static Shift shift(Program program, Instruction instruction) {
		Opcode o = opcode(instruction);
		if (o == null || !(o.op() >= 0xd0 && o.op() <= 0xd3 || o.op() == 0xc0 || o.op() == 0xc1)) {
			return null;
		}
		ModRm modrm = o.modRm();
		if (modrm == null || !modrm.isRegister()) {
			return null;
		}
		Register register = register(program, modrm.rm(), (o.op() & 1) == 0 ? 1 : 2);
		if (o.op() <= 0xd1) {
			return new Shift(modrm.reg(), register, 1, false);
		}
		if (o.op() <= 0xd3) {
			return new Shift(modrm.reg(), register, 0, true);
		}
		Long count = immediate(o.bytes(), o.at() + 2, 1);
		return count == null ? null : new Shift(modrm.reg(), register, count.intValue(), false);
	}

	/**
	 * The two registers {@code XCHG} swaps — {@code 90+r} (AX with r16) or {@code 86/87} with
	 * {@code mod == 3} — or null for any other instruction ({@code 90} itself is NOP).
	 */
	static RegisterPair exchange(Program program, Instruction instruction) {
		Opcode o = opcode(instruction);
		if (o == null) {
			return null;
		}
		if (o.op() > 0x90 && o.op() <= 0x97) {
			return new RegisterPair(register(program, 0, 2), register(program, o.op() - 0x90, 2));
		}
		return o.op() == 0x86 || o.op() == 0x87 ? registerPair(program, instruction, 0x84) : null;
	}

	/** The divisor of a byte {@code DIV r8} ({@code F6 /6}, {@code mod == 3}), or null. */
	static Register byteDivisor(Program program, Instruction instruction) {
		Opcode o = opcode(instruction);
		ModRm modrm = o == null || o.op() != 0xf6 ? null : o.modRm();
		return modrm != null && modrm.isRegister() && modrm.reg() == 6
				? register(program, modrm.rm(), 1)
				: null;
	}

	/** The register {@code INC} increments — {@code 40+r} or {@code FE/FF /0} with {@code mod == 3} — or null. */
	static Register incremented(Program program, Instruction instruction) {
		Opcode o = opcode(instruction);
		if (o == null) {
			return null;
		}
		if (o.op() >= 0x40 && o.op() <= 0x47) {
			return register(program, o.op() - 0x40, 2);
		}
		ModRm modrm = o.op() == 0xfe || o.op() == 0xff ? o.modRm() : null;
		return modrm != null && modrm.isRegister() && modrm.reg() == 0
				? register(program, modrm.rm(), o.op() == 0xfe ? 1 : 2)
				: null;
	}

	/** The register a near {@code JMP r16} ({@code FF /4}, {@code mod == 3}) jumps through, or null. */
	static Register jumpRegister(Program program, Instruction instruction) {
		Opcode o = opcode(instruction);
		ModRm modrm = o == null || o.op() != 0xff ? null : o.modRm();
		return modrm != null && modrm.isRegister() && modrm.reg() == 4
				? register(program, modrm.rm(), 2)
				: null;
	}

	/** True for a far {@code JMP}: {@code EA ptr16:16} or {@code FF /5} through memory. */
	static boolean isFarJump(Instruction instruction) {
		Opcode o = opcode(instruction);
		if (o == null) {
			return false;
		}
		if (o.op() == 0xea) {
			return true;
		}
		ModRm modrm = o.op() == 0xff ? o.modRm() : null;
		return modrm != null && !modrm.isRegister() && modrm.reg() == 5;
	}

	/** True for any unconditional {@code JMP}: {@code E9}, {@code EB}, {@code FF /4}, or a {@link #isFarJump far} one. */
	static boolean isUnconditionalJump(Instruction instruction) {
		Opcode o = opcode(instruction);
		if (o == null) {
			return false;
		}
		if (o.op() == 0xe9 || o.op() == 0xeb || isFarJump(instruction)) {
			return true;
		}
		ModRm modrm = o.op() == 0xff ? o.modRm() : null;
		return modrm != null && modrm.reg() == 4;
	}

	/**
	 * An instruction's memory operand, decoded from its ModRM byte (or the {@code A0-A3}
	 * {@code moffs16} form).
	 *
	 * @param offset the offset it adds: a {@code [disp16]} address, the unsigned disp16, or the
	 *            disp8 as the CPU sign-extends it (so possibly negative)
	 * @param based whether a base or index register is added to {@code offset}
	 * @param stackDefault whether it addresses through BP, so defaults to SS
	 */
	record MemoryOperand(int offset, boolean based, boolean stackDefault) {
	}

	/**
	 * The memory operand of {@code instruction}, or null when it has none with a displacement
	 * ({@code [BX]}, {@code [BX+SI]}), has a register operand there, or uses 32-bit addressing
	 * ({@code 67}). Only call this on an instruction known to have a memory operand: any
	 * opcode that is not {@code A0-A3} is assumed to be followed by a ModRM byte.
	 */
	static MemoryOperand memoryOperand(Instruction instruction) {
		byte[] b = bytes(instruction);
		int i = opcodeIndex(b);
		if (i < 0 || hasPrefix(b, i, 0x67)) {
			return null;
		}
		int op = b[i] & 0xff;
		if (op >= 0xa0 && op <= 0xa3) {
			return i + 2 < b.length ? new MemoryOperand(word(b, i + 1), false, false) : null;
		}
		int at = op == 0x0f ? i + 2 : i + 1;
		if (at >= b.length) {
			return null;
		}
		ModRm modrm = modRm(b, at);
		if (modrm.isRegister() || at + modrm.displacementLength() >= b.length) {
			return null;
		}
		if (modrm.isDirect()) {
			return new MemoryOperand(word(b, at + 1), false, false);
		}
		boolean stack = modrm.rm() == 2 || modrm.rm() == 3 || modrm.rm() == 6;
		return switch (modrm.mod()) {
			case 1 -> new MemoryOperand(modrm.displacement(b, at), true, stack);
			case 2 -> new MemoryOperand(word(b, at + 1), true, stack);
			default -> null; // no displacement
		};
	}

	/**
	 * An immediate an instruction may be using as an address: {@code PUSH imm16} ({@code 68},
	 * no register), {@code MOV r16,imm16} ({@code B8+r}, {@code C7 /0}) and
	 * {@code ADD r16,imm16} ({@code 05}, {@code 81 /0}), registers only.
	 */
	record AddressOf(Register register, int value, boolean added) {
	}

	/**
	 * The full 16-bit immediate {@code instruction} might take the address of, or null. The
	 * sign-extended byte forms ({@code 6A}, {@code 83}) are not: {@code PUSH -1} is a constant.
	 */
	static AddressOf addressOf(Program program, Instruction instruction) {
		Opcode o = opcode(instruction);
		if (o == null) {
			return null;
		}
		byte[] b = o.bytes();
		int at = o.at();
		if (o.op() == 0x68 && at + 2 < b.length) {
			return new AddressOf(null, word(b, at + 1), false);
		}
		if (o.op() >= 0xb8 && o.op() <= 0xbf && at + 2 < b.length) {
			return new AddressOf(register(program, o.op() - 0xb8, 2), word(b, at + 1), false);
		}
		if (o.op() == 0x05 && at + 2 < b.length) {
			return new AddressOf(register(program, 0, 2), word(b, at + 1), true);
		}
		ModRm modrm = o.op() == 0x81 || o.op() == 0xc7 ? o.modRm() : null;
		if (modrm == null || !modrm.isRegister() || modrm.reg() != 0 || at + 3 >= b.length) {
			return null;
		}
		return new AddressOf(register(program, modrm.rm(), 2), word(b, at + 2), o.op() == 0x81);
	}

	/** True for a bare one-byte {@code XLAT} ({@code D7}) with no segment override. */
	static boolean isPlainXlat(Instruction instruction) {
		byte[] b = bytes(instruction);
		return b.length == 1 && b[0] == (byte) 0xd7;
	}

	// ---------------------------------------------------------------- registers

	/** True if {@code a} and {@code b} share bits: {@code AX} and {@code AH}, not {@code AH} and {@code AL}. */
	static boolean overlaps(Register a, Register b) {
		return a.contains(b) || b.contains(a);
	}

	/** True if {@code instruction} writes {@code register} or any register overlapping it. */
	static boolean writes(Instruction instruction, Register register) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register written && overlaps(written, register)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * True if {@code instruction} may change the value of {@code register}: {@link #writes},
	 * except {@code OR r,r} and {@code AND r,r}, which write {@code r} without changing it — the
	 * {@code OR AH,AH; JNZ} remainder check after a byte divide (NEBULAR OVERLAY_27).
	 */
	static boolean changes(Instruction instruction, Register register) {
		Program program = instruction.getProgram();
		for (int base : new int[] { OR * 8, AND * 8 }) {
			RegisterPair pair = registerPair(program, instruction, base);
			if (pair != null && pair.destination().equals(pair.source())) {
				return false;
			}
		}
		return writes(instruction, register);
	}

	/**
	 * The one register {@code mov} writes, from its p-code results, or null if it writes memory
	 * or more than one register. Not operand 0: see the class comment.
	 */
	static Register movDestination(Instruction mov) {
		Register written = null;
		for (Object result : mov.getResultObjects()) {
			if (!(result instanceof Register register) || written != null) {
				return null;
			}
			written = register;
		}
		return written;
	}

	/** The register {@code mov} copies, from its p-code inputs, or null for an immediate or memory source. */
	static Register movSourceRegister(Instruction mov) {
		Object[] inputs = mov.getInputObjects();
		return inputs.length == 1 && inputs[0] instanceof Register register ? register : null;
	}

	/**
	 * The immediate a {@code MOV reg,imm} loads, read from its bytes — {@code B0-B7 ib},
	 * {@code B8-BF iw}, or {@code C6 /0 ib} / {@code C7 /0 iw} with a register operand — or null
	 * for any other instruction. An operand's scalar is no substitute: {@code MOV BX,[0x2a56]}
	 * shows the address {@code 0x2a56} there too. The destination is {@link #movDestination}.
	 */
	static Long movImmediate(Instruction instruction) {
		byte[] b = bytes(instruction);
		int i = opcodeIndex(b);
		if (i < 0 || hasOperandSizePrefix(b, i)) {
			return null;
		}
		int op = b[i] & 0xff;
		if (op >= 0xb0 && op <= 0xb7) {
			return immediate(b, i + 1, 1);
		}
		if (op >= 0xb8 && op <= 0xbf) {
			return immediate(b, i + 1, 2);
		}
		if ((op == 0xc6 || op == 0xc7) && i + 1 < b.length) {
			ModRm modrm = modRm(b, i + 1);
			if (!modrm.isRegister() || modrm.reg() != 0) {
				return null;
			}
			return immediate(b, i + 2, op == 0xc6 ? 1 : 2);
		}
		return null;
	}

	/** The unsigned {@code size}-byte immediate at {@code b[at]}, or null past the end. */
	private static Long immediate(byte[] b, int at, int size) {
		if (at + size > b.length) {
			return null;
		}
		return (long) (size == 1 ? b[at] & 0xff : word(b, at));
	}

	/** True if an {@code 66} prefix precedes the opcode at {@code b[opcode]}: a 32-bit operand. */
	private static boolean hasOperandSizePrefix(byte[] b, int opcode) {
		return hasPrefix(b, opcode, 0x66);
	}

	/** True if {@code prefix} is among the prefixes before the opcode at {@code b[opcode]}. */
	static boolean hasPrefix(byte[] b, int opcode, int prefix) {
		for (int i = 0; i < opcode; i++) {
			if ((b[i] & 0xff) == prefix) {
				return true;
			}
		}
		return false;
	}

	static boolean isScalar(Scalar scalar, long value) {
		return scalar != null && scalar.getUnsignedValue() == value;
	}

	// ---------------------------------------------------------------- segments

	/**
	 * True if {@code jump} resolves its target against its 64KB page rather than the CS it runs
	 * with: stock's {@code currentCS} writes {@code (inst_next >> 4) & 0xf000} into CS as part of
	 * the jump, where upstream PR #9703 (the dailydriver fork) reads CS from context and writes
	 * nothing. A near jump writes CS for no other reason.
	 */
	static boolean resolvesAgainstPage(Program program, Instruction jump) {
		Register cs = program.getRegister("CS");
		return cs != null && writes(jump, cs);
	}

	/**
	 * The segment {@code block} starts at, or -1 for a block outside the segmented space: an
	 * overlay block's start is a {@code GenericAddress}.
	 */
	static int segment(MemoryBlock block) {
		return block.getStart() instanceof SegmentedAddress start ? start.getSegment() : -1;
	}

	/** The 64KB page segment of {@code address}, {@code (offset >> 4) & 0xf000}: stock's guess at CS. */
	static int pageSegment(Address address) {
		return (int) ((address.getOffset() >> 4) & 0xf000L);
	}

	/** The program's segmented (real-mode) default address space. */
	static SegmentedAddressSpace space(Program program) {
		return (SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
	}

	/**
	 * The CS {@code instruction} runs with: the value asserted in context (the MZ loader over
	 * each resident block, the overlay analyzer over each overlay module), else the segment of
	 * its address. Never the language default, which is a page guess.
	 */
	static int codeSegment(Program program, Instruction instruction, SegmentedAddress at) {
		Register cs = program.getLanguage().getRegister("CS");
		RegisterValue value = cs == null ? null
				: program.getProgramContext().getNonDefaultValue(cs, instruction.getMinAddress());
		if (value != null && value.hasValue()) {
			return value.getUnsignedValue().intValue() & 0xffff;
		}
		return at.getSegment();
	}

	/**
	 * The DS asserted in context at {@code at}, or null where none is. Only the overlay
	 * analyzer's DGROUP pass sets DS over code, so a value both names the data segment and
	 * confirms the assumption holds there.
	 */
	static Integer dataSegment(Program program, Address at) {
		Register ds = program.getLanguage().getRegister("DS");
		RegisterValue value =
			ds == null ? null : program.getProgramContext().getRegisterValue(ds, at);
		return value != null && value.hasValue() ? value.getUnsignedValue().intValue() & 0xffff
				: null;
	}
}
