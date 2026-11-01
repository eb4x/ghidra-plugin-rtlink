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
		String mnemonic = instruction.getMnemonicString();
		if (("OR".equals(mnemonic) || "AND".equals(mnemonic)) &&
			instruction.getRegister(0) != null &&
			instruction.getRegister(0).equals(instruction.getRegister(1))) {
			return false;
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
		for (int i = 0; i < opcode; i++) {
			if ((b[i] & 0xff) == 0x66) {
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
