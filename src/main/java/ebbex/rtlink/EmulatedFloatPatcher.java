package ebbex.rtlink;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Rewrites the DOS floating-point emulator's {@code INT} calls into the x87 instructions
 * they stand for, so the disassembler can read them.
 * <p>
 * Microsoft C and Borland C compile floating-point code for machines that may or may not
 * have a coprocessor. Each x87 instruction {@code ESC(D8+n) modrm...} is emitted instead as
 * {@code INT (34h+n) modrm...} — the two-byte {@code CD 3n} exactly replacing the one-byte
 * ESC plus the {@code WAIT} that would precede it. At load time the runtime patches every
 * site in place: with a coprocessor present, {@code CD 3n} becomes {@code 9B D8+n}
 * (WAIT + ESC), which is why the encoding is the length it is. The bytes that follow —
 * the modrm and any displacement — are <b>operands</b> in both forms.
 * <p>
 * Ghidra's x86 real-mode Sleigh has no notion of this, so it decodes {@code CD 3n} as a
 * plain two-byte {@code INT} and then disassembles the operand bytes as code. In a
 * float-heavy program the damage is extensive: ROE2MAIN.EXE (Rules of Engagement 2) has
 * 1010 such calls and every one of them derails the instruction stream, which is where its
 * "conflicting instruction" and "Unable to resolve constructor" errors came from.
 * <p>
 * This class performs the same patch the runtime does, before anything is disassembled.
 * The rewritten bytes are the real instruction encoding, so everything downstream — the
 * disassembler, the decompiler, p-code — sees genuine x87.
 * <p>
 * The mapping is not guesswork; it is confirmed by what the operand bytes decode to.
 * In ROE2MAIN the modrm following {@code INT 3Bh} is {@code E0} 40 times
 * ({@code DF E0} = {@code FNSTSW AX}), the one following {@code INT 3Ah} is
 * {@code C1/C9/E9/F9} ({@code FADDP/FMULP/FSUBP/FDIVP}), and the one following
 * {@code INT 35h} is {@code C9/E0} ({@code FXCH}/{@code FCHS}) — textbook x87 in every
 * case, and meaningless under any other reading.
 */
class EmulatedFloatPatcher {

	private static final byte OPCODE_INT = (byte) 0xCD;
	private static final byte OPCODE_WAIT = (byte) 0x9B;
	private static final byte OPCODE_NOP = (byte) 0x90;

	/** {@code INT 34h}..{@code INT 3Bh} stand for {@code ESC 0}..{@code ESC 7} = D8..DF. */
	private static final int FIRST_ESC_INT = 0x34;
	private static final int LAST_ESC_INT = 0x3B;
	private static final int FIRST_ESC_OPCODE = 0xD8;

	/**
	 * {@code INT 3Ch} stands for an ESC carrying a <b>segment override</b>: the real
	 * instruction is {@code WAIT; <seg>: ESC...}, and the ESC opcode is the byte after the
	 * INT rather than being encoded in the interrupt number. <b>Bits 7-6 of that byte select
	 * the segment</b>, and the ESC is the byte with both set again ({@code 11011xxx}):
	 * <ul>
	 * <li>{@code 11} ({@code D8}-{@code DF}) — {@code ES:}; the byte already is the ESC.
	 * Every such site in ROE2MAIN is preceded by {@code LES SI,[BP+8]} or
	 * {@code MOV ES,[..]}: the program has just loaded a far pointer and dereferences it.</li>
	 * <li>{@code 01} ({@code 58}-{@code 5F}) — {@code SS:}. Every one of ROE2MAIN's 154 such
	 * sites has modrm {@code rm=7}, i.e. <b>{@code [BX]}</b> — and the code before it is
	 * always {@code SUB SP,8; MOV BX,SP}. {@code [BX]} defaults to {@code DS}, so
	 * addressing that stack temp <em>requires</em> the {@code SS:} override. Restored they
	 * read {@code FLD/FST/FSTP qword ptr [BX]} — a double being passed by value.</li>
	 * <li>{@code 10} ({@code 98}-{@code 9F}) — {@code CS:}.</li>
	 * <li>{@code 00} ({@code 18}-{@code 1F}) — {@code DS:}.</li>
	 * </ul>
	 * The encoding is the linker's: Microsoft's emulator fixups turn {@code 9B <seg>} into
	 * {@code CD 3C} (FIERQQ, FISRQQ, FICRQQ, FIARQQ) and add {@code 80h}, {@code C0h} or
	 * {@code 40h} to the ESC byte (FJSRQQ, FJCRQQ, FJARQQ), carry discarded — so only the
	 * top two bits change. The CS: and DS: forms follow from the fixup values (OS/2 Museum,
	 * "8087 Emulation on 8086 Systems"; Wine's INT 3Ch notes agree) and have not been seen
	 * in the corpus.
	 */
	private static final int SEGMENT_OVERRIDE_INT = 0x3C;

	/** The prefix for each value of bits 7-6 of the INT 3Ch byte: DS, SS, CS, ES. */
	private static final byte[] SEGMENT_PREFIXES = { 0x3E, 0x36, 0x2E, 0x26 };

	/** Bits 5-3 of an ESC opcode ({@code 11011xxx}), which every INT 3Ch byte keeps. */
	private static final int ESC_LOW_MASK = 0x38;
	private static final int ESC_LOW_BITS = 0x18;

	/** The ESC opcode's top bits, which the segment selector replaced. */
	private static final int ESC_SEGMENT_BITS = 0xC0;

	/**
	 * {@code INT 3Dh} is {@code FWAIT} — it takes no operand bytes (the byte after it is
	 * always the start of an ordinary instruction) and sits exactly where a wait belongs:
	 * between an FPU status store and the read of it
	 * ({@code FSTSW [BP+x]; INT 3Dh; TEST [BP+x],8}) and immediately before far calls.
	 * Patches two bytes to two: {@code WAIT} + {@code NOP}.
	 */
	private static final int WAIT_INT = 0x3D;

	/**
	 * Below this many emulator calls a program is not treated as float-emulated, and
	 * nothing is patched. Guards against a program that legitimately uses an interrupt in
	 * this range: the emulator saturates the code (ROE2MAIN has 1010), while binaries that
	 * merely contain the byte pair by accident have a handful (VICEROY 8, SPHERE 2,
	 * NEBULAR 1) — the two populations are three orders of magnitude apart, so the exact
	 * threshold is not delicate.
	 */
	private static final int MIN_EMULATOR_CALLS = 32;

	/**
	 * Bytes to clear past a rewritten call, so the out-of-phase instructions the mis-decode
	 * left behind cannot block the corrected flow. Long enough to cover the longest x86
	 * instruction the wreckage can start (plus its overlap), short enough that fallthrough
	 * from the rewritten site puts everything back.
	 */
	private static final int CLEAR_LOOKAHEAD = 12;

	private EmulatedFloatPatcher() {
	}

	/**
	 * True if {@code program} is float-emulated: either it has already been recognized as
	 * such ({@link RTLinkProgram#isFloatEmulated} — the rewrite consumes the very bytes this
	 * counts, so the answer is recorded before it runs), or its resident code still carries
	 * enough emulator calls to say so. Overlay blocks are not scanned — the question has to be
	 * answerable before they exist, and a program whose float code lives entirely in overlays
	 * still links the emulator's INT handlers into the resident image.
	 */
	static boolean isEmulated(Program program, TaskMonitor monitor) throws CancelledException {
		if (RTLinkProgram.isFloatEmulated(program)) {
			return true;
		}

		Memory memory = program.getMemory();
		int calls = 0;
		for (MemoryBlock block : memory.getBlocks()) {
			if (!CodeSeeds.isResidentCode(block)) {
				continue;
			}
			calls += CodeSeeds.scan(memory, block, new byte[] { OPCODE_INT }, null, monitor, at -> {
				int vector = Byte.toUnsignedInt(memory.getByte(at.add(1)));
				return vector >= FIRST_ESC_INT && vector <= LAST_ESC_INT;
			});
			if (calls >= MIN_EMULATOR_CALLS) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Rewrite the emulator call that {@code insn} decoded as, into the x87 instruction it
	 * stands for, and re-disassemble over it.
	 * <p>
	 * <b>Patching is driven by the disassembler, never by a byte scan.</b> The two bytes
	 * {@code CD 3n} are not distinguishable from operand bytes by inspection, and a blind
	 * scan does real damage: ROE2MAIN.EXE has a dispatch stub whose {@code JMPF} target
	 * offset is {@code 0x34CD} — little-endian {@code CD 34} — and a byte scan rewrote it,
	 * destroying the stub. It cannot be fixed by looking at surrounding bytes either: 15 of
	 * the 16 sites with a {@code 9A}/{@code EA} in the preceding four bytes are genuine
	 * emulator calls whose neighbour merely has a displacement byte of that value
	 * ({@code MOV [BP-0x16],DX} = {@code 89 56 EA}). Only an instruction the disassembler
	 * reached by flow is known to start where it appears to, which is exactly what this
	 * takes.
	 * <p>
	 * {@code insn} must be live: an earlier patch's clear may have deleted it, and a deleted
	 * instruction does not fail — it reads whatever bytes now sit at its old address. Callers
	 * re-fetch it by address immediately before calling.
	 *
	 * @param analyze whether the re-disassembly may start auto-analysis, as disassembly does;
	 *        false for a pass that has to finish a repair before analysis sees any of it
	 * @return what the rewrite cleared and re-disassembled, or null if the site was not patched
	 */
	static AddressSetView patch(Program program, Instruction insn, boolean analyze,
			TaskMonitor monitor) throws CancelledException {
		int vector = emulatorVector(insn);
		if (vector < 0) {
			return null;
		}

		Memory memory = program.getMemory();
		Address addr = insn.getMinAddress();
		try {
			// Work out the real instruction's extent first, while only reading. The
			// rewritten instruction is at least as long as the INT it replaces, and the
			// code after it was decoded from what are really its operand bytes.
			byte opcode;
			int span;
			Address escAddr = addr.add(2);
			int storedEsc = -1; // the INT 3Ch byte, when the rewrite changes it

			if (vector <= LAST_ESC_INT) {
				// CD 3n modrm...  ->  9B D8+n modrm...   (WAIT + ESC; operands untouched)
				opcode = (byte) (FIRST_ESC_OPCODE + vector - FIRST_ESC_INT);
				span = 3 + displacementLength(memory, escAddr);
			}
			else if (vector == WAIT_INT) {
				// CD 3D  ->  9B 90   (WAIT + NOP; FWAIT takes no operands)
				opcode = OPCODE_NOP;
				span = 2;
			}
			else {
				// CD 3C <b> modrm...  ->  9B <seg> <ESC> modrm...
				// Bits 7-6 of <b> pick the segment, and the ESC is <b> with both put back.
				// See SEGMENT_OVERRIDE_INT.
				int b = Byte.toUnsignedInt(memory.getByte(escAddr));
				if ((b & ESC_LOW_MASK) != ESC_LOW_BITS) {
					return null; // not an ESC under any segment; leave it as an INT
				}
				opcode = SEGMENT_PREFIXES[b >> 6];
				if ((b | ESC_SEGMENT_BITS) != b) {
					storedEsc = b;
				}
				span = 4 + displacementLength(memory, addr.add(3));
			}

			// Clear before writing: Ghidra refuses to modify bytes that a defined
			// instruction covers, so the INT and the mis-decoded code after it have to go
			// first. Then rewrite, then disassemble again — flow from here regenerates
			// everything downstream.
			//
			// Clear past the instruction, not just over it. The mis-decode does not stop at
			// the emulator call's last byte: reading the operands as code leaves the stream
			// out of phase, so the instructions that follow start on the wrong boundaries
			// and would block the corrected flow — Ghidra will not decode an instruction
			// that overlaps an existing one. At 1a5e:0069 in ROE2MAIN, the old decode ran
			// D8 CD across the next call's INT prefix, and left a CMP one byte past it that
			// pinned the whole run out of phase. The lookahead is generous because
			// straight-line float code re-disassembles from here by fallthrough anyway.
			Address blockEnd = memory.getBlock(addr).getEnd();
			Address last = addr.add(span - 1 + CLEAR_LOOKAHEAD);
			if (last.compareTo(blockEnd) > 0) {
				last = blockEnd;
			}
			program.getListing().clearCodeUnits(addr, last, false);

			// Keep the bytes the rewrite overwrites, for the relocation record — three of
			// them in the DS:, SS: and CS: forms, which also restore the ESC opcode's top bits.
			byte[] original = storedEsc >= 0
					? new byte[] { OPCODE_INT, (byte) vector, (byte) storedEsc }
					: new byte[] { OPCODE_INT, (byte) vector };
			memory.setByte(addr, OPCODE_WAIT);
			memory.setByte(addr.add(1), opcode);
			if (storedEsc >= 0) {
				memory.setByte(escAddr, (byte) (storedEsc | ESC_SEGMENT_BITS));
			}

			// Record the rewrite, exactly as RTLinkOverlayAnalyzer records the relocations
			// it applies. This is a load-time fixup — the same one the DOS runtime performs
			// when it finds a coprocessor — and like any fixup it leaves the program's bytes
			// differing from the file on disk. Putting it in the relocation table is what
			// makes that difference visible and auditable (Window > Relocation Table) rather
			// than a silent discrepancy for the next person who diffs against the raw EXE.
			program.getRelocationTable().add(addr, Status.APPLIED, vector,
				new long[] { vector, Byte.toUnsignedInt(opcode) }, original,
				String.format("EMULATED_FP_INT_%02X", vector));

			DisassembleCommand redo =
				new DisassembleCommand(restartPoints(program, addr, last), null, true);
			redo.enableCodeAnalysis(analyze);
			redo.applyTo(program, monitor);
			AddressSet touched = new AddressSet(addr, last);
			touched.add(redo.getDisassembledAddressSet());
			return touched;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Where to disassemble from after the rewrite: the patched instruction, plus anything
	 * inside the cleared window that is the destination of a flow reference.
	 * <p>
	 * Flow from the patch point regenerates the straight-line code after it, but only that.
	 * A jump target inside the window is reached from somewhere else — clearing it and then
	 * disassembling by flow alone would leave it as raw bytes. That is not hypothetical:
	 * the {@code JMP word ptr [DI]} at {@code 122e:5280} in ROE2MAIN.EXE has a case at
	 * {@code 122e:528a}, which sits within the window of the emulator call two bytes into
	 * the case before it. Recovering that switch (see {@code RTLinkSwitchTableAnalyzer}) is
	 * what makes the case reachable in the first place, and the reference it adds is what
	 * this finds it by.
	 * <p>
	 * Only <em>flow</em> destinations are restarted, never every address that used to hold
	 * an instruction: the mis-decoded run this clears is out of phase, so its old
	 * instruction starts are exactly the wrong boundaries to disassemble from again.
	 */
	private static AddressSet restartPoints(Program program, Address addr, Address last) {
		AddressSet starts = new AddressSet(addr, addr);
		Address afterPatch = addr.next();
		if (afterPatch == null || afterPatch.compareTo(last) > 0) {
			return starts;
		}
		AddressIterator cleared = program.getReferenceManager()
				.getReferenceDestinationIterator(new AddressSet(afterPatch, last), true);
		while (cleared.hasNext()) {
			Address destination = cleared.next();
			if (CodeEvidence.hasFlowReferenceTo(program, destination)) {
				starts.add(destination);
			}
		}
		return starts;
	}

	/**
	 * The emulator interrupt vector {@code insn} calls ({@code 34h}..{@code 3Ch}), or -1 if
	 * it is not an emulator call.
	 * <p>
	 * Read from the instruction's bytes rather than its operand: {@code CD 3n} is the whole
	 * of what identifies an emulator call, and matching the encoding directly avoids any
	 * assumption about how the operand happens to be modelled.
	 */
	static int emulatorVector(Instruction insn) {
		byte[] bytes = X86.bytes(insn);
		if (bytes.length != 2 || bytes[0] != OPCODE_INT) {
			return -1;
		}
		int vector = Byte.toUnsignedInt(bytes[1]);
		return (vector >= FIRST_ESC_INT && vector <= WAIT_INT) ? vector : -1;
	}

	/**
	 * Bytes of displacement carried by the 16-bit modrm at {@code addr} — the only part of
	 * an x87 instruction's length that varies.
	 */
	private static int displacementLength(Memory memory, Address addr)
			throws MemoryAccessException {
		int modrm = Byte.toUnsignedInt(memory.getByte(addr));
		return switch (modrm >> 6) {
			case 0 -> (modrm & 0x7) == 0x6 ? 2 : 0; // [disp16]: the only mod-0 form with one
			case 1 -> 1;
			case 2 -> 2;
			default -> 0; // mod 3: register operand, no memory reference
		};
	}

}
