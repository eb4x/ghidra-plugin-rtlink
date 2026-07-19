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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
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
	private static final byte PREFIX_ES = (byte) 0x26;
	private static final byte PREFIX_SS = (byte) 0x36;

	/** {@code INT 34h}..{@code INT 3Bh} stand for {@code ESC 0}..{@code ESC 7} = D8..DF. */
	private static final int FIRST_ESC_INT = 0x34;
	private static final int LAST_ESC_INT = 0x3B;
	private static final int FIRST_ESC_OPCODE = 0xD8;

	/**
	 * {@code INT 3Ch} stands for an ESC carrying a <b>segment override</b>: the real
	 * instruction is {@code WAIT; <seg>: ESC...}, and the ESC opcode is the byte after the
	 * INT rather than being encoded in the interrupt number. <b>Bit 7 of that byte selects
	 * the segment</b>:
	 * <ul>
	 * <li>set ({@code D8}-{@code DF}) — {@code ES:}; the opcode is already the ESC.
	 * Every such site is preceded by {@code LES SI,[BP+8]} or {@code MOV ES,[..]}: the
	 * program has just loaded a far pointer and is dereferencing it.</li>
	 * <li>clear ({@code 58}-{@code 5F}) — {@code SS:}; the opcode is the ESC with bit 7
	 * cleared, and restoring it is part of the patch. Every one of ROE2MAIN's 154 such
	 * sites has modrm {@code rm=7}, i.e. <b>{@code [BX]}</b> — and the code before it is
	 * always {@code SUB SP,8; MOV BX,SP}. {@code [BX]} defaults to {@code DS}, so
	 * addressing that stack temp <em>requires</em> the {@code SS:} override. Restored they
	 * read {@code FLD/FST/FSTP qword ptr [BX]} — a double being passed by value.</li>
	 * </ul>
	 */
	private static final int SEGMENT_OVERRIDE_INT = 0x3C;

	/**
	 * {@code INT 3Dh} is {@code FWAIT} — it takes no operand bytes (the byte after it is
	 * always the start of an ordinary instruction) and sits exactly where a wait belongs:
	 * between an FPU status store and the read of it
	 * ({@code FSTSW [BP+x]; INT 3Dh; TEST [BP+x],8}) and immediately before far calls.
	 * Patches two bytes to two: {@code WAIT} + {@code NOP}.
	 */
	private static final int WAIT_INT = 0x3D;

	/** ESC opcodes with bit 7 cleared, as the {@code SS:} form of {@code INT 3Ch} carries them. */
	private static final int FIRST_MASKED_ESC = 0x58;
	private static final int LAST_MASKED_ESC = 0x5F;
	private static final int ESC_HIGH_BIT = 0x80;

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

	/**
	 * PROGRAM_INFO property recording that this program was found to be float-emulated.
	 * <p>
	 * Needed because the detector reads the very bytes the patch destroys: once the
	 * resident blocks have been rewritten, a fresh scan finds no emulator calls and would
	 * report the program as not emulated — so an overlay block created later would never
	 * be patched. The flag preserves the answer across that.
	 */
	private static final String EMULATED_FLAG = "DOS Emulated Floating Point";

	private EmulatedFloatPatcher() {
	}

	/**
	 * True if {@code program} is float-emulated: either it has already been recognized as
	 * such (see {@link #EMULATED_FLAG}), or its resident code still carries enough emulator
	 * calls to say so. Overlay blocks are not scanned — the question has to be answerable
	 * before they exist, and a program whose float code lives entirely in overlays still
	 * links the emulator's INT handlers into the resident image.
	 */
	static boolean isEmulated(Program program, TaskMonitor monitor) throws CancelledException {
		if (program.getOptions(Program.PROGRAM_INFO).getBoolean(EMULATED_FLAG, false)) {
			return true;
		}

		Memory memory = program.getMemory();
		int calls = 0;
		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}
			calls += countEmulatorCalls(memory, block, monitor);
			if (calls >= MIN_EMULATOR_CALLS) {
				return true;
			}
		}
		return false;
	}

	/** Record that {@code program} is float-emulated, before its calls are rewritten away. */
	static void recordEmulated(Program program) {
		program.getOptions(Program.PROGRAM_INFO).setBoolean(EMULATED_FLAG, true);
	}

	private static int countEmulatorCalls(Memory memory, MemoryBlock block, TaskMonitor monitor)
			throws CancelledException {
		int calls = 0;
		Address addr = block.getStart();
		Address end = block.getEnd();
		while (addr != null && addr.compareTo(end) < 0) {
			monitor.checkCancelled();
			addr = memory.findBytes(addr, end, new byte[] { OPCODE_INT }, null, true, monitor);
			if (addr == null) {
				break;
			}
			try {
				int vector = Byte.toUnsignedInt(memory.getByte(addr.add(1)));
				if (vector >= FIRST_ESC_INT && vector <= LAST_ESC_INT) {
					calls++;
				}
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				// past the end of the block; nothing to count
			}
			addr = addr.add(1);
		}
		return calls;
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
	 *
	 * @return true if the site was patched
	 */
	static boolean patch(Program program, Instruction insn, TaskMonitor monitor)
			throws CancelledException {
		int vector = emulatorVector(insn);
		if (vector < 0) {
			return false;
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
			byte restoredEsc = 0;

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
				// CD 3C <esc> modrm...  ->  9B <seg> <ESC> modrm...
				// Bit 7 of the byte after the INT picks the segment: set = ES: and the byte
				// already is the ESC; clear = SS: and the ESC is the byte with bit 7 put
				// back. See SEGMENT_OVERRIDE_INT.
				int esc = Byte.toUnsignedInt(memory.getByte(escAddr));
				if (esc >= FIRST_ESC_OPCODE && esc <= FIRST_ESC_OPCODE + 7) {
					opcode = PREFIX_ES;
				}
				else if (esc >= FIRST_MASKED_ESC && esc <= LAST_MASKED_ESC) {
					opcode = PREFIX_SS;
					restoredEsc = (byte) (esc | ESC_HIGH_BIT);
				}
				else {
					return false; // not a form this understands; leave it as an INT
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
			// them in the SS: form, which also restores the ESC opcode's high bit.
			byte[] original = restoredEsc != 0
					? new byte[] { OPCODE_INT, (byte) vector,
						(byte) (restoredEsc & ~ESC_HIGH_BIT) }
					: new byte[] { OPCODE_INT, (byte) vector };
			memory.setByte(addr, OPCODE_WAIT);
			memory.setByte(addr.add(1), opcode);
			if (restoredEsc != 0) {
				// SS: form only — the ESC opcode is stored with bit 7 cleared, so put it back.
				memory.setByte(escAddr, restoredEsc);
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

			new DisassembleCommand(restartPoints(program, addr, last), null, true)
					.applyTo(program, monitor);
			return true;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
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
		ReferenceManager references = program.getReferenceManager();
		AddressIterator cleared = references
				.getReferenceDestinationIterator(new AddressSet(afterPatch, last), true);
		while (cleared.hasNext()) {
			Address destination = cleared.next();
			for (Reference reference : references.getReferencesTo(destination)) {
				if (reference.getReferenceType().isFlow()) {
					starts.add(destination);
					break;
				}
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
		byte[] bytes;
		try {
			bytes = insn.getBytes();
		}
		catch (MemoryAccessException e) {
			return -1;
		}
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
		int mod = modrm >> 6;
		int rm = modrm & 0x7;
		switch (mod) {
			case 0:
				return rm == 0x6 ? 2 : 0; // [disp16] is the only mod-0 form with a displacement
			case 1:
				return 1;
			case 2:
				return 2;
			default:
				return 0; // mod 3: register operand, no memory reference
		}
	}

}
