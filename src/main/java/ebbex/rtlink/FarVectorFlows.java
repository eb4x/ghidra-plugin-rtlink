package ebbex.rtlink;

import java.util.Arrays;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair — far jumps and calls through a code-segment vector,
 * {@code JMPF CS:[imm16]} and {@code CALLF CS:[imm16]}.
 * <p>
 * Ghidra will not follow an indirect far flow, so whatever it lands on is never
 * disassembled and, having no reference, is never found by anything else either.
 * The vendor driver every binary in this corpus links does exactly this: its fatal
 * error handler is reached only through {@code JMPF CS:[0x656]}, and the vector is
 * a plain far pointer sitting initialized in the image (VICEROY {@code 275d:0656}
 * → {@code 275d:0660}). Eighty-three bytes of real code — redirect stdout to
 * stderr, print the message, wait for a key, {@code MOV AX,0x4C01; INT 21h} — that
 * no pass had ever decoded.
 * <p>
 * The vector is only followed when its four bytes are initialized and point into
 * mapped executable memory. A zero (or unrelocated) vector is patched at runtime
 * and resolves to nothing here — that is the RTLink dispatch-stub form, and it
 * belongs to {@link RTLinkOverlayAnalyzer}.
 */
final class FarVectorFlows {

	/** {@code JMPF CS:[disp16]} — CS prefix, opcode FF /5, mod=00 r/m=110. */
	private static final byte[] FAR_JUMP_VECTOR = { 0x2e, (byte) 0xff, 0x2e };

	/** {@code CALLF CS:[disp16]} — the same through opcode FF /3. */
	private static final byte[] FAR_CALL_VECTOR = { 0x2e, (byte) 0xff, 0x1e };

	private FarVectorFlows() {
	}

	/** Reference, disassemble and make functions of the vectors' targets; returns the count. */
	static int resolve(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		ReferenceManager references = program.getReferenceManager();
		AddressSet targets = new AddressSet();
		int resolved = 0;

		for (Instruction instruction : listing.getInstructions(true)) {
			monitor.checkCancelled();
			Vector vector = Vector.of(instruction);
			if (vector == null) {
				continue;
			}
			Address target = farPointerAt(program, instruction, vector.offset());
			if (target == null) {
				continue;
			}
			// Since GP-7349 Ghidra resolves the vector itself and plants the reference, but
			// a target only that reference reaches may still be undecoded: done means both.
			boolean referenced = CodeEvidence.refersTo(instruction, target, RefType::isFlow);
			boolean decoded = listing.getInstructionAt(target) != null;
			if (referenced && decoded) {
				continue; // idempotent for one-shot re-runs
			}
			if (!referenced) {
				references.addMemoryReference(instruction.getMinAddress(), target,
					vector.call() ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP, SourceType.ANALYSIS,
					Reference.MNEMONIC);
			}
			if (!decoded) {
				targets.add(target);
			}
			resolved++;
		}

		if (!targets.isEmpty()) {
			new DisassembleCommand(targets, null, true).applyTo(program, monitor);
			for (Address target : targets.getAddresses(true)) {
				monitor.checkCancelled();
				if (listing.getInstructionAt(target) != null) {
					CodeEvidence.makeFunction(program, target, monitor);
				}
			}
		}
		return resolved;
	}

	/**
	 * A far flow through a code-segment vector: the vector's {@code CS} offset, and whether it
	 * is a call ({@code CALLF}) or a jump ({@code JMPF}).
	 */
	private record Vector(int offset, boolean call) {

		/** The vector {@code instruction} flows through, or null if it is neither form. */
		static Vector of(Instruction instruction) {
			byte[] bytes = X86.bytes(instruction);
			if (matches(bytes, FAR_CALL_VECTOR)) {
				return new Vector(X86.word(bytes, FAR_CALL_VECTOR.length), true);
			}
			if (matches(bytes, FAR_JUMP_VECTOR)) {
				return new Vector(X86.word(bytes, FAR_JUMP_VECTOR.length), false);
			}
			return null;
		}

		/** True if {@code bytes} are exactly {@code pattern} plus a disp16. */
		private static boolean matches(byte[] bytes, byte[] pattern) {
			return bytes.length == pattern.length + 2 &&
				Arrays.equals(bytes, 0, pattern.length, pattern, 0, pattern.length);
		}
	}

	/**
	 * The {@code seg:off} far pointer stored at {@code CS:offset}, or null when it is
	 * not initialized, not mapped, or does not point at executable memory.
	 */
	private static Address farPointerAt(Program program, Instruction instruction, int offset) {
		if (!(instruction.getMinAddress() instanceof SegmentedAddress at)) {
			return null;
		}
		SegmentedAddressSpace space = (SegmentedAddressSpace) at.getAddressSpace();
		Address vector = space.getAddress(at.getSegment(), offset);
		MemoryBlock block = program.getMemory().getBlock(vector);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		try {
			X86.FarPointer pointer = X86.farPointer(program.getMemory(), vector);
			if (pointer.segment() == 0) {
				return null; // unrelocated: patched at runtime, not ours to follow
			}
			Address target = pointer.in(space);
			MemoryBlock targetBlock = program.getMemory().getBlock(target);
			if (targetBlock == null || !targetBlock.isExecute() ||
				!targetBlock.isInitialized()) {
				return null;
			}
			return target;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException _) {
			return null;
		}
	}
}
