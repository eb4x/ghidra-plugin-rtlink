package ebbex.rtlink;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * One RTLink VM dispatch jump: the {@code JMP reg} itself, the register, and the
 * {@code MOV reg,imm16} constants that reach it, found once by {@link #of}. See
 * {@link RTLinkDispatcherJumpAnalyzer} for what the dispatch is and why stock gets it wrong.
 *
 * @param jump the {@code JMP reg} ({@code FF /4}, {@code mod == 3})
 * @param register the register it jumps through
 * @param immediates the constants that reach it, in walk order; never empty
 */
record VmDispatch(Instruction jump, Register register, Set<Long> immediates) {

	/** How many instructions back to look for the constant that feeds the jump register. */
	private static final int FEEDER_WALK_LIMIT = 16;

	/** 16-bit MOV r/m16, r16. The return-slot patch's opcode (e.g. {@code 89 44 fc}). */
	private static final int OPCODE_MOV_RM_R = 0x89;

	/**
	 * The dispatch at {@code jmp}, or null unless it is one: a register-indirect near jump,
	 * immediately preceded by a return-slot patch {@code MOV [base-disp], reg} and fed by a
	 * {@code MOV <jumpreg>, imm16}. The return-slot patch is the near-unforgeable gate — a
	 * compiler does not store into a return-offset slot and then jump through a
	 * just-constant-loaded register.
	 */
	static VmDispatch of(Program program, Instruction jmp) {
		if (!jmp.getFlowType().isComputed() || !jmp.getFlowType().isJump()) {
			return null;
		}
		Register register = X86.jumpRegister(program, jmp);
		if (register == null || !hasReturnSlotPatchBefore(program, jmp)) {
			return null;
		}
		Set<Long> immediates = loadedImmediates(program, jmp, register);
		return immediates.isEmpty() ? null : new VmDispatch(jmp, register, immediates);
	}

	/** Every dispatch in {@code set}, found before anything changes the listing. */
	static List<VmDispatch> in(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		List<VmDispatch> dispatches = new ArrayList<>();
		for (Instruction jmp : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			VmDispatch dispatch = of(program, jmp);
			if (dispatch != null) {
				dispatches.add(dispatch);
			}
		}
		return dispatches;
	}

	/**
	 * Lay down the true {@code CS:imm} references on every dispatch in {@code set} ahead of
	 * {@code CODE_ANALYSIS}, for {@link RTLinkSwitchTableAnalyzer} to call; returns how many
	 * jumps it claimed.
	 * <p>
	 * {@code DecompilerSwitchAnalyzer} runs at {@code CODE_ANALYSIS}, long before the dispatcher
	 * pass, and leaves alone any computed branch that already carries a computed reference.
	 * Where {@code currentCS} still resolves against the 64KB page (stock Ghidra; the dailydriver
	 * fork carries #9703), it reads {@code JMP DX} as a switch over the page and plants a
	 * reference to every byte of the code below it — 110 on the smoke sample, {@code 1000:0000}
	 * to {@code 1000:006f}, junk decoded at each — which no immediate explains, so
	 * {@link RTLinkDispatcherJumpAnalyzer#resolveDispatchJumps} could not take them back.
	 * Claimed first, the jump is never read as a switch at all. Only where the jump does resolve
	 * against the page ({@link X86#resolvesAgainstPage}): with #9703 the switch pass reads it
	 * correctly, and pre-empting it there moves VICEROY's nucleus function boundaries
	 * ({@code 210d:0c7f} ends up inside {@code 210d:0e52}). Not at all where the dispatcher
	 * analyzer is switched off: the claim is half of its work, and the other half would never
	 * follow.
	 */
	static int claim(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		if (!RTLinkProgram.isAnalyzerEnabled(program, RTLinkDispatcherJumpAnalyzer.NAME)) {
			return 0;
		}
		List<VmDispatch> dispatches = new ArrayList<>();
		for (Instruction jmp : program.getListing().getInstructions(set, true)) {
			monitor.checkCancelled();
			VmDispatch dispatch = X86.resolvesAgainstPage(program, jmp) ? of(program, jmp) : null;
			if (dispatch != null) {
				dispatches.add(dispatch);
			}
		}
		int claimed = 0;
		for (VmDispatch dispatch : dispatches) {
			monitor.checkCancelled();
			if (dispatch.referenceBodies(program) > 0) {
				claimed++;
			}
		}
		return claimed;
	}

	/** The {@code CS:imm} bodies, in resident code only: the nucleus is resident. */
	List<Address> bodies(Program program) {
		if (!(jump.getMinAddress() instanceof SegmentedAddress at)) {
			return List.of();
		}
		int segment = X86.codeSegment(program, jump, at);
		SegmentedAddressSpace space = (SegmentedAddressSpace) at.getAddressSpace();
		List<Address> bodies = new ArrayList<>();
		for (long imm : immediates) {
			Address body = space.getAddress(segment, (int) imm);
			if (CodeSeeds.isResidentCode(program.getMemory(), body)) {
				bodies.add(body);
			}
		}
		return bodies;
	}

	/**
	 * Reference every body from the jump, decoding nothing; returns how many references were
	 * added. The early claim needs no more: the reference is what the switch pass checks, and
	 * the bodies are decoded in the dispatcher pass's own slot.
	 */
	int referenceBodies(Program program) {
		ReferenceManager references = program.getReferenceManager();
		int added = 0;
		for (Address body : bodies(program)) {
			if (!CodeEvidence.refersTo(jump, body, RefType::isJump)) {
				references.addMemoryReference(jump.getMinAddress(), body, RefType.COMPUTED_JUMP,
					SourceType.ANALYSIS, Reference.MNEMONIC);
				added++;
			}
		}
		return added;
	}

	/**
	 * True when the instruction immediately before {@code jmp} is a return-slot patch:
	 * {@code MOV word ptr [base - disp], reg16} — opcode {@code 0x89}, a memory ModRM with a
	 * base register ({@code [SI]/[DI]/[BP]/[BX]}) and a negative displacement. This is the
	 * {@code 89 44 fc} ({@code MOV [SI-4],AX}) fingerprint seen in every corpus dispatcher.
	 */
	private static boolean hasReturnSlotPatchBefore(Program program, Instruction jmp) {
		Instruction prev = program.getListing().getInstructionBefore(jmp.getMinAddress());
		if (prev == null) {
			return false;
		}
		Address after = prev.getMaxAddress().next();
		if (after == null || !after.equals(jmp.getMinAddress())) {
			return false; // must be immediately, contiguously before the jump
		}
		byte[] bytes = X86.bytes(prev);
		int i = X86.opcodeIndex(bytes);
		if (i < 0 || i + 2 >= bytes.length || (bytes[i] & 0xff) != OPCODE_MOV_RM_R) {
			return false;
		}
		X86.ModRm modrm = X86.modRm(bytes, i + 1);
		// Memory form with a base register: 16-bit rm 4=[SI] 5=[DI] 6=[BP] 7=[BX]; mod 1/2
		// carry a displacement (mod 0 has none, and rm 6 mod 0 is the [disp16] direct form).
		if (modrm.rm() < 4 || modrm.mod() == 0 || modrm.isRegister()) {
			return false;
		}
		if (modrm.mod() == 2 && i + 3 >= bytes.length) {
			return false;
		}
		// a return-slot patch stores below the frame pointer
		return modrm.displacement(bytes, i + 1) < 0;
	}

	/**
	 * The {@code MOV <jumpReg>, imm16} immediates that reach {@code jmp}: a backward walk over
	 * fall-through and jump predecessors, each path ending at its first write to the register
	 * (a path whose write is anything but such a {@code MOV} contributes nothing), at most
	 * {@value #FEEDER_WALK_LIMIT} instructions deep. Reaching definitions rather than a linear
	 * scan, so that the sibling dispatcher's constants above an unconditional jump never count,
	 * and a constant the other arm overwrites is not taken for a target.
	 */
	private static Set<Long> loadedImmediates(Program program, Instruction jmp, Register jumpReg) {
		Set<Long> immediates = new LinkedHashSet<>();
		Set<Address> visited = new HashSet<>();
		Deque<Instruction> frontier = new ArrayDeque<>(predecessors(program, jmp));
		for (int depth = 0; depth < FEEDER_WALK_LIMIT && !frontier.isEmpty(); depth++) {
			Deque<Instruction> next = new ArrayDeque<>();
			for (Instruction cur : frontier) {
				if (!visited.add(cur.getMinAddress())) {
					continue;
				}
				Long imm = loadedImmediate(cur, jumpReg);
				if (imm != null) {
					immediates.add(imm);
				}
				else if (!X86.writes(cur, jumpReg)) {
					next.addAll(predecessors(program, cur));
				}
			}
			frontier = next;
		}
		return immediates;
	}

	/** The instruction falling through to {@code instruction} and every jump landing on it. */
	private static List<Instruction> predecessors(Program program, Instruction instruction) {
		Listing listing = program.getListing();
		Address at = instruction.getMinAddress();
		List<Instruction> predecessors = new ArrayList<>();
		Instruction above = listing.getInstructionBefore(at);
		if (above != null && at.equals(above.getFallThrough())) {
			predecessors.add(above);
		}
		for (Reference reference : program.getReferenceManager().getReferencesTo(at)) {
			if (!reference.getReferenceType().isJump()) {
				continue;
			}
			Instruction source = listing.getInstructionAt(reference.getFromAddress());
			if (source != null) {
				predecessors.add(source);
			}
		}
		return predecessors;
	}

	/** The 16-bit immediate a {@code MOV <reg>, imm16} loads, or null if that is not this. */
	private static Long loadedImmediate(Instruction instruction, Register reg) {
		if (!"MOV".equals(instruction.getMnemonicString()) ||
			!reg.equals(X86.movDestination(instruction))) {
			return null;
		}
		return X86.movImmediate(instruction);
	}
}
