package ebbex.rtlink;

import static ebbex.rtlink.FillerIslands.FILLER_BYTE;
import static ebbex.rtlink.FillerIslands.FILLER_MIN_RUN;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair — disassemble the code gaps that flow never reaches.
 * <p>
 * A routine whose entry nothing references and whose bytes were cleared out from
 * under the pattern seeders is reachable by no pass at all: it is simply left as
 * undefined bytes between two runs of code. ROE2MAIN has both halves of one such
 * routine — the prologue at {@code 122e:51a0} ({@code PUSH BP; MOV BP,SP;
 * SUB SP,0x12}, byte-for-byte its sibling {@code FUN_122e_5177}) and its epilogue
 * at {@code 122e:51be} ({@code MOV SP,BP; POP BP; RETF}) — orphaned when
 * {@link EmulatedFloatPatcher} cleared the emulator-call window around them and
 * re-disassembled by flow, which reaches neither.
 * <p>
 * The gap is claimed only when its bytes account for themselves exactly: every
 * instruction decodes, and the run ends precisely on the boundary of the next
 * defined code unit — one byte over or under and this is not an in-phase run of
 * code. That alone would also swallow alignment padding, so the gap must in
 * addition <i>look like</i> a routine: it begins with a frame prologue, or it ends
 * with a return right where the next function begins (a stranded epilogue), or the
 * instruction above it falls straight into it. A run of one repeated byte is
 * padding by definition and is never claimed — which is what keeps this off the
 * zero-filled islands in the C library's data.
 * <p>
 * A longer gap is claimed only as a run of <b>whole routines</b>: the code above it
 * ends in a return, and the gap splits exactly into routines that
 * each end in a return or an unconditional jump, separated at most by the single
 * {@code NOP} that puts the next routine on an even address. Every branch that lands
 * inside the gap must land on an instruction of the decode. VICEROY's
 * {@code OVERLAY_30::03a40a} is the shape: three library routines linked in with
 * their module, 158 bytes that nothing calls, which no flow and no single-routine
 * rule reaches. Each routine becomes a function.
 */
final class CodeGaps {

	/** A gap shorter than this cannot be a routine, and a longer one is not a gap. */
	private static final int MIN_GAP_LENGTH = 2;
	private static final int MAX_GAP_LENGTH = 64;

	/** A run of whole routines may be longer; past this an undefined run is not a gap. */
	private static final int MAX_ROUTINE_RUN_LENGTH = 1024;

	/** The one-byte alignment pad MSC puts between routines to start the next on a word. */
	private static final byte NOP = (byte) 0x90;

	/** How far above a gap a jump back marks the gap as a detached block of that routine. */
	private static final int DETACHED_BLOCK_REACH = 0x100;

	private CodeGaps() {
	}

	/** Disassemble every recoverable gap; returns how many gaps or routines were filled. */
	static int fill(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		List<GapClaim> claims = new ArrayList<>();

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			monitor.checkCancelled();
			if (!block.isExecute() || !block.isInitialized()) {
				continue;
			}
			AddressIterator undefined = listing.getUndefinedRanges(
				new AddressSet(block.getStart(), block.getEnd()), true, monitor)
					.getAddresses(true);
			Address gapStart = null;
			Address previous = null;
			while (undefined.hasNext()) {
				monitor.checkCancelled();
				Address current = undefined.next();
				if (gapStart == null) {
					gapStart = current;
				}
				else if (previous != null && !current.equals(previous.next())) {
					claimGap(program, block, gapStart, previous, claims);
					gapStart = current;
				}
				previous = current;
			}
			if (gapStart != null && previous != null) {
				claimGap(program, block, gapStart, previous, claims);
			}
		}

		int filled = 0;
		for (GapClaim claim : claims) {
			monitor.checkCancelled();
			filled += claim.wholeRoutines() ? fillRoutines(program, claim, monitor)
					: fillGap(program, claim.starts().get(0), monitor);
		}
		return filled;
	}

	/**
	 * What the gap filler will disassemble in one gap: its start, or the start of every
	 * routine in it when it is a run of whole routines.
	 */
	private record GapClaim(AddressSet gap, List<Address> starts, boolean wholeRoutines) {
	}

	private static void claimGap(Program program, MemoryBlock block, Address start,
			Address end, List<GapClaim> claims) {
		GapClaim claim = recoverableGap(program, start, end);
		if (claim == null) {
			return;
		}
		List<Address> starts = claim.starts().stream().map(a -> inSegmentOf(block, a)).toList();
		claims.add(new GapClaim(claim.gap(), starts, claim.wholeRoutines()));
	}

	private static int fillGap(Program program, Address start, TaskMonitor monitor) {
		// Fall-through only: flow out of the gap is already disassembled, and a runaway
		// would be exactly the mis-phased decode this guards against.
		new DisassembleCommand(start, null, false).applyTo(program, monitor);
		if (program.getListing().getInstructionAt(start) == null) {
			return 0;
		}
		promoteIfPrologue(program, start, monitor);
		return 1;
	}

	private static int fillRoutines(Program program, GapClaim claim, TaskMonitor monitor) {
		// Named one by one: a claim this wide is worth being able to audit.
		Msg.info(RTLinkFlowRepairAnalyzer.class, String.format(
			"RTLink/Plus: Unreached run of %d routine(s) at %s", claim.starts().size(),
			claim.starts()));
		List<Address> decoded = new ArrayList<>();
		for (Address start : claim.starts()) {
			// Following flow, but only inside the gap: a routine's own branches are
			// what reach the code past its first unconditional jump.
			new DisassembleCommand(start, claim.gap(), true).applyTo(program, monitor);
			if (program.getListing().getInstructionAt(start) != null) {
				decoded.add(start);
			}
		}
		// Last entry first: of entries sharing a tail, the one that falls into it owns it,
		// and each earlier one then keeps only the bytes up to its jump into that tail.
		for (Address start : decoded.reversed()) {
			if (program.getFunctionManager().getFunctionContaining(start) == null) {
				new CreateFunctionCmd(start).applyTo(program, monitor);
			}
		}
		return decoded.size();
	}

	/**
	 * The same byte, addressed through the paragraph its block is based at.
	 * <p>
	 * Iterating a segmented space hands back addresses built from the flat offset, and
	 * {@code SegmentedAddressSpace} renders those through the 64KB <i>page</i> segment
	 * ({@code getDefaultSegmentFromFlat}) — so a gap in a block based at {@code 122e}
	 * arrives as {@code 1000:7480}. It is the same location and compares equal, but a
	 * function created at it is named for the page, and every label the repair leaves
	 * behind reads as if it belonged to a segment the code never runs in.
	 */
	private static Address inSegmentOf(MemoryBlock block, Address address) {
		if (!(block.getStart() instanceof SegmentedAddress start) ||
			!(address.getAddressSpace() instanceof SegmentedAddressSpace space) ||
			!address.getAddressSpace().equals(start.getAddressSpace())) {
			return address;
		}
		long offset = address.getOffset() - (long) start.getSegment() * 16;
		if (offset < 0 || offset > 0xffffL) {
			return address; // not addressable from this block's paragraph
		}
		return space.getAddress(start.getSegment(), (int) offset);
	}

	/**
	 * What to claim of the undefined run {@code [start, end]}, or null when it is padding
	 * or data rather than code the analysis missed. It must be in phase (it decodes
	 * exactly onto the next code unit) and shaped like code: a short gap with a
	 * prologue, a stranded epilogue or a fall-through into it, or a run of whole
	 * routines.
	 */
	private static GapClaim recoverableGap(Program program, Address start, Address end) {
		long length = end.subtract(start) + 1;
		if (length < MIN_GAP_LENGTH || length > MAX_ROUTINE_RUN_LENGTH) {
			return null;
		}
		byte[] bytes = new byte[(int) length];
		try {
			if (program.getMemory().getBytes(start, bytes) != bytes.length) {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		int pad = leadingZeros(bytes);
		if (pad > 0 && pad < FILLER_MIN_RUN && pad < length && closedAbove(program, start)) {
			// Zero padding or a zeroed variable between a routine's last jump and the next
			// routine (RTLink's rtcommon, 275d:07cf): left alone, and what follows judged
			// as a gap of its own.
			return recoverableGap(program, start.add(pad), end);
		}
		if (isRepeatedByte(bytes) || containsFillerRun(bytes)) {
			// Padding, not code — and a gap that merely *contains* a fill run is no
			// better: once an island has been cleared, the undefined bytes around it
			// may no longer be uniform, and without this a gap straddling the island's
			// edge could decode in phase and put the junk straight back.
			return null;
		}
		List<PseudoInstruction> decoded = decodeExactly(program, start, length);
		if (decoded == null) {
			return null;
		}

		AddressSet gap = new AddressSet(start, end);
		// Below a routine exit, whole routines first: each then becomes a function, where
		// the single-start claim would decode only the first one and name none
		// (RTLink's $$RTL_PRELOAD and $$RTL_SHELL_EVENT, 275d:07d5 and 275d:07df).
		List<Address> routines = splitIntoRoutines(program, gap, decoded);
		if (!routines.isEmpty()) {
			return new GapClaim(gap, routines, true);
		}
		Instruction last = decoded.get(decoded.size() - 1);
		if (length <= MAX_GAP_LENGTH && (startsWithPrologue(bytes) ||
			isStrandedEpilogue(program, end, last) || fallsInto(program, start))) {
			return new GapClaim(gap, List.of(start), false);
		}
		return null;
	}

	/**
	 * A near {@code JMP} between routines: a slot of a table of jumps that only a computed
	 * jump reaches (VICEROY {@code 210d:2016}, {@code JMP 2121} between two others), not a
	 * routine. Its target is decoded anyway; the slot itself is not claimed.
	 */
	private static boolean isJumpSlot(PseudoInstruction instruction) {
		FlowType flowType = instruction.getFlowType();
		return flowType.isJump() && !flowType.hasFallthrough() &&
			!"JMPF".equals(instruction.getMnemonicString());
	}

	/**
	 * The instructions {@code [start, start + length)} decodes to, or null unless every
	 * byte decodes and the last instruction ends exactly at the end of the run.
	 */
	private static List<PseudoInstruction> decodeExactly(Program program, Address start,
			long length) {
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		List<PseudoInstruction> decoded = new ArrayList<>();
		Address at = start;
		long consumed = 0;
		while (consumed < length) {
			PseudoInstruction instruction = CodeSeeds.decode(pseudo, at);
			if (instruction == null) {
				return null; // does not decode: not code
			}
			if (flowsNowhere(program, instruction)) {
				// A decode that jumps somewhere that does not exist is not code this
				// pass may claim. The shape that matters here is RTLink's own
				// dispatch stub — CALLF dispatcher; JMPF 0000:offset, whose segment is
				// deliberately left unrelocated until the overlay manager patches it at
				// runtime. Those are RTLinkOverlayAnalyzer's to resolve into thunks;
				// decoding them here produces a real instruction and a "flow into
				// non-existing memory" error nobody sweeps.
				return null;
			}
			decoded.add(instruction);
			consumed += instruction.getLength();
			at = at.add(instruction.getLength());
		}
		// Out of phase when the run overshoots the code that follows.
		return consumed == length ? decoded : null;
	}

	/**
	 * The entry of every routine in {@code gap}, or an empty list unless the gap is a run
	 * of whole routines: the code above it cannot run into it (see {@link #closedAbove}),
	 * every branch that lands in the gap lands on an instruction of the decode, and the gap
	 * splits exactly into routines, with at most one {@code NOP} padding a routine onto an
	 * even address. No routine may start on a zero byte.
	 * <p>
	 * A routine ends at an instruction without a fall-through (a return or an
	 * unconditional jump) that none of its own jumps reaches past. One that some jump
	 * does reach past is internal ({@code JMP} over an {@code else}), and the code after
	 * it must then be a target of one of the routine's jumps — or a further entry that
	 * jumps or falls straight into one of them, as hand-written runtimes share one body
	 * between entries that differ in a register they load first. A run that merely falls
	 * into the function below the gap is not claimed: short data in front of a routine
	 * decodes that way as readily as an entry does.
	 */
	private static List<Address> splitIntoRoutines(Program program, AddressSet gap,
			List<PseudoInstruction> decoded) {
		if (!closedAbove(program, gap.getMinAddress())) {
			return List.of();
		}
		Set<Address> boundaries = new LinkedHashSet<>();
		decoded.forEach(instruction -> boundaries.add(instruction.getAddress()));

		List<Address> starts = new ArrayList<>();
		Set<Address> targets = new LinkedHashSet<>(); // the current routine's jump targets
		Address furthest = null;
		int entry = -1; // the current routine's first entry, as an index into decoded
		boolean betweenRoutines = true;
		boolean padded = false;
		boolean unreached = false; // the previous instruction has no fall-through
		for (int index = 0; index < decoded.size(); index++) {
			PseudoInstruction instruction = decoded.get(index);
			Address at = instruction.getAddress();
			if (betweenRoutines) {
				if (isAlignmentPad(instruction) && !padded) {
					padded = true;
					continue;
				}
				if (startsOnZero(instruction)) {
					// ADD [BX+SI],AL: zeroed data that happens to decode, such as a
					// saved interrupt vector or a CS variable, never a routine entry.
					return List.of();
				}
				if (isJumpSlot(instruction)) {
					continue; // still between routines
				}
				starts.add(at);
				targets.clear();
				furthest = null;
				entry = index;
				betweenRoutines = false;
			}
			else if (unreached && !targets.contains(at)) {
				// Nothing in this routine reaches it, so it is either a further entry
				// into the routine's tail (PUSH DX ; MOV DX,0x2000 ; JMP tail, VICEROY
				// 210d:1df7, parallel to the first entry PUSH DX ; MOV DX,0x0800) or not
				// code at all — dead code, or data, after an inner jump. Only the first is
				// claimed.
				if (!parallelEntry(decoded, entry, index) || !joinsTail(decoded, index, targets)) {
					return List.of();
				}
				starts.add(at);
			}
			FlowType flowType = instruction.getFlowType();
			for (Address flow : instruction.getFlows()) {
				if (!gap.contains(flow)) {
					if (flowType.isJump() && backIntoRoutineAbove(program, gap, flow)) {
						// A block that jumps back into the middle of a routine is a
						// detached part of it (VICEROY 210d:05f0, below a far jump, jumps
						// back into the INT 21h hook), not a routine of its own.
						return List.of();
					}
					continue;
				}
				if (!boundaries.contains(flow)) {
					return List.of(); // a branch into the middle of an instruction
				}
				if (flowType.isJump()) {
					targets.add(flow);
					furthest = furthest == null || flow.compareTo(furthest) > 0 ? flow : furthest;
				}
			}
			unreached = !flowType.hasFallthrough();
			if (unreached && (furthest == null || furthest.compareTo(at) <= 0)) {
				betweenRoutines = true;
				padded = false;
			}
		}
		return betweenRoutines ? starts : List.of();
	}

	/**
	 * True when {@code target} lies just above the gap ({@value #DETACHED_BLOCK_REACH} bytes
	 * at most) inside a function's body but not at its entry: the gap is then a detached block
	 * of that routine. A jump into the middle of a routine further away is a tail jump into a
	 * shared exit, which library and runtime routines make routinely (getchar,
	 * {@code 1d1d:077e}).
	 */
	private static boolean backIntoRoutineAbove(Program program, AddressSet gap, Address target) {
		Address start = gap.getMinAddress();
		if (target.compareTo(start) >= 0 || start.subtract(target) > DETACHED_BLOCK_REACH) {
			return false;
		}
		Function function = program.getFunctionManager().getFunctionContaining(target);
		return function != null && !function.getEntryPoint().equals(target);
	}

	/**
	 * True when the first two instructions at {@code decoded[index]} have the mnemonics and
	 * register operands of the two at {@code decoded[entry]}: entries into one shared body
	 * that differ only in the constant they load ({@code PUSH DX ; MOV DX,imm}).
	 */
	private static boolean parallelEntry(List<PseudoInstruction> decoded, int entry, int index) {
		if (entry < 0 || index + 1 >= decoded.size()) {
			return false;
		}
		for (int i = 0; i < 2; i++) {
			PseudoInstruction first = decoded.get(entry + i);
			PseudoInstruction other = decoded.get(index + i);
			if (!first.getMnemonicString().equals(other.getMnemonicString()) ||
				first.getNumOperands() != other.getNumOperands()) {
				return false;
			}
			for (int op = 0; op < first.getNumOperands(); op++) {
				if (!Objects.equals(first.getRegister(op), other.getRegister(op))) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * True when the straight-line run from {@code decoded[index]} reaches one of
	 * {@code targets} — by a jump or by falling into it — before it stops. That is what makes
	 * code below a routine's unconditional jump another entry into the same routine.
	 */
	private static boolean joinsTail(List<PseudoInstruction> decoded, int index,
			Set<Address> targets) {
		for (int i = index; i < decoded.size(); i++) {
			PseudoInstruction instruction = decoded.get(i);
			if (i > index && targets.contains(instruction.getAddress())) {
				return true; // fell into it
			}
			for (Address flow : instruction.getFlows()) {
				if (targets.contains(flow)) {
					return true;
				}
			}
			if (!instruction.getFlowType().hasFallthrough() ||
				instruction.getFlowType().isConditional()) {
				return false;
			}
		}
		return false;
	}

	/**
	 * True when the routine above {@code start} has certainly ended there: its last
	 * instruction leaves it — a return, a far jump, or a jump to another function's entry (a
	 * tail call: VICEROY's {@code JMP rtlink_error_vm_stack_underflow} at {@code 210d:2b7a})
	 * — possibly followed by fewer than {@value FillerIslands#FILLER_MIN_RUN} zero bytes of
	 * padding. A near jump within the routine does not: what follows it may be a case of an
	 * unresolved switch, code of that same routine that only a computed jump reaches.
	 */
	private static boolean closedAbove(Program program, Address start) {
		Address before = start.previous();
		try {
			for (int i = 0; i < FILLER_MIN_RUN && before != null; i++) {
				Instruction above = program.getListing().getInstructionContaining(before);
				if (above != null) {
					return leavesRoutine(program, above);
				}
				if (program.getMemory().getByte(before) != FILLER_BYTE) {
					return false;
				}
				before = before.previous();
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		return false;
	}

	private static boolean leavesRoutine(Program program, Instruction instruction) {
		FlowType flowType = instruction.getFlowType();
		if (flowType.hasFallthrough()) {
			return false;
		}
		if (flowType.isTerminal() && !flowType.isJump()) {
			// RET, RETF, IRET — or a jump the Shared Return Calls analyzer made a tail call
			return true;
		}
		if (!flowType.isJump()) {
			return false;
		}
		if ("JMPF".equals(instruction.getMnemonicString())) {
			return true;
		}
		Address[] flows = instruction.getFlows();
		if (flows.length == 0) {
			return false; // an unresolved near jump: a switch, not an exit
		}
		for (Address flow : flows) {
			if (program.getFunctionManager().getFunctionAt(flow) == null) {
				return false;
			}
		}
		return true;
	}

	private static int leadingZeros(byte[] bytes) {
		int zeros = 0;
		while (zeros < bytes.length && bytes[zeros] == FILLER_BYTE) {
			zeros++;
		}
		return zeros;
	}

	private static boolean startsOnZero(PseudoInstruction instruction) {
		try {
			return instruction.getByte(0) == 0;
		}
		catch (MemoryAccessException e) {
			return true;
		}
	}

	/** A one-byte {@code NOP} at an odd address: it puts what follows on a word. */
	private static boolean isAlignmentPad(PseudoInstruction instruction) {
		return instruction.getLength() == 1 && (instruction.getAddress().getOffset() & 1) == 1 &&
			isNop(instruction);
	}

	private static boolean isNop(PseudoInstruction instruction) {
		try {
			return instruction.getByte(0) == NOP;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/** True if any flow out of {@code instruction} lands outside mapped memory. */
	private static boolean flowsNowhere(Program program, PseudoInstruction instruction) {
		for (Address flow : instruction.getFlows()) {
			if (!program.getMemory().contains(flow)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A frame prologue: {@code PUSH BP; MOV BP,SP}, or {@code ENTER n,0}, which MSC emits
	 * instead for 186+ targets (VICEROY {@code OVERLAY_30::03a40a}).
	 */
	private static boolean startsWithPrologue(byte[] bytes) {
		boolean pushBp = bytes.length >= 3 && bytes[0] == 0x55 && bytes[1] == (byte) 0x8b &&
			bytes[2] == (byte) 0xec;
		boolean enter = bytes.length >= 4 && bytes[0] == (byte) 0xc8 && bytes[3] == 0;
		return pushBp || enter;
	}

	/**
	 * True when the gap ends in a return and the next code unit starts a function —
	 * the epilogue of the routine above it, stranded when nothing flowed into it.
	 */
	private static boolean isStrandedEpilogue(Program program, Address end,
			Instruction last) {
		if (last == null || !last.getFlowType().isTerminal()) {
			return false;
		}
		Address next = end.next();
		return next != null && program.getFunctionManager().getFunctionAt(next) != null;
	}

	/** True when the instruction above the gap falls straight into it. */
	private static boolean fallsInto(Program program, Address start) {
		Address before = start.previous();
		if (before == null) {
			return false;
		}
		Instruction previous = program.getListing().getInstructionContaining(before);
		return previous != null && start.equals(previous.getFallThrough());
	}

	/** True when {@code bytes} contains a fill run — {@value FillerIslands#FILLER_MIN_RUN} zeros. */
	private static boolean containsFillerRun(byte[] bytes) {
		int run = 0;
		for (byte value : bytes) {
			run = value == FILLER_BYTE ? run + 1 : 0;
			if (run >= FILLER_MIN_RUN) {
				return true;
			}
		}
		return false;
	}

	private static boolean isRepeatedByte(byte[] bytes) {
		for (int i = 1; i < bytes.length; i++) {
			if (bytes[i] != bytes[0]) {
				return false;
			}
		}
		return true;
	}

	/** Make a recovered prologue a function; its callers, if any, are indirect. */
	private static void promoteIfPrologue(Program program, Address start,
			TaskMonitor monitor) {
		if (program.getFunctionManager().getFunctionContaining(start) != null) {
			return;
		}
		try {
			byte[] bytes = new byte[4]; // ENTER n,0 is four bytes
			if (program.getMemory().getBytes(start, bytes) == bytes.length &&
				startsWithPrologue(bytes)) {
				new CreateFunctionCmd(start).applyTo(program, monitor);
			}
		}
		catch (MemoryAccessException e) {
			// leave it as code without a function
		}
	}
}
