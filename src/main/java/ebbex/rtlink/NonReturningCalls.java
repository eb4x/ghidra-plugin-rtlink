package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair — calls that cannot return. A call to a routine that terminates the
 * program cannot return, so the bytes after it are not code.
 * <p>
 * The corpus shape is the vendor driver's handler-registration routine: its table
 * is full, so it aborts — {@code PUSH CS; CALL abort}, where {@code abort} sets up
 * a message and tail-jumps (through the vector {@link FarVectorFlows} has just
 * followed) into a handler ending in {@code MOV AX,0x4C01; INT 21h}. DOS
 * function {@code 4Ch} does not come back. What sits after that call is the
 * handler table itself — sixty-odd zero bytes the disassembler decodes until its
 * repeated-byte limiter gives up, leaving the one benign-looking ERROR bookmark
 * each binary used to carry.
 * <p>
 * Non-return is established, never guessed: a function qualifies only if it
 * contains no return instruction at all, and every one of its terminal
 * instructions is either the DOS-exit idiom or a jump into another function that
 * qualifies (a fixpoint, so a tail-jump chain is followed). Everything else is
 * assumed to return.
 */
final class NonReturningCalls {

	/** How far back from an {@code INT 21h} to look for the AH it was given. */
	private static final int DOS_EXIT_SCAN_LIMIT = 4;

	/** Instructions to follow when measuring the junk behind a non-returning call. */
	private static final int MAX_JUNK_RUN = 256;

	private NonReturningCalls() {
	}

	/** Mark the DOS exits, then seal every call to a routine that ends in one; returns the count. */
	static int seal(Program program, TaskMonitor monitor) throws CancelledException {
		markDosExits(program, monitor);
		Set<Function> terminating = terminatingFunctions(program, monitor);
		if (terminating.isEmpty()) {
			return 0;
		}
		Listing listing = program.getListing();
		int sealed = 0;

		for (Function function : terminating) {
			monitor.checkCancelled();
			if (!function.hasNoReturn()) {
				function.setNoReturn(true);
			}
			// Through its thunks too: a thunk delegates its no-return to the routine. And a
			// copy, since the clear below removes references.
			for (Instruction collected : CodeEvidence.callsTo(program, function)) {
				monitor.checkCancelled();
				// Re-fetched: clearing junk behind an earlier call may have taken this one.
				Instruction call = listing.getInstructionAt(collected.getMinAddress());
				if (call == null || !call.getFlowType().isCall() ||
					call.getFlowOverride() == FlowOverride.CALL_RETURN ||
					call.getFallThrough() == null) {
					continue;
				}
				Address fallThrough = call.getFallThrough();
				AddressSetView junk = fallThroughRun(program, fallThrough);
				call.setFlowOverride(FlowOverride.CALL_RETURN);

				// Clear the junk outright rather than through ClearFlowAndRepairCmd:
				// that command spares any block something references, and this junk is
				// referenced — the bytes behind the driver's abort are its handler
				// table, and constant propagation has (rightly) resolved the routine's
				// own CS:[BX] loads onto them. Those data references are the very
				// evidence that the bytes are not code. The call cannot return here, so
				// nothing decoded from here is an instruction; the walk stops at the
				// first address anything actually flows to, so real code is never taken.
				if (!junk.isEmpty()) {
					listing.clearCodeUnits(junk.getMinAddress(), junk.getMaxAddress(),
						false);
					ClearFlowAndRepairCmd.clearBadBookmarks(program,
						ErrorMarks.markedRange(junk), monitor);
				}
				sealed++;
			}
		}
		return sealed;
	}

	/**
	 * Tell Ghidra what DOS already knows: {@code INT 21h} with {@code AH = 4Ch}
	 * terminates the process, so nothing follows it.
	 * <p>
	 * Left unmarked, the exit is just another instruction with a fall-through, and
	 * whatever bytes come after it are pulled into the routine that exits. That is how
	 * ROE2MAIN's fatal handler came to swallow the routine below it — a body of 123
	 * bytes where VICEROY's, whose successor was already a function, is 83 — and the
	 * stray {@code RETF} it thereby contained was enough to make the handler look like
	 * it returns. Overriding the flow to a terminator fixes the bodies, and with them
	 * everything downstream that reasons about what a routine does at its end.
	 */
	private static void markDosExits(Program program, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Instruction> exits = new ArrayList<>();
		for (Instruction instruction : listing.getInstructions(true)) {
			monitor.checkCancelled();
			if (instruction.getFlowOverride() == FlowOverride.NONE &&
				isDosExit(program, instruction)) {
				exits.add(instruction);
			}
		}
		for (Instruction exit : exits) {
			monitor.checkCancelled();
			Address after = exit.getMaxAddress().next();
			exit.setFlowOverride(FlowOverride.RETURN);
			Function owner =
				program.getFunctionManager().getFunctionContaining(exit.getMinAddress());
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(program,
					listing.getInstructionAt(owner.getEntryPoint()), monitor);
			}
			if (after != null) {
				dropFallThroughMarks(program, after);
			}
		}
	}

	/**
	 * Drop the disassembler's ERROR marks at {@code after}, the address an exit used to fall
	 * into, once nothing flows there any more. Where the bytes after the exit are already
	 * data when disassembly reaches them — the smoke sample's abort vector, typed as a
	 * pointer as soon as the indirect {@code JMPF CS:[vector]} above reads it (GP-7349) — the
	 * fall-through left "Failed to disassemble … due to conflicting data" there, which the
	 * exit, now terminal, no longer explains.
	 */
	private static void dropFallThroughMarks(Program program, Address after) {
		if (CodeEvidence.fallingInto(program, after) != null) {
			return;
		}
		ErrorMarks.removeUnreached(program, after);
	}

	/**
	 * The run of instructions the disassembler decoded straight through from
	 * {@code start}, plus the byte after it — where a run it abandoned (a long stretch
	 * of one repeated byte, say) leaves its ERROR mark.
	 * <p>
	 * The first instruction is held to a weaker test than the rest: a function at the
	 * fall-through is no evidence by itself, since analysis makes an orphan of the junk
	 * behind a call that never returns. Anything else — a flow reference, an external entry,
	 * a name someone gave it — means the run is empty and nothing is cleared.
	 */
	private static AddressSetView fallThroughRun(Program program, Address start) {
		AddressSet run = new AddressSet();
		Listing listing = program.getListing();
		Address at = start;
		for (int i = 0; i < MAX_JUNK_RUN && at != null; i++) {
			Instruction instruction = listing.getInstructionAt(at);
			if (instruction == null) {
				break;
			}
			boolean evidenced = at.equals(start)
					? isEvidencedBesidesFunction(program, at)
					: CodeEvidence.isEvidenced(program, instruction);
			if (evidenced) {
				break; // something really flows here: the run has left the junk
			}
			run.add(instruction.getMinAddress(), instruction.getMaxAddress());
			at = instruction.getFallThrough();
		}
		return run;
	}

	/** {@link CodeEvidence#isEvidenced} without its function-entry clause. */
	private static boolean isEvidencedBesidesFunction(Program program, Address entry) {
		if (CodeEvidence.hasFlowReferenceTo(program, entry) ||
			program.getSymbolTable().isExternalEntryPoint(entry)) {
			return true;
		}
		Symbol primary = program.getSymbolTable().getPrimarySymbol(entry);
		return primary != null && primary.getSource() != SourceType.DEFAULT;
	}

	/**
	 * The functions that never return: those with no return instruction whose every
	 * terminal path exits through DOS {@code INT 21h/4Ch}, directly or by tail-jumping
	 * into another such function.
	 */
	private static Set<Function> terminatingFunctions(Program program, TaskMonitor monitor)
			throws CancelledException {
		Set<Function> terminating = new LinkedHashSet<>();
		boolean grew = true;
		while (grew) {
			grew = false;
			for (Function function : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				if (terminating.contains(function) || function.isThunk()) {
					continue;
				}
				if (isTerminating(program, function, terminating)) {
					terminating.add(function);
					grew = true;
				}
			}
		}
		return terminating;
	}

	/**
	 * True when {@code function} has no return instruction and each of its terminal
	 * instructions either is the DOS exit idiom or jumps into a function already known
	 * to terminate.
	 * <p>
	 * That verdict is only as good as the body is complete, so every way out of the body
	 * is accounted for: a fall-through or a conditional branch that leaves it — a body cut
	 * short by a disassembly conflict, or a branch to a shared return in another routine —
	 * is a path this test cannot see the end of, and the routine is assumed to return.
	 */
	private static boolean isTerminating(Program program, Function function,
			Set<Function> terminating) {
		Listing listing = program.getListing();
		AddressSetView body = function.getBody();
		InstructionIterator instructions = listing.getInstructions(body, true);
		boolean sawTerminalPath = false;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			FlowType flow = instruction.getFlowType();
			if (isDosExit(program, instruction)) {
				sawTerminalPath = true;
				continue;
			}
			// An unconditional jump is a tail call, and it is recognized by the
			// instruction rather than by its flow type: once Ghidra's shared-return pass
			// has been over a tail jump it carries a CALL flow override, and the flow
			// type then describes what Ghidra made of it, not what the code does.
			boolean tailCall = X86.isUnconditionalJump(instruction);
			if (flow.isTerminal() && !tailCall) {
				return false; // a return: it comes back
			}
			if (!tailCall) {
				if (leavesBody(program, instruction, body, terminating)) {
					return false;
				}
				continue; // an ordinary call or a branch within the routine: not an exit
			}
			// A tail call terminates only if what it lands in does. Destinations come
			// from the references, not from getFlows(): the same override that hides the
			// jump's nature also empties its flow list.
			Set<Address> destinations = jumpDestinations(program, instruction);
			if (destinations.isEmpty()) {
				return false; // where it goes is unknown: assume it comes back
			}
			for (Address destination : destinations) {
				if (function.getBody().contains(destination)) {
					continue; // a jump inside the routine — a loop, not an exit
				}
				Function target = program.getFunctionManager().getFunctionAt(destination);
				if (target == null || !terminating.contains(target)) {
					return false;
				}
				sawTerminalPath = true;
			}
		}
		return sawTerminalPath;
	}

	/**
	 * True if {@code instruction}, which is neither a return nor a tail jump, can continue
	 * outside {@code body}: its fall-through lands outside it, or a conditional branch goes
	 * somewhere other than the body or a function known to terminate.
	 */
	private static boolean leavesBody(Program program, Instruction instruction,
			AddressSetView body, Set<Function> terminating) {
		Address fallThrough = instruction.getFallThrough();
		if (fallThrough != null && !body.contains(fallThrough)) {
			return true;
		}
		if (!instruction.getFlowType().isConditional() || !instruction.getFlowType().isJump()) {
			return false;
		}
		for (Address destination : instruction.getFlows()) {
			if (body.contains(destination)) {
				continue;
			}
			Function target = program.getFunctionManager().getFunctionAt(destination);
			if (target == null || !terminating.contains(target)) {
				return true;
			}
		}
		return false;
	}

	/** Where an unconditional jump goes, however its reference happens to be typed. */
	private static Set<Address> jumpDestinations(Program program, Instruction instruction) {
		Set<Address> destinations = new LinkedHashSet<>();
		for (Address flow : instruction.getFlows()) {
			destinations.add(flow);
		}
		for (Reference reference : program.getReferenceManager()
				.getReferencesFrom(instruction.getMinAddress())) {
			RefType type = reference.getReferenceType();
			if (type.isCall() || type.isJump()) {
				destinations.add(reference.getToAddress());
			}
		}
		return destinations;
	}

	/**
	 * True for {@code INT 21h} whose {@code AH} is provably {@code 4Ch} — the DOS
	 * terminate-process call, loaded as {@code MOV AH,4Ch} ({@code B4 4C}) or
	 * {@code MOV AX,4Cxx} ({@code B8 xx 4C}).
	 * <p>
	 * A wrong verdict is never revisited and seals every caller's fall-through, so this
	 * proves rather than guesses. It walks back along the fall-through chain only — never
	 * into the routine above — and gives up where another path joins (a flow reference to
	 * any instruction after the load) or where anything else writes {@code AH}, whatever the
	 * form ({@code MOV AH,[mem]}, {@code POP AX}, {@code XOR AX,AX}). A write to {@code AL}
	 * alone leaves {@code AH} intact and is stepped over. The test is on the bytes, not on
	 * the operands Ghidra happens to display.
	 */
	private static boolean isDosExit(Program program, Instruction instruction) {
		if (!startsWith(X86.bytes(instruction), 0xcd, 0x21)) {
			return false;
		}
		Register ah = program.getRegister("AH");
		Instruction at = instruction;
		for (int i = 0; i < DOS_EXIT_SCAN_LIMIT; i++) {
			if (CodeEvidence.hasFlowReferenceTo(program, at.getMinAddress())) {
				return false; // another path joins here, with an AH of its own
			}
			Address from = at.getFallFrom();
			Instruction previous = from == null ? null : program.getListing().getInstructionAt(from);
			if (previous == null) {
				return false;
			}
			if (X86.writes(previous, ah)) {
				byte[] bytes = X86.bytes(previous);
				return startsWith(bytes, 0xb4, 0x4c) ||
					(startsWith(bytes, 0xb8) && bytes.length > 2 && bytes[2] == 0x4c);
			}
			at = previous;
		}
		return false;
	}

	/** True if {@code bytes} start with {@code expected}. */
	private static boolean startsWith(byte[] bytes, int... expected) {
		if (bytes.length < expected.length) {
			return false;
		}
		for (int i = 0; i < expected.length; i++) {
			if ((bytes[i] & 0xff) != expected[i]) {
				return false;
			}
		}
		return true;
	}
}
