package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair — no-return flags that the disassembled body contradicts.
 * <p>
 * Ghidra's "Non-Returning Functions - Discovered" pass decides from the call sites, never from
 * the callee: enough callers whose fall-through looks wrong and the callee is marked
 * non-returning, every call to it gets a {@code CALL_RETURN} override, and each caller is cut
 * off at the call. It runs right behind {@link EmulatedFloatAnalyzer}, while the float code
 * around those calls is still settling, so the evidence it counts can be the emulator calls'
 * own wreckage. ROE2MAIN's {@code __ftol} at {@code 122e:530c} ({@code FISTP} under a
 * truncating control word, then {@code RETF}) is marked that way: its 126 callers each stop at
 * the {@code CALLF}, and the code after it becomes a function of its own that nothing calls
 * ({@code OVERLAY_084::0465de}, below the call in {@code OVL084_2545}).
 * <p>
 * Only the discovery pass's verdicts are revisited, recognised by the bookmark it leaves; a
 * flag set by name ({@code exit}), by hand or by {@link NonReturningCalls} stays. The verdict
 * is overturned only when the body reaches a return: the body is computed by flow from the
 * entry, so a return in it is a path that comes back. Runs after {@link NonReturningCalls}
 * has marked the DOS exits, which is what keeps a fatal handler from owning the routine below
 * it, and that routine's return.
 */
final class StaleNoReturns {

	/** The bookmark category the discovery pass marks each verdict with. */
	private static final String DISCOVERED = "Non-Returning Function";

	/** How far down the straight line after a call to look for junk blocking it. */
	private static final int STRAIGHT_LINE_LIMIT = 256;

	/** How many instructions above a call to look for the function it belongs in. */
	private static final int OWNER_WALK_LIMIT = 512;

	private StaleNoReturns() {
	}

	/**
	 * Clear every contradicted verdict and restore its callers; returns how many were cleared.
	 * <p>
	 * The restore is all or nothing as far as analysis can see. Disassembly over a wide enough
	 * range starts auto-analysis on the spot ({@code DisassembleCommand.analyzeIfNeeded}), and
	 * so does Ghidra's flow repair; the discovery pass, finding three callers still cut — an
	 * orphan, undefined bytes or junk after the call — flags the routine again and clears the
	 * fall-throughs already restored. So everything is settled with analysis off — every call,
	 * every orphan, the junk that blocks a fall-through, the emulator calls the re-decoded code
	 * exposes — and only then is the new code handed to analysis.
	 */
	static int clear(Program program, TaskMonitor monitor) throws CancelledException {
		List<Function> stale = contradicted(program, monitor);
		if (stale.isEmpty()) {
			return 0;
		}
		BookmarkManager bookmarks = program.getBookmarkManager();
		for (Function function : stale) {
			monitor.checkCancelled();
			function.setNoReturn(false);
			Bookmark mark =
				bookmarks.getBookmark(function.getEntryPoint(), BookmarkType.ANALYSIS, DISCOVERED);
			if (mark != null) {
				bookmarks.removeBookmark(mark);
			}
		}
		// To a fixpoint: decoding a cleared fall-through decodes the calls in it, whose own
		// fall-throughs were cut in turn.
		AddressSet decoded = new AddressSet();
		boolean changed;
		do {
			monitor.checkCancelled();
			changed = false;
			AddressSet round = new AddressSet();
			for (Instruction collected : calls(program, stale)) {
				monitor.checkCancelled();
				// Re-fetched: clearing junk for an earlier call may have taken this one, if it
				// was itself junk — a deleted instruction still answers, from whatever is there.
				Instruction call = program.getListing().getInstructionAt(collected.getMinAddress());
				if (call == null || !call.getFlowType().isCall()) {
					continue;
				}
				if (call.getFlowOverride() == FlowOverride.CALL_RETURN) {
					call.setFlowOverride(FlowOverride.NONE);
					changed = true;
				}
				changed |= reopenFallThrough(program, call, round, monitor);
			}
			decoded.add(round);
			if (RTLinkProgram.isFloatEmulated(program)) {
				AddressSetView rewritten = rewriteEmulatorCalls(program, round, monitor);
				decoded.add(rewritten);
				changed |= !rewritten.isEmpty();
			}
		}
		while (changed);

		// Only once every orphan is gone: a body grown earlier would stop at the next one.
		for (Function owner : owners(program, calls(program, stale))) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, owner, monitor);
		}
		if (!decoded.isEmpty() && AutoAnalysisManager.hasAutoAnalysisManager(program)) {
			AutoAnalysisManager.getAnalysisManager(program).codeDefined(decoded);
		}
		return stale.size();
	}

	/** The functions the discovery pass marked non-returning whose bodies return. */
	private static List<Function> contradicted(Program program, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager functions = program.getFunctionManager();
		List<Function> stale = new ArrayList<>();
		var marks = program.getBookmarkManager().getBookmarksIterator(BookmarkType.ANALYSIS);
		while (marks.hasNext()) {
			monitor.checkCancelled();
			Bookmark mark = marks.next();
			if (!DISCOVERED.equals(mark.getCategory())) {
				continue;
			}
			Function function = functions.getFunctionAt(mark.getAddress());
			if (function == null || !function.hasNoReturn() || isCommitted(function)) {
				continue;
			}
			if (bodyReturns(function)) {
				stale.add(function);
			}
		}
		return stale;
	}

	/**
	 * True if someone has committed to {@code function}'s signature, by hand or by import: the
	 * no-return flag is then theirs, whatever bookmark the discovery pass left before.
	 */
	private static boolean isCommitted(Function function) {
		return function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS);
	}

	/**
	 * Returns true if {@code func}'s disassembled body contains a return instruction —
	 * proof that a no-return flag on it is wrong.
	 */
	static boolean bodyReturns(Function func) {
		InstructionIterator it =
			func.getProgram().getListing().getInstructions(func.getBody(), true);
		while (it.hasNext()) {
			if (it.next().getFlowType() == RefType.TERMINATOR) {
				return true;
			}
		}
		return false;
	}

	/** Every call to the {@code functions}, directly or through their thunks. */
	private static List<Instruction> calls(Program program, List<Function> functions) {
		List<Instruction> calls = new ArrayList<>();
		for (Function function : functions) {
			calls.addAll(CodeEvidence.callsTo(program, function));
		}
		return calls;
	}

	/**
	 * Make the code after {@code call} the caller's again: disassemble it, without analysis, if
	 * the discovery pass's repair cleared it, and remove the function auto-analysis made of it
	 * once it hung from nothing — one with a default name that nothing references. Returns
	 * true if anything changed; what was decoded is added to {@code decoded}.
	 */
	private static boolean reopenFallThrough(Program program, Instruction call,
			AddressSet decoded, TaskMonitor monitor) throws CancelledException {
		Address fallThrough = call.getFallThrough();
		if (fallThrough == null) {
			return false;
		}
		if (program.getListing().getInstructionAt(fallThrough) == null) {
			DisassembleCommand disassemble = new DisassembleCommand(fallThrough, null, true);
			disassemble.enableCodeAnalysis(false);
			disassemble.applyTo(program, monitor);
			AddressSetView added = disassemble.getDisassembledAddressSet();
			decoded.add(added);
			return unblockStraightLine(program, fallThrough, decoded, monitor) || !added.isEmpty();
		}
		if (unblockStraightLine(program, fallThrough, decoded, monitor)) {
			return true;
		}
		Function orphan = program.getFunctionManager().getFunctionAt(fallThrough);
		if (orphan == null) {
			return false;
		}
		if (!isOrphan(program, orphan)) {
			return false;
		}
		return program.getFunctionManager().removeFunction(fallThrough);
	}

	/**
	 * True if {@code function} is what analysis leaves behind a cut call and nothing more: a
	 * default name, no references, no comment and no committed signature. A function someone
	 * split off there by hand carries a default name too, and is told apart only if they left
	 * something else on it.
	 */
	private static boolean isOrphan(Program program, Function function) {
		Symbol symbol = function.getSymbol();
		Address entry = function.getEntryPoint();
		return symbol.getSource() == SourceType.DEFAULT && !symbol.isExternalEntryPoint() &&
			program.getReferenceManager().getReferenceCountTo(entry) == 0 &&
			function.getComment() == null && function.getRepeatableComment() == null &&
			!isCommitted(function);
	}

	/**
	 * Rewrite the emulator calls in freshly decoded code, as {@link EmulatedFloatAnalyzer} would,
	 * before analysis sees it. Code the old junk covered was never rewritten — at
	 * {@code OVERLAY_052::044c7e} the {@code FLD} under the junk is still {@code CD 39 42 80} —
	 * and decoded as it stands each {@code INT 3xh} derails what follows, swallowing the next
	 * call ({@code 044c82}): the very wreckage the discovery pass mistook for a routine that does
	 * not return. Each rewrite re-decodes what follows and can expose the next emulator call, so
	 * this runs until a round rewrites none. Returns everything the rewrites touched.
	 */
	private static AddressSetView rewriteEmulatorCalls(Program program, AddressSetView decoded,
			TaskMonitor monitor) throws CancelledException {
		AddressSet touched = new AddressSet();
		AddressSetView pending = decoded;
		while (!pending.isEmpty()) {
			AddressSetView round =
				EmulatedFloatPatcher.rewriteAll(program, pending, false, monitor).touched();
			touched.add(round);
			pending = round;
		}
		return touched;
	}

	/**
	 * Decode the rest of the straight line after a restored call where junk blocks it. The
	 * cleared fall-through is re-decoded into bytes that out-of-phase junk from the emulator
	 * calls' old mis-decode still covers — {@code OVERLAY_052::044c79}, inside the
	 * {@code MOV [BP-0x90],DX} after the call at {@code 044c6d} — so the decode stops one
	 * instruction short, and the discovery pass reads the gap as a caller that falls into data.
	 * {@link ConflictArbitration} would settle each such conflict later, but analysis gets to
	 * look first. Returns true if any code was recovered.
	 */
	private static boolean unblockStraightLine(Program program, Address start,
			AddressSet decoded, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		boolean recovered = false;
		Address at = start;
		for (int i = 0; i < STRAIGHT_LINE_LIMIT && at != null; i++) {
			Instruction instruction = listing.getInstructionAt(at);
			if (instruction == null) {
				if (!ConflictArbitration.recover(program, at, decoded, monitor)) {
					break;
				}
				recovered = true;
				instruction = listing.getInstructionAt(at);
			}
			at = instruction.getFallThrough();
		}
		return recovered;
	}

	/**
	 * The functions whose bodies the restored calls should be in: for a call the cut left
	 * outside every body, the nearest function above it. The body can stop well above the
	 * call — where the cleared code began ({@code OVL064_182D} ends at
	 * {@code OVERLAY_064::045855}, its call to {@code __ftol} is at {@code 045884}), or where
	 * a float rewrite re-decoded code after the body was drawn ({@code OVL078_0BC9}, 86 bytes
	 * of a routine that runs to {@code OVERLAY_078::044e38}) — with jumps in between, so the
	 * walk goes by address. A wrong guess costs nothing: a body grows only along flow from
	 * its own entry.
	 */
	private static Set<Function> owners(Program program, List<Instruction> calls) {
		FunctionManager functions = program.getFunctionManager();
		Listing listing = program.getListing();
		Set<Function> owners = new LinkedHashSet<>();
		for (Instruction call : calls) {
			Instruction at = call;
			Function owner = null;
			for (int i = 0; i < OWNER_WALK_LIMIT && at != null && owner == null; i++) {
				owner = functions.getFunctionContaining(at.getMinAddress());
				Instruction before = listing.getInstructionBefore(at.getMinAddress());
				// Contiguous code only: a gap above is the end of whatever routine this is.
				at = before != null && before.getMaxAddress().next().equals(at.getMinAddress())
						? before : null;
			}
			if (owner != null) {
				owners.add(owner);
			}
		}
		return owners;
	}
}
