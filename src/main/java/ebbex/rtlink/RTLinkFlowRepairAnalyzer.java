package ebbex.rtlink;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Repairs <b>buried code</b>: real, evidenced instructions that stay undisassembled
 * because junk from a bad flow covers their bytes, or that no flow ever reaches. Runs
 * dead last, after every pass that plants flows or stamps conflict bookmarks, and
 * enforces one invariant — <i>referenced code always wins over unreferenced junk</i>.
 * <p>
 * The repairs are separate passes, each in its own class, run here in this order, which
 * matters (the reasons are at each call):
 * <ol>
 * <li>{@link RelocationFallthroughs} — calls whose fall-through lands on a loader-relocated
 * segment word cannot return there.</li>
 * <li>{@link FarVectorFlows} — far jumps and calls through {@code CS:[imm16]} vectors.</li>
 * <li>{@link NonReturningCalls} — calls to routines that end in DOS exit.</li>
 * <li>{@link StaleNoReturns} — discovered no-return flags on routines whose body returns.</li>
 * <li>{@link FillerIslands} — instructions decoded out of zero fill.</li>
 * <li>{@link ConflictArbitration} — the disassembler's conflicting-instruction marks, decided
 * for the side with evidence.</li>
 * <li>{@link FarCodePointers} and {@link CodeGaps}, to a fixpoint — routines reached through a
 * far pointer the program builds, and undefined gaps that decode exactly onto the code after
 * them.</li>
 * <li>{@link ConflictArbitration#sweepRepaired} — the conflict marks those repairs made
 * fossils of.</li>
 * </ol>
 */
public class RTLinkFlowRepairAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink Buried Code Repair";
	private static final String DESCRIPTION =
		"Repairs code buried under junk instructions from bad flows: removes the " +
			"impossible fall-through of calls that land on loader-relocated segment " +
			"words, and arbitrates the disassembler's conflicting-instruction " +
			"bookmarks in favor of referenced code over unreferenced junk; recovers " +
			"routines reached only through a CS:imm far pointer (interrupt hooks, " +
			"registered handlers, return vectors) and runs of routines nothing reaches. " +
			"Re-run as a one-shot to repair conflicts introduced after the initial pass.";

	/** Rounds to run the gap filler for; it converges in two or three on this corpus. */
	private static final int GAP_FILL_ROUNDS = 10;

	private long lastTxId = -1;

	public RTLinkFlowRepairAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Dead last: every pass that disassembles, plants flows or stamps conflict
		// bookmarks — including DecompilerSwitchAnalyzer at CODE_ANALYSIS and every other
		// RTLink analyzer but the library signatures — has finished its first wave by then.
		setPriority(AnalysisPriority.LOW_PRIORITY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkProgram.isSegmentedMz(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		if (!RTLinkProgram.isOverlayAnalyzed(program)) {
			return false; // canAnalyze accepts any segmented MZ; these repairs are RTLink's
		}
		TransactionInfo tx = program.getCurrentTransactionInfo();
		if (tx != null) {
			if (tx.getID() == lastTxId) {
				return true; // our own repairs re-trigger byte analysis; run once per txn
			}
			lastTxId = tx.getID();
		}

		int fallthroughs = RelocationFallthroughs.repair(program, monitor);
		int vectors = FarVectorFlows.resolve(program, monitor);
		fallthroughs += NonReturningCalls.seal(program, monitor);
		// After NonReturningCalls: only once the DOS exits are marked do the bodies end where
		// the code does, so a return in one is a return of that routine. And before
		// ConflictArbitration: its clears start auto-analysis, whose no-return discovery would
		// re-flag a routine whose callers are still cut.
		int reopened = StaleNoReturns.clear(program, monitor);
		// After NonReturningCalls, never before it: the junk table behind a non-returning call
		// is fallen into (from the call), so FillerIslands would refuse to touch it.
		// NonReturningCalls removes the cause; FillerIslands only clears islands that never
		// had one.
		int filler = FillerIslands.clear(program, monitor);
		int conflicts = ConflictArbitration.arbitrate(program, monitor);

		// Filling a gap creates a function, and a function is what identifies the
		// stranded epilogue of the routine above it — so each round exposes the next. A
		// routine reached through a far pointer brings its own calls and pointers along.
		// Run to a fixpoint rather than leaving code for a second invocation to find.
		int gaps = 0;
		int pointed = 0;
		for (int round = 0; round < GAP_FILL_ROUNDS; round++) {
			int claimed = FarCodePointers.recover(program, monitor);
			int filled = CodeGaps.fill(program, monitor);
			if (claimed + filled == 0) {
				break;
			}
			pointed += claimed;
			gaps += filled;
		}
		// Last: a conflict mark whose blocked address now holds code is a fossil,
		// whether this analyzer cleared the junk or an earlier pass already had.
		ConflictArbitration.sweepRepaired(program, monitor);

		RTLinkProgram.report(this, vectors,
			"RTLink/Plus: Followed %d far jump(s)/call(s) through a code-segment vector");
		RTLinkProgram.report(this, fallthroughs,
			"RTLink/Plus: Sealed %d fall-through(s) behind non-returning calls");
		RTLinkProgram.report(this, reopened,
			"RTLink/Plus: Cleared %d no-return flag(s) on functions whose body returns");
		RTLinkProgram.report(this, conflicts,
			"RTLink/Plus: Recovered %d buried instruction run(s) from junk conflicts");
		RTLinkProgram.report(this, pointed,
			"RTLink/Plus: Recovered %d routine(s) reached through a CS:imm far pointer");
		RTLinkProgram.report(this, gaps,
			"RTLink/Plus: Disassembled %d unreached code gap(s) between routines");
		RTLinkProgram.report(this, filler,
			"RTLink/Plus: Cleared %d instruction(s) decoded from zero fill");
		return true;
	}
}
