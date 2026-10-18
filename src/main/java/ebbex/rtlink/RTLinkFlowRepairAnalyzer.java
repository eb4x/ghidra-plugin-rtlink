package ebbex.rtlink;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Repairs <b>buried code</b>: real, evidenced instructions that stay undisassembled
 * because junk from a bad flow covers their bytes, or that no flow ever reaches. Runs
 * dead last, after every pass that plants flows or stamps conflict bookmarks, and
 * enforces one invariant — <i>referenced code always wins over unreferenced junk</i>.
 * <p>
 * The repairs are separate passes, each in its own class, run here in an order that
 * matters:
 * <ol type="A">
 * <li>{@link RelocationFallthroughs} — calls whose fall-through lands on a loader-relocated
 * segment word cannot return there.</li>
 * <li>{@link ConflictArbitration} — the disassembler's conflicting-instruction marks, decided
 * for the side with evidence.</li>
 * <li>{@link CodeGaps} — undefined gaps that decode exactly onto the code after them.</li>
 * <li>{@link FarVectorFlows} — far jumps and calls through {@code CS:[imm16]} vectors.</li>
 * <li>{@link NonReturningCalls} — calls to routines that end in DOS exit.</li>
 * <li>{@link FillerIslands} — instructions decoded out of zero fill.</li>
 * </ol>
 * plus {@link FarCodePointers}, run with the gap filler to a fixpoint.
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
		// After E, never before it: the junk table behind a non-returning call is
		// fallen into (from the call), so F would refuse to touch it. E removes the
		// cause; F only clears islands that never had one.
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

		// Msg.info only — content in the MessageLog pops the analysis warnings dialog.
		if (vectors > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Followed %d far jump(s)/call(s) through a code-segment vector",
				vectors));
		}
		if (fallthroughs > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Sealed %d fall-through(s) behind non-returning calls",
				fallthroughs));
		}
		if (conflicts > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Recovered %d buried instruction run(s) from junk conflicts",
				conflicts));
		}
		if (pointed > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Recovered %d routine(s) reached through a CS:imm far pointer",
				pointed));
		}
		if (gaps > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Disassembled %d unreached code gap(s) between routines", gaps));
		}
		if (filler > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Cleared %d instruction(s) decoded from zero fill", filler));
		}
		return true;
	}
}
