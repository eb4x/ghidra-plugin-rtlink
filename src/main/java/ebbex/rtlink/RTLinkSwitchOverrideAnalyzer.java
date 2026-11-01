package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Tells the decompiler where the RTLink/Plus switch tables — resident and overlay — really go.
 * <p>
 * {@link RTLinkSwitchTableAnalyzer} repairs the <i>references</i>, which is what keeps the listing
 * and function bodies sane. It cannot repair the decompiler, whose own p-code still resolves
 * {@code JMP word ptr CS:[BX+disp]} against the 64KB-page segment that the x86 {@code currentCS}
 * subconstructor synthesises — so those functions still decompile into whichever segment the page
 * happens to cover, with "Unable to resolve constructor" errors along the way.
 * <p>
 * A jump-table override fixes that, and Ghidra stores one purely as symbols: a namespace
 * {@code <func>::override::jmp_<branchaddr>} holding a {@code switch} label at the branch and a
 * {@code case_N} label at each destination (see {@link JumpTable#writeOverride}). The decompiler
 * reads them back through {@code HighFunction.grabOverrides()} and emits
 * "Switch is manually overridden" instead of guessing.
 * <p>
 * The override is written from the table pass's own record: the targets it recovered, kept
 * with the dispatch ({@link RTLinkProgram#recordSwitch}). Not from the references, which stock
 * switch analysis may have replaced by then ({@code DecompilerSwitchAnalysisCmd} re-walks every
 * jump table in a function it visits), and not by re-deriving the table from a program that has
 * changed since. The table pass writes the override itself where the function already exists;
 * this pass, and {@link #analysisEnded}, catch the dispatches whose function appeared later.
 * Once the function exists the record is consumed: an override already present (this pass's or
 * the user's) is left alone, one the user deletes stays deleted, and a failed write is reported
 * once.
 */
public final class RTLinkSwitchOverrideAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Switch Override";
	private static final String DESCRIPTION =
		"Writes decompiler jump-table overrides for the CS-relative switches recovered by the " +
			"RTLink/Plus Switch Table analyzer, so the decompiler stops resolving them against " +
			"the 64KB-page segment.";

	public RTLinkSwitchOverrideAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkProgram.isSegmentedMz(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (!RTLinkProgram.isOverlayAnalyzed(program)) {
			return false; // canAnalyze accepts any segmented MZ; these switches are RTLink's
		}
		report(writeOverrides(program, set, log, monitor));
		return true;
	}

	@Override
	public void analysisEnded(Program program) {
		// Called on every analyzer whose canAnalyze passed, enabled or not.
		if (!RTLinkProgram.isAnalyzerEnabled(program, NAME) ||
			!RTLinkProgram.isOverlayAnalyzed(program)) {
			return;
		}
		RTLinkProgram.dropLegacySwitchMarks(program);
		MessageLog log = new MessageLog();
		try {
			report(writeOverrides(program, program.getMemory(), log, TaskMonitor.DUMMY));
		}
		catch (CancelledException _) {
			return; // DUMMY monitor never cancels
		}
		// analysisEnded cannot surface the analysis warnings dialog.
		if (log.hasMessages()) {
			Msg.warn(this, log.toString());
		}
	}

	/**
	 * Write the override for each switch within {@code set} still waiting for one, wherever its
	 * function now exists. Returns the number written.
	 */
	static int writeOverrides(Program program, AddressSetView set, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		List<Address> pending = new ArrayList<>();
		AddressIterator dispatches = RTLinkProgram.pendingSwitches(program, set);
		while (dispatches.hasNext()) {
			pending.add(dispatches.next()); // consuming while iterating would disturb the map
		}
		int written = 0;
		for (Address dispatch : pending) {
			monitor.checkCancelled();
			if (writeOverride(program, dispatch, log)) {
				written++;
			}
		}
		return written;
	}

	/**
	 * Write the override for the pending switch at {@code dispatch} from its recorded targets,
	 * if its function exists. Returns whether one was written.
	 * <p>
	 * The record is consumed once the function exists, whatever happens: the override is
	 * written, or one is already there (this pass's or the user's), or writing it failed and
	 * has been logged. So an override the user deletes stays deleted, and a failure is
	 * reported once rather than at every analysis end. Without a function the record waits.
	 */
	static boolean writeOverride(Program program, Address dispatch, MessageLog log) {
		Function function = program.getFunctionManager().getFunctionContaining(dispatch);
		if (function == null) {
			return false;
		}
		List<Address> targets = RTLinkProgram.switchTargets(program, dispatch);
		RTLinkProgram.consumeSwitch(program, dispatch);
		if (targets.isEmpty() || hasOverride(function, dispatch)) {
			return false;
		}
		JumpTable override =
			new JumpTable(dispatch, new ArrayList<>(targets), true, EquateSymbol.FORMAT_DEFAULT);
		try {
			override.writeOverride(function);
			return true;
		}
		catch (InvalidInputException e) {
			log.appendMsg(String.format("RTLink: could not override switch at %s in %s: %s",
				dispatch, function.getName(), e.getMessage()));
			return false;
		}
	}

	/** True if {@code function} already carries a jump-table override for {@code dispatch}. */
	private static boolean hasOverride(Function function, Address dispatch) {
		Namespace overrides = HighFunction.findOverrideSpace(function);
		return overrides != null && HighFunction.findNamespace(
			function.getProgram().getSymbolTable(), overrides, "jmp_" + dispatch) != null;
	}

	private void report(int written) {
		RTLinkProgram.report(this, written, "RTLink/Plus: Wrote %d switch table override(s)");
	}
}
