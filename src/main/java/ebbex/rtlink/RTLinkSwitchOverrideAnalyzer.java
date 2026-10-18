package ebbex.rtlink;

import java.util.ArrayList;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
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
 * The override is written from the table pass's own record — the dispatches it marked and the
 * {@code COMPUTED_JUMP} references it laid down — never by re-deriving the table, which by now
 * would read a program with more functions and more code and could disagree with those
 * references. It needs a {@link FunctionDB} to hang its namespace off, which may not exist when
 * this pass first sees the dispatch, so {@link #analysisEnded} catches every marked dispatch whose
 * function appeared later. An override already present is left alone: it is either this pass's
 * own, written from the same references, or the user's.
 */
public class RTLinkSwitchOverrideAnalyzer extends AbstractAnalyzer {

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
		MessageLog log = new MessageLog();
		try {
			report(writeOverrides(program, program.getMemory(), log, TaskMonitor.DUMMY));
		}
		catch (CancelledException e) {
			return; // DUMMY monitor never cancels
		}
		// analysisEnded cannot surface the analysis warnings dialog.
		if (log.hasMessages()) {
			Msg.warn(this, log.toString());
		}
	}

	/**
	 * Write an override for each dispatch {@link RTLinkSwitchTableAnalyzer} marked in
	 * {@code set} that has a defined function and no override yet. Returns the number written.
	 */
	static int writeOverrides(Program program, AddressSetView set, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		int written = 0;
		AddressIterator dispatches = RTLinkProgram.switchDispatches(program, set);
		while (dispatches.hasNext()) {
			monitor.checkCancelled();
			Address dispatch = dispatches.next();
			Function function = program.getFunctionManager().getFunctionContaining(dispatch);
			if (!(function instanceof FunctionDB) || hasOverride(function, dispatch)) {
				continue;
			}
			ArrayList<Address> destinations = computedTargets(program, dispatch);
			if (destinations.isEmpty()) {
				continue;
			}
			JumpTable override =
				new JumpTable(dispatch, destinations, true, EquateSymbol.FORMAT_DEFAULT);
			try {
				override.writeOverride(function);
				written++;
			}
			catch (InvalidInputException e) {
				log.appendMsg(String.format("RTLink: could not override switch at %s in %s: %s",
					dispatch, function.getName(), e.getMessage()));
			}
		}
		return written;
	}

	/** True if {@code function} already carries a jump-table override for {@code dispatch}. */
	private static boolean hasOverride(Function function, Address dispatch) {
		Namespace overrides = HighFunction.findOverrideSpace(function);
		return overrides != null && HighFunction.findNamespace(
			function.getProgram().getSymbolTable(), overrides, "jmp_" + dispatch) != null;
	}

	/** The destinations of the computed-jump references from {@code dispatch}, in address order. */
	private static ArrayList<Address> computedTargets(Program program, Address dispatch) {
		ArrayList<Address> targets = new ArrayList<>();
		for (Reference reference : program.getReferenceManager().getReferencesFrom(dispatch)) {
			if (reference.getReferenceType().isComputed() && reference.getReferenceType().isJump()) {
				targets.add(reference.getToAddress());
			}
		}
		targets.sort(null);
		return targets;
	}

	private void report(int written) {
		if (written > 0) {
			// Msg.info only, never log.appendMsg: any content in the analysis MessageLog makes
			// AutoAnalysisPlugin pop a "warnings/errors issued during analysis" dialog.
			Msg.info(this, String.format("RTLink/Plus: Wrote %d switch table override(s)", written));
		}
	}
}
