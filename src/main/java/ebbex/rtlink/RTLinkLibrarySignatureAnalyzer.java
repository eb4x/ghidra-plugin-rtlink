package ebbex.rtlink;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Names the RTLink runtime's public entries, and recovers the ones nothing in the program
 * reaches, by matching the user's own copy of the vendor library ({@code RTLUTILS.LIB} of an
 * RTLink/Plus distribution) against the resident code. Inert until the option names a
 * library: the extension ships no vendor bytes. See {@code docs/vendor-signatures.md}.
 * <p>
 * Runs last, after {@link RTLinkFlowRepairAnalyzer}: whether a placed public is code or a
 * variable is read from what the program's own analysis has made of the address (an
 * instruction start, or bytes something reads as data), and the code that reads a variable
 * may itself be buried code that pass recovers (RTLUTILS' messages, read only from a routine
 * nothing calls).
 */
public final class RTLinkLibrarySignatureAnalyzer extends AbstractAnalyzer {

	static final String NAME = "RTLink Library Signatures";
	private static final String DESCRIPTION =
		"Names the RTLink runtime's public entries ($$VM_*, $$RTL*, _rtvm_*) and recovers " +
			"those nothing reaches, by matching the vendor library you name in the options " +
			"(RTLUTILS.LIB of your RTLink/Plus distribution) against the resident code. Does " +
			"nothing until a library is set.";

	static final String OPTION_LIBRARY = "Vendor library";
	private static final String OPTION_LIBRARY_DESCRIPTION =
		"Path of RTLUTILS.LIB (or another RTLink/Plus OMF library or object). Empty: off.";

	private String library = "";
	private long lastTxId = -1;

	public RTLinkLibrarySignatureAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY.after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkProgram.isSegmentedMz(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_LIBRARY, "", null, OPTION_LIBRARY_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		library = options.getString(OPTION_LIBRARY, "").strip();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (library.isEmpty()) {
			return true;
		}
		TransactionInfo tx = program.getCurrentTransactionInfo();
		if (tx != null) {
			if (tx.getID() == lastTxId) {
				return true; // the functions it makes re-trigger byte analysis; once per txn
			}
			lastTxId = tx.getID();
		}

		Path path = Path.of(library);
		List<OmfLibrary.Module> modules;
		try {
			if (!Files.isRegularFile(path)) {
				log.appendMsg(NAME, "No vendor library at " + library);
				return false;
			}
			modules = OmfLibrary.read(path);
		}
		catch (IOException e) {
			log.appendMsg(NAME, "Cannot read the vendor library " + library + ": " + e.getMessage());
			return false;
		}
		LibrarySignatures.Result result = LibrarySignatures.apply(program, modules, monitor);
		Msg.info(this, String.format(
			"RTLink/Plus: Placed %d vendor library entr%s from %s (%d new function(s))",
			result.placed(), result.placed() == 1 ? "y" : "ies", path.getFileName(),
			result.functions()));
		return true;
	}
}
