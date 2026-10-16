// Pre-script for a headless run (viceroyTest): points the RTLink Library Signatures analyzer
// at the vendor library named by the first argument, before analysis. "none" leaves it off.
import ghidra.app.script.GhidraScript;

public class RTLinkLibraryOptionScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String library = args.length > 0 ? args[0] : "none";
		if (library.equals("none")) {
			println("rtlink: no vendor library");
			return;
		}
		setAnalysisOption(currentProgram, "RTLink Library Signatures.Vendor library", library);
		println("rtlink: vendor library " + library);
	}
}
