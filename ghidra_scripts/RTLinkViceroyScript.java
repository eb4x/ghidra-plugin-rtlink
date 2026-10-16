// Local-only check of the RTLink extension on a real target: run as -postScript after a fresh
// import+analysis of VICEROY.EXE (see the viceroyTest gradle task; never in verify).
// Asserts that the RTLink analyzers actually ran: overlay memory blocks were created
// and code ended up inside them. Prints its own verdict because analyzeHeadless
// exits 0 even when a post-script throws.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class RTLinkViceroyScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		int overlayBlocks = 0;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName().startsWith("OVERLAY_")) {
				overlayBlocks++;
			}
		}
		if (overlayBlocks == 0) {
			println("UNEXPECTED: no OVERLAY_ memory blocks — RTLinkOverlayAnalyzer did not run?");
			return;
		}
		println("viceroy: " + overlayBlocks + " overlay blocks");

		int overlayFunctions = 0;
		int thunks = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getEntryPoint().getAddressSpace().getName().startsWith("OVERLAY_")) {
				overlayFunctions++;
			}
			if (f.isThunk()) {
				thunks++;
			}
		}
		if (overlayFunctions == 0) {
			println("UNEXPECTED: overlay blocks exist but contain no functions");
			return;
		}
		println("viceroy: " + overlayFunctions + " functions in overlay blocks, " +
			thunks + " thunks program-wide");

		// The VM-runtime seeding pass: the entry stub must have yielded __astart with a
		// real function body, and the $$VM_UNK constant-pair recognizer must have seeded
		// vendor entries (recorded by the analyzer in a program-info option).
		var astartSymbols = currentProgram.getSymbolTable().getSymbols("__astart");
		if (!astartSymbols.hasNext()) {
			println("UNEXPECTED: no __astart symbol — entry stub seeding did not run?");
			return;
		}
		Function astart = currentProgram.getFunctionManager()
				.getFunctionAt(astartSymbols.next().getAddress());
		if (astart == null) {
			println("UNEXPECTED: __astart exists but is not a function");
			return;
		}
		int vmSeeds = currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
				.getInt("RTLink VM Runtime Seeds", 0);
		if (vmSeeds < 4) {
			println("UNEXPECTED: only " + vmSeeds +
				" VM runtime seeds — dispatch-pair recognizer did not fire?");
			return;
		}
		println("viceroy: __astart at " + astart.getEntryPoint() + ", " + vmSeeds +
			" VM runtime function seeds");

		String[] args = getScriptArgs();
		boolean library = args.length > 0 && !args[0].equals("none");
		if (!checkRuntimeCoverage(library)) {
			return;
		}
		if (library && !checkVendorNames()) {
			return;
		}
		println("VICEROY OK");
	}

	/**
	 * With the vendor library: entries its publics name, checked at a sample of each kind.
	 * $$VMGETPAGE (1ebd) is not among them: VICEROY inserts an AND AX,3FFF as its second
	 * instruction, so no reference variant's opening matches it.
	 */
	private static final String[][] VENDOR_NAMES = {
		{ "210d:0e52", "$$VM_CALL" }, { "210d:1216", "$$VM_JMP" }, { "210d:1554", "$$VM_RET" },
		{ "210d:1bc0", "$$VMRELEASE" }, { "210d:1cce", "_vm_longjmp" },
		{ "210d:1df7", "_rtvm_this_section_hold" }, { "275d:0645", "$$RTLSETERROR" },
		{ "275d:07d5", "$$RTL_PRELOAD" }, { "275d:0834", "$$RTLOVL_ALLOC_SAVE_FILE" },
		{ "275d:0838", "$$RTLOVL_DELETE_SAVE_FILE" }, { "275d:0909", "$$RTLPATHSEARCH" },
	};

	private boolean checkVendorNames() {
		var missing = new java.util.ArrayList<String>();
		for (String[] entry : VENDOR_NAMES) {
			boolean named = false;
			for (var symbol : currentProgram.getSymbolTable().getSymbols(toAddr(entry[0]))) {
				named |= symbol.getName().equals(entry[1]);
			}
			if (!named) {
				missing.add(entry[0] + " " + entry[1]);
			}
		}
		println("viceroy: vendor names " + (VENDOR_NAMES.length - missing.size()) + "/" +
			VENDOR_NAMES.length + "; missing " + missing);
		if (!missing.isEmpty()) {
			println("UNEXPECTED: vendor library publics not placed where VICEROY has them");
			return false;
		}
		return true;
	}

	/** What only the vendor library proves: three public entries nothing references. */
	private static final String[] PROVEN_BY_THE_LIBRARY = { "210d:1cce", "275d:0834", "275d:0838" };

	/**
	 * Every routine of the RTLink runtime (the VM nucleus at 210d, RTLUTILS at 275d) that
	 * viceroy carved out by hand and proved, each against NEBULAR's build, the vendor's
	 * objects or a reference in these bytes (the plates on /COLONIZE/VICEROY.PRE-CSEG). A fresh
	 * analysis has to find each as a function — less {@link #NOT_IN_THESE_BYTES}, plus
	 * {@link #BEYOND_THE_CARVING} — and no function may start anywhere else in the two
	 * segments but {@link #TAIL_CALLED_BLOCKS}.
	 */
	private static final String[] RUNTIME_ENTRIES = {
		"210d:051a", "210d:053f", "210d:0554", "210d:0574", "210d:05e6", "210d:0630", "210d:0701",
		"210d:071d", "210d:0727", "210d:0c7f", "210d:0d91", "210d:0dab", "210d:0e52", "210d:1216",
		"210d:12ec", "210d:1341", "210d:13be", "210d:1402", "210d:147c", "210d:1554", "210d:1563",
		"210d:167b", "210d:1695", "210d:18c7", "210d:18ea", "210d:1939", "210d:194a", "210d:1954",
		"210d:19d6", "210d:1aae", "210d:1ac0", "210d:1ac4", "210d:1b86", "210d:1bc0", "210d:1bc4",
		"210d:1bd3", "210d:1bdd", "210d:1c43", "210d:1c61", "210d:1c75", "210d:1c88", "210d:1c92",
		"210d:1cce", "210d:1cd4", "210d:1cde", "210d:1d49", "210d:1dbd", "210d:1df1", "210d:1df7",
		"210d:1dfd", "210d:1e44", "210d:1e4a", "210d:1e50", "210d:1ebd", "210d:2019", "210d:2042",
		"210d:238c", "210d:238e", "210d:239d", "210d:2492", "210d:2590", "210d:2607", "210d:265a",
		"210d:2684", "210d:26a0", "210d:2982", "210d:2a0e", "210d:2a48", "210d:2a6e", "210d:2aa5",
		"210d:2ae5", "210d:2b22", "210d:2b7d", "210d:2b9b", "210d:2c57", "210d:2d5a", "210d:2e59",
		"210d:2e78", "210d:2f42", "210d:2fb7", "210d:2fd2", "210d:3018", "210d:302e", "210d:3046",
		"210d:3080", "210d:3094", "210d:3147", "210d:3179", "210d:31c4", "210d:322c", "210d:3254",
		"210d:3260", "210d:3322", "210d:3367", "210d:33e3",
		// viceroy's rtlink_vm_event_handler sits at 3418, which is the RET above it: the
		// registration at 210d:0bf1 passes 0x3419.
		"210d:3419",
		"210d:3437", "210d:3564", "210d:3791", "210d:37ad", "210d:37d9", "210d:38d8", "210d:391d",
		"210d:3a0f", "210d:3d9b", "210d:3ed3", "210d:3f46", "210d:3fb7", "210d:402f", "210d:4052",
		"210d:409c", "210d:40e6", "210d:43f0", "210d:4454", "210d:44db", "210d:45d3", "210d:45da",
		"210d:45e7", "210d:45f1", "210d:466e", "210d:470f", "210d:4751", "210d:479f", "210d:49c3",
		"210d:49db", "210d:4a4c", "210d:4c83", "210d:4ce3", "210d:4d4f", "210d:4de3", "210d:4e28",
		"210d:4e3b", "210d:4e4e", "210d:4fe5", "210d:508b", "210d:5247", "210d:52a6", "210d:52d3",
		"210d:535c", "210d:5365", "210d:536e", "210d:538c", "210d:53b5", "210d:53ce", "210d:53fd",
		"210d:541e", "210d:545f", "210d:54d0", "210d:552c", "210d:5699", "210d:56e5", "210d:5716",
		"210d:5808", "210d:5856", "210d:58c2", "210d:58f7", "210d:58f9", "210d:597f", "210d:59ce",
		"210d:5a76", "210d:5a9d", "210d:5afc", "210d:5b26", "210d:5b9d", "210d:5bcb", "210d:5c9e",
		"210d:5d49", "210d:5dd0",
		"275d:0000", "275d:023a", "275d:02b2", "275d:033a", "275d:0443", "275d:048f", "275d:05ed",
		"275d:0624", "275d:062d", "275d:0645", "275d:0660", "275d:06b3", "275d:06db", "275d:0700",
		"275d:07a4", "275d:07d5", "275d:07df", "275d:07e3", "275d:080f", "275d:0830", "275d:0834",
		"275d:0838", "275d:08ad", "275d:0909", "275d:0a11", "275d:0a4f", "275d:0ab8", "275d:0acc",
		"275d:0b09",
	};

	/**
	 * viceroy's entries no evidence in these bytes can find. Five split a routine at a jump
	 * target where NEBULAR's symbol table starts a function (12ec, 13be, 1402, 26a0 behind a
	 * VICEROY-only prologue, 3260 behind a VICEROY-only guard): from VICEROY alone they are
	 * one routine. Three are entries nothing references (vm_longjmp's AND ahead of its gate,
	 * 1cce; RTLUTILS' two return stubs, 0834 and 0838), proven against NEBULAR and the
	 * vendor's objects.
	 */
	private static final String[] NOT_IN_THESE_BYTES = {
		"210d:12ec", "210d:13be", "210d:1402", "210d:26a0", "210d:3260", "210d:1cce",
		"275d:0834", "275d:0838",
	};

	/**
	 * Routines the bytes prove that viceroy's carving left undefined: 1b43 (between
	 * $$VMREINIT's RETF and $$VMNOAUTOFLUSH, restores the INT 21h vector), 52df and 5338
	 * (the allocators rtlink_reserve_low/high_memory hand rtlink_reserve_loop in DI for its
	 * CALL DI).
	 */
	private static final String[] BEYOND_THE_CARVING = { "210d:1b43", "210d:52df", "210d:5338" };

	/**
	 * Jump targets Ghidra's Shared Return Calls makes functions of, as tail calls, where
	 * viceroy kept the code inside the routine jumping there: the INT 21h hook's AH=48h/49h
	 * branches (0668, 06c9) and three shared blocks of $$VM_JMP/$$VM_CALLR (1268, 12ad, 1407).
	 */
	private static final String[] TAIL_CALLED_BLOCKS =
		{ "210d:0668", "210d:06c9", "210d:1268", "210d:12ad", "210d:1407" };

	private boolean checkRuntimeCoverage(boolean library) {
		var functions = currentProgram.getFunctionManager();
		var expected = new java.util.TreeSet<ghidra.program.model.address.Address>();
		for (String entry : RUNTIME_ENTRIES) {
			expected.add(toAddr(entry));
		}
		for (String entry : NOT_IN_THESE_BYTES) {
			expected.remove(toAddr(entry));
		}
		if (library) {
			for (String entry : PROVEN_BY_THE_LIBRARY) {
				expected.add(toAddr(entry));
			}
		}
		for (String entry : BEYOND_THE_CARVING) {
			expected.add(toAddr(entry));
		}
		var tolerated = new java.util.HashSet<ghidra.program.model.address.Address>();
		for (String entry : TAIL_CALLED_BLOCKS) {
			tolerated.add(toAddr(entry));
		}
		var missing = new java.util.ArrayList<String>();
		for (var entry : expected) {
			if (functions.getFunctionAt(entry) == null) {
				missing.add(entry.toString());
			}
		}
		var extra = new java.util.ArrayList<String>();
		for (String name : new String[] { "CODE_94", "CODE_98" }) {
			MemoryBlock block = currentProgram.getMemory().getBlock(name);
			for (Function f : functions.getFunctions(
				new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd()), true)) {
				if (!expected.contains(f.getEntryPoint()) && !tolerated.contains(f.getEntryPoint())) {
					var from = new java.util.ArrayList<String>();
					for (var ref : getReferencesTo(f.getEntryPoint())) {
						from.add(ref.getFromAddress() + " " + ref.getReferenceType());
					}
					extra.add(f.getEntryPoint() + " (" + f.getBody().getNumAddresses() + "B, from " +
						from + ")");
				}
			}
		}
		println("viceroy: runtime " + (expected.size() - missing.size()) + "/" + expected.size() +
			" entries found; missing " + missing + "; extra " + extra);
		if (!missing.isEmpty() || !extra.isEmpty()) {
			println("UNEXPECTED: the RTLink runtime is not recovered as viceroy carved it");
			return false;
		}
		return true;
	}
}
