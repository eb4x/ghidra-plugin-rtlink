package ebbex.rtlink;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.mz.OldDOSHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MzLoader;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Detects and loads RTLink/Plus overlay pages from DOS MZ executables.
 * <p>
 * RTLink/Plus was a widely-used overlay manager for late-DOS commercial
 * software (Microprose, Sierra, etc.). Overlay pages are stored at file offsets
 * past the MZ image end and are invisible to {@link MzLoader}'s static
 * analysis. This analyzer creates overlay memory blocks for each page, applies
 * segment relocations, and wires cross-references from dispatch stubs to
 * overlay functions.
 * <p>
 * Dispatch stubs are 12- or 14-byte sequences: {@code CALLF seg:0DAB} (5 bytes) +
 * {@code JMPF 0000:offset} (5 bytes) + page_id (2 bytes) + an optional module_word
 * (2 bytes). Bits 0-13 of page_id hold a 1-based descriptor index into the overlay
 * descriptor table; descriptor index N is overlay record N - 1, so page_id 1 targets
 * record 0. Record 0 is a real code page like the rest (in VICEROY.EXE it holds 15.6KB
 * of code, with its own relocations and 47 stubs targeting it); an earlier revision
 * assumed it was a non-code "global overlay table" and silently dropped every stub
 * aimed at it.
 * <p>
 * Pages contain multiple link-time modules, each with its own segment base
 * (CS = page frame + module base paragraph), so the JMPF offset is
 * module-relative. 12-byte stubs target module 0 (JMPF offset = in-page code
 * offset); 14-byte stubs carry the target module's base paragraph in module_word,
 * and the in-page code offset is {@code JMPF offset + module_word * 16}. See
 * {@link DispatchStubs} for how the two forms are told apart.
 * <p>
 * The same jump table also holds 10-byte <em>resident-target trampolines</em>:
 * {@code CALLF seg:disp} + {@code JMPF seg:off} with a real (relocated) target
 * segment. RTLink routes far calls from movable overlay code into resident code
 * through these so the overlay manager can re-vector the caller's far return
 * address if its page moves. Each one is converted into a thunk of its JMPF
 * target; see {@link DispatchStubs} for why leaving them as plain
 * functions damages decompilation at every call site.
 */
public final class RTLinkOverlayAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Overlay";
	private static final String DESCRIPTION =
		"Detects and loads RTLink/Plus overlay pages from DOS MZ executables. " +
			"Creates overlay memory blocks, applies segment relocations, and " +
			"creates cross-references from dispatch stubs to overlay functions.";
	/** The segment {@code MzLoader} loads the image at. */
	static final int INITIAL_SEGMENT_VAL = 0x1000;


	private static final String OPTION_APPLY_RELOCS = "Apply Relocations";
	private static final String OPTION_CREATE_XREFS = "Create Stub Cross-References";
	private static final String OPTION_MARKUP_HEADERS = "Markup Page Headers";
	private static final String OPTION_ASSUME_DS = "Assume Data Segment (DS)";

	/**
	 * Bodies of the dispatch stubs/trampolines this run actually resolved — the set that
	 * {@link #analysisEnded} sweeps clean of the disassembler's stale "Bad Instruction"
	 * marks. Analyzer instances are created per program, so this is program-scoped.
	 */
	private AddressSet resolvedStubBodies = new AddressSet();

	private boolean applyRelocations = true;
	private boolean createStubXrefs = true;
	private boolean markupHeaders = true;
	private boolean assumeDataSegment = true;

	private long lastTxId = -1;

	public RTLinkOverlayAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
		// Offer this analyzer in Analysis -> One Shot so it can be re-run on an
		// already-analyzed program to retrofit the assumed data segment (DS/DGROUP)
		// and overlay markup without re-importing.
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkProgram.isSegmentedMz(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		TransactionInfo tx = program.getCurrentTransactionInfo();
		if (tx != null) {
			if (tx.getID() == lastTxId) {
				return true;
			}
			lastTxId = tx.getID();
		}

		if (RTLinkProgram.isOverlayAnalyzed(program)) {
			// Overlays were processed by a prior run; still retrofit what can be repaired
			// in place on re-analysis so an already-analyzed program benefits without
			// re-importing: disassemble and rebuild "husk" functions whose code the old
			// disassembler abandoned, re-wire dispatch-stub thunks (clearing stale
			// no-return flags that silently truncate every caller's decompilation) and
			// assume DS. Husks first, so the thunk pass finds real code at its targets.
			HuskRepair.repair(program, log, monitor);
			if (createStubXrefs) {
				// The stub pass also retrofits the VM-runtime entry seeds, and only it: a
				// binary without corroborating dispatch stubs gets none, as on a fresh import.
				repairStubThunks(program, log, monitor);
			}
			ModuleSegments.assign(program, log);
			maybeAssumeDataSegment(program, log);
			return true;
		}

		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			return false;
		}

		FileBytes fileBytes = allFileBytes.get(0);
		try (FileBytesProvider provider = new FileBytesProvider(fileBytes)) {
			BinaryReader reader = new BinaryReader(provider, true);

			OldDOSHeader header = new OldDOSHeader(reader);
			if (!header.isDosSignature()) {
				return false;
			}

			long imageEnd = computeImageEnd(header);
			long overlayStart = (imageEnd + 15) & ~15L;
			if (overlayStart <= 0 || overlayStart >= fileBytes.getSize()) {
				return false;
			}

			if (!detectRTLinkOverlay(reader, overlayStart, fileBytes.getSize())) {
				return false;
			}

			List<RTLinkOverlayPage> allPages =
				RTLinkOverlayPage.parseAllPages(reader, overlayStart, fileBytes.getSize());
			if (allPages.size() < 2) {
				return false;
			}
			if (hasOverlayBlocks(program)) {
				// The flag is set only once a run completes, so blocks without it are what a
				// cancelled or failed run left. Creating them again would not fail: Ghidra
				// names a clashing overlay space OVERLAY_NN.1, and the program would carry
				// two copies of every page.
				log.appendMsg("RTLink: overlay blocks from an interrupted run are present; " +
					"re-import the program to analyze its overlays");
				return false;
			}

			Msg.info(this, String.format(
				"RTLink/Plus: Found %d overlay pages at file offset 0x%X",
				allPages.size(), overlayStart));

			List<OverlayBlockInfo> overlayBlocks =
				createOverlayBlocks(program, fileBytes, allPages, log, monitor);
			// Before the stub scan disassembles anything; again inside it, once the stubs
			// have named the modules the relocation table cannot.
			ModuleSegments.assign(program, log);

			if (applyRelocations && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Applying overlay relocations...");
				for (OverlayBlockInfo info : overlayBlocks) {
					monitor.checkCancelled();
					OverlayRelocations.apply(program, info.block(), info.page(), log);
				}
			}

			if (createStubXrefs && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Discovering dispatch stubs...");
				DispatchStubs.resolve(program, overlayBlocks, resolvedStubBodies, log, monitor);
			}

			if (markupHeaders) {
				monitor.setMessage("RTLink: Marking up page headers...");
				markupOverlayHeaders(program, fileBytes, allPages, log, monitor);
			}

			monitor.setMessage("RTLink: Determining data segment (DGROUP)...");
			maybeAssumeDataSegment(program, log);

			RTLinkProgram.markOverlayAnalyzed(program);
			return true;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendMsg("RTLink: Analysis failed: " + e.getMessage());
			Msg.error(this, "RTLink overlay analysis failed", e);
			return false;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_APPLY_RELOCS, applyRelocations, null,
			"Rebase unrelocated segment words in overlay code by the image base, " +
				"at the sites given by each page's relocation table.");
		options.registerOption(OPTION_CREATE_XREFS, createStubXrefs, null,
			"Discover dispatch stubs and resident-target trampolines; create " +
				"cross-references and thunks to their targets.");
		options.registerOption(OPTION_MARKUP_HEADERS, markupHeaders, null,
			"Create data structures for RTLink page headers in the listing.");
		options.registerOption(OPTION_ASSUME_DS, assumeDataSegment, null,
			"Detect DGROUP from the C startup and assume it for DS over all code, so the " +
				"decompiler resolves DS-relative data accesses (bare offsets like " +
				"*(int *)0x8542) to real addresses.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyRelocations = options.getBoolean(OPTION_APPLY_RELOCS, applyRelocations);
		createStubXrefs = options.getBoolean(OPTION_CREATE_XREFS, createStubXrefs);
		markupHeaders = options.getBoolean(OPTION_MARKUP_HEADERS, markupHeaders);
		assumeDataSegment = options.getBoolean(OPTION_ASSUME_DS, assumeDataSegment);
	}

	// ---- Private implementation ----

	/** True if {@code program} already has blocks named the way this analyzer names its own. */
	private static boolean hasOverlayBlocks(Program program) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			String name = block.getName();
			if (name.startsWith("OVERLAY_") || name.startsWith("RTLINK_HDR_")) {
				return true;
			}
		}
		return false;
	}


	/** Establish DS if the option is on; see {@link DataSegmentAssumption}. */
	private void maybeAssumeDataSegment(Program program, MessageLog log) {
		if (assumeDataSegment) {
			DataSegmentAssumption.assume(program, log);
		}
	}

	private static long computeImageEnd(OldDOSHeader header) {
		int pages = Short.toUnsignedInt(header.e_cp());
		int lastPageBytes = Short.toUnsignedInt(header.e_cblp());
		if (pages == 0) {
			return 0;
		}
		if (lastPageBytes == 0) {
			return (long) pages * 512;
		}
		return ((long) (pages - 1)) * 512 + lastPageBytes;
	}

	private static boolean detectRTLinkOverlay(BinaryReader reader, long overlayStart,
			long fileLength) {
		if (overlayStart + RTLinkPageHeader.HEADER_SIZE > fileLength) {
			return false;
		}
		try {
			reader.setPointerIndex(overlayStart);
			RTLinkPageHeader first = RTLinkPageHeader.read(reader);
			if (!first.isValid()) {
				return false;
			}
			if (first.totalSizeBytes() > fileLength - overlayStart) {
				return false;
			}

			// A second header, chained from the first, with the same frame size: frame_size is
			// constant along the chain in every binary checked (VICEROY 0x2bc, NEBULAR 0x1fe,
			// SPHERE 0x262, RETURN 0x25a, VMEX1-3 0x262), and two such headers are far harder
			// for unrelated appended data to fake than one.
			long secondOffset = overlayStart + first.totalSizeBytes();
			if (secondOffset + RTLinkPageHeader.HEADER_SIZE > fileLength) {
				return false;
			}
			reader.setPointerIndex(secondOffset);
			RTLinkPageHeader second = RTLinkPageHeader.read(reader);
			return second.isValid() && second.frameSize() == first.frameSize();
		}
		catch (IOException _) {
			return false;
		}
	}

	/**
	 * Create an overlay memory block named {@code OVERLAY_<record>} for every overlay
	 * record with code — including record 0, which earlier revisions wrongly skipped as
	 * a non-code "global overlay table". Block numbering therefore matches the
	 * OVLSTUB_NN / RTLINK_HDR_NN record numbering.
	 */
	private List<OverlayBlockInfo> createOverlayBlocks(Program program, FileBytes fileBytes,
			List<RTLinkOverlayPage> pages, MessageLog log, TaskMonitor monitor)
			throws Exception {
		List<OverlayBlockInfo> result = new ArrayList<>();
		SegmentedAddressSpace space = X86.space(program);
		Address overlayBase = space.getAddress(overlayBaseSegment(program), 0);
		long fileSize = fileBytes.getSize();
		int width = OverlayNames.width(pages);

		for (RTLinkOverlayPage page : pages) {
			monitor.checkCancelled();

			int codeSize = page.codeSize();
			if (codeSize <= 0) {
				log.appendMsg(
					"RTLink: Overlay page " + page.pageIndex() + " has no code, skipping");
				continue;
			}

			// The final page's header-declared (paragraph-rounded) code size can run a
			// few bytes past the physical end of file, because the image is not padded
			// to a full paragraph. Clamp to the bytes actually present so block creation
			// does not read past FileBytes; parseAllPages has already refused a page
			// whose code starts at or past the end.
			long codeFileOffset = page.codeFileOffset();
			codeSize = (int) Math.min(codeSize, fileSize - codeFileOffset);

			String blockName = String.format("OVERLAY_%0" + width + "d", page.pageIndex());

			// Note the module bases known from the relocation table in the block
			// comment; CS-relative absolute offsets in module code (e.g. switch jump
			// tables) are relative to these paragraphs, not to the page start. The
			// stub scan later contributes the modules the relocation table cannot
			// name (see ModuleSegments.mergeStubBases).
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, true,
				blockName, overlayBase, fileBytes, codeFileOffset, codeSize,
				ModuleSegments.blockComment(page, page.moduleBases()), "RTLink", true, false, true, log);

			if (block != null) {
				result.add(new OverlayBlockInfo(page, block));
				RTLinkProgram.recordModuleBases(program, blockName, page.moduleBases());
			}
			else {
				log.appendMsg(
					"RTLink: Failed to create block for page " + page.pageIndex());
			}
		}

		Msg.debug(this, "RTLink/Plus: Created " + result.size() + " overlay memory blocks");
		return result;
	}

	/**
	 * Segment paragraph where the overlay blocks are based: the first 0x100-paragraph
	 * boundary past the end of the loaded image (highest base-space block). Basing the
	 * overlays above the image — instead of on top of its low segments at the old
	 * fixed 0x1000 — keeps the overlay address spaces from shadowing resident code. A
	 * list-1-relocated far call/jump in overlay code always targets the resident
	 * image (the statically encoded intra-page far calls are the list-2 sites, whose
	 * frame-relative words land inside the block itself, where overlay-space binding
	 * is correct), but the disassembler binds a flow whose flat target lies inside the
	 * instruction's own overlay space back into that space. Under the old base that
	 * planted garbage code over real page bytes: NEBULAR.EXE OVERLAY_59 held
	 * {@code CALLF 1089:01a1} (= resident 1085:01e1), which was bound to the page's
	 * own 0xa31 and collided with the genuine stub entry at 0xa2e, leaving a husk
	 * and an uncleared ERROR bookmark.
	 */
	private static int overlayBaseSegment(Program program) {
		AddressSpace base = program.getAddressFactory().getDefaultAddressSpace();
		long maxEnd = 0;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			Address end = block.getEnd();
			if (end.getAddressSpace().equals(base) && end.getOffset() > maxEnd) {
				maxEnd = end.getOffset();
			}
		}
		int segment = (int) ((maxEnd >> 4) + 1 + 0xff) & ~0xff;
		if (segment + 0x1000 > 0xffff) {
			// The image nearly fills the segmented space; fall back to the old base
			// rather than collide with the 20-bit limit. Shadowing returns, but only
			// for an image layout no RTLink binary seen so far comes close to.
			return INITIAL_SEGMENT_VAL;
		}
		return segment;
	}

	/**
	 * Sweep the stale ERROR bookmarks off the stubs this analyzer resolved, once all
	 * other analyzers are done.
	 * <p>
	 * Clearing at resolve time is not enough on a fresh import: this analyzer runs at
	 * {@code FORMAT_ANALYSIS.after()} — it has to, since it creates the overlay memory
	 * blocks everything else depends on — so it resolves each stub <em>before</em> the
	 * disassembler ever walks into it. The "Bad Instruction" marks are therefore stamped
	 * after we are finished, and are already stale the moment they are written. Removing
	 * them when analysis ends is the only point at which both facts are on the table.
	 * The resolve-time clear still matters for the retrofit/one-shot path, where the
	 * marks are already present when we run.
	 */
	@Override
	public void analysisEnded(Program program) {
		// AutoAnalysisManager calls this on every analyzer whose canAnalyze passed, enabled
		// or not, and canAnalyze accepts any segmented MZ: act only where this analyzer is
		// on and found RTLink overlays.
		if (!RTLinkProgram.isAnalyzerEnabled(program, NAME) ||
			!RTLinkProgram.isOverlayAnalyzed(program)) {
			return;
		}
		// Repair husk functions now that every function is finally in place. added() runs at
		// FORMAT_ANALYSIS.after (before the husks exist), so it can only repair them on the
		// retrofit/one-shot path; and even the dead-last flow-repair pass runs before the
		// final re-analysis round that fabricates these call-target husks (its once-per-txn
		// guard then skips its re-invocation). analysisEnded is the one hook after every
		// round. Idempotent — a no-op once no husks remain — so it is harmless on the
		// retrofit path where added() already ran it. Failures go to a throwaway log
		// because analysisEnded cannot surface the analysis warnings dialog.
		try {
			program.withTransaction("RTLink: repair husk functions",
				() -> HuskRepair.repair(program, new MessageLog(), TaskMonitor.DUMMY));
		}
		catch (CancelledException _) {
			// DUMMY monitor never cancels
		}

		if (resolvedStubBodies.isEmpty()) {
			return;
		}
		AddressSet stubs = resolvedStubBodies;
		resolvedStubBodies = new AddressSet();

		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		// Both severities are stale on a resolved stub (see DispatchStubs.clearErrorBookmarks):
		// a conflicting decode leaves an ERROR, an offset-0 stub's JMPF 0000:0000 leaves a
		// WARNING, and neither describes anything broken once the stub is a thunk.
		long stale = bookmarkMgr.getBookmarkAddresses(BookmarkType.ERROR)
				.union(bookmarkMgr.getBookmarkAddresses(BookmarkType.WARNING))
				.intersect(stubs)
				.getNumAddresses();
		if (stale == 0) {
			return;
		}
		try {
			program.withTransaction("RTLink: clear resolved-stub bad-instruction bookmarks",
				() -> {
					bookmarkMgr.removeBookmarks(stubs, BookmarkType.ERROR, TaskMonitor.DUMMY);
					bookmarkMgr.removeBookmarks(stubs, BookmarkType.WARNING, TaskMonitor.DUMMY);
				});
		}
		catch (CancelledException _) {
			return; // DUMMY monitor never cancels
		}
		Msg.info(this, "RTLink/Plus: Cleared " + stale +
			" stale Bad Instruction bookmark(s) on resolved dispatch stubs");
	}

	/**
	 * Re-run dispatch-stub discovery and thunk wiring — including resident-target
	 * trampolines — on a program whose overlays were created by a prior (possibly
	 * older) run of this analyzer, without re-importing.
	 * <p>
	 * Everything this does is idempotent: existing labels, references and functions are
	 * kept (a plain function converted to a thunk keeps its user-defined name), correct
	 * thunks are left untouched, and {@link StubThunks#create} repairs stubs that
	 * ended up as plain functions as well as overlay targets carrying a stale
	 * no-return flag (which silently truncates the decompilation of every caller of
	 * every stub forwarding to them).
	 */
	private void repairStubThunks(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			return;
		}
		FileBytes fileBytes = allFileBytes.get(0);
		try (FileBytesProvider provider = new FileBytesProvider(fileBytes)) {
			BinaryReader reader = new BinaryReader(provider, true);
			OldDOSHeader header = new OldDOSHeader(reader);
			long overlayStart = (computeImageEnd(header) + 15) & ~15L;
			List<RTLinkOverlayPage> allPages =
				RTLinkOverlayPage.parseAllPages(reader, overlayStart, fileBytes.getSize());
			if (allPages.size() < 2) {
				return;
			}

			// Rebuild the OverlayBlockInfo list from the existing blocks, mirroring
			// createOverlayBlocks()'s skip logic so stub page indexing lines up.
			Memory memory = program.getMemory();
			int width = OverlayNames.width(allPages);
			List<OverlayBlockInfo> overlayBlocks = new ArrayList<>();
			for (RTLinkOverlayPage page : allPages) {
				if (page.codeSize() <= 0) {
					continue;
				}
				MemoryBlock block =
					OverlayNames.findOverlayBlock(memory, page.pageIndex(), width);
				if (block == null) {
					// Unexpected layout (blocks renamed/removed); leave the program alone.
					return;
				}
				overlayBlocks.add(new OverlayBlockInfo(page, block));
			}

			DispatchStubs.resolve(program, overlayBlocks, resolvedStubBodies, log, monitor);
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendMsg("RTLink: stub thunk retrofit failed: " + e.getMessage());
		}
	}

	/** Type the entries of one relocation list, laid out from {@code start}. */
	private static void markupRelocations(Program program, Address start,
			List<RTLinkRelocation> relocations, TaskMonitor monitor) throws Exception {
		if (relocations.isEmpty()) {
			return;
		}
		var relocType = relocations.get(0).toDataType();
		int relocSize = relocType.getLength();
		for (int j = 0; j < relocations.size(); j++) {
			monitor.checkCancelled();
			DataUtilities.createData(program, start.add((long) j * relocSize), relocType, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
	}

	private void markupOverlayHeaders(Program program, FileBytes fileBytes,
			List<RTLinkOverlayPage> allPages, MessageLog log, TaskMonitor monitor)
			throws Exception {
		int width = OverlayNames.width(allPages);
		for (RTLinkOverlayPage page : allPages) {
			monitor.checkCancelled();

			int headerAndRelocSize = page.header().overheadSizeBytes();
			Address headerBase = AddressSpace.OTHER_SPACE.getAddress(0);
			String name = String.format("RTLINK_HDR_%0" + width + "d", page.pageIndex());

			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				name, headerBase, fileBytes, page.fileOffset(), headerAndRelocSize,
				"RTLink page " + page.pageIndex() + " header", "RTLink",
				false, false, false, log);

			if (headerBlock == null) {
				continue;
			}

			try {
				Address addr = headerBlock.getStart();
				RTLinkPageHeader header = page.header();
				DataUtilities.createData(program, addr, header.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				markupRelocations(program, addr.add(header.relocOffset()),
					page.relocations(), monitor);
				markupRelocations(program, addr.add(header.secondRelocOffset()),
					page.secondRelocations(), monitor);
				markupRelocations(program, addr.add(header.thirdRelocOffset()),
					page.thirdRelocations(), monitor);
			}
			catch (Exception _) {
				log.appendMsg(
					"RTLink: Failed to markup header for page " + page.pageIndex());
			}
		}
	}
}
