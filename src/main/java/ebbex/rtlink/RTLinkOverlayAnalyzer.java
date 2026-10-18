package ebbex.rtlink;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.TransactionInfo;
import ghidra.app.util.opinion.MzLoader;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
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
 * {@link #scanForJmpfStubs} for how the two forms are told apart.
 * <p>
 * The same jump table also holds 10-byte <em>resident-target trampolines</em>:
 * {@code CALLF seg:disp} + {@code JMPF seg:off} with a real (relocated) target
 * segment. RTLink routes far calls from movable overlay code into resident code
 * through these so the overlay manager can re-vector the caller's far return
 * address if its page moves. Each one is converted into a thunk of its JMPF
 * target; see {@link #scanForResidentTrampolines} for why leaving them as plain
 * functions damages decompilation at every call site.
 */
public class RTLinkOverlayAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Overlay";
	private static final String DESCRIPTION =
		"Detects and loads RTLink/Plus overlay pages from DOS MZ executables. " +
			"Creates overlay memory blocks, applies segment relocations, and " +
			"creates cross-references from dispatch stubs to overlay functions.";
	private static final int INITIAL_SEGMENT_VAL = 0x1000;

	private static final byte OPCODE_CALLF = X86.OPCODE_CALLF;
	private static final byte OPCODE_JMPF = X86.OPCODE_JMPF;
	private static final int PAGE_ID_MASK = 0x3FFF;

	// Far calling convention (x86-16.cspec: extrapop=4, stackshift=4) stamped on every
	// stub/trampoline target so thunk call sites model the far return address and decode
	// their arguments at the correct stack offsets.
	private static final String FAR_CALLING_CONVENTION = "__cdecl16far";

	// A real overlay dispatcher is the CALLF target shared by many stubs. Any
	// physical address hit by at least this many CALLF+JMPF stub candidates is
	// treated as a dispatcher, replacing the old hardcoded 0x0DAB dispatch offset
	// so the analyzer adapts to binaries linked with the dispatcher elsewhere.
	private static final int MIN_DISPATCHER_STUB_COUNT = 4;

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
				// Retrofit the VM-runtime entry seeds too, unless the stub pass already
				// did: dispatch-stub discovery is a cheap byte scan, and everything
				// VmRuntimeSeeds does is a no-op where a prior run or hand
				// analysis already claimed the address.
				if (!repairStubThunks(program, log, monitor)) {
					VmRuntimeSeeds.seed(program, discoverDispatchers(program, monitor),
						log, monitor);
				}
			}
			assignCodeSegments(program, log);
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
			assignCodeSegments(program, log);

			if (applyRelocations && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Applying overlay relocations...");
				for (OverlayBlockInfo info : overlayBlocks) {
					monitor.checkCancelled();
					applyOverlayRelocations(program, info.block(), info.page(), log);
				}
			}

			if (createStubXrefs && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Discovering dispatch stubs...");
				discoverAndProcessStubs(program, overlayBlocks, log, monitor);
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

	private record OverlayBlockInfo(RTLinkOverlayPage page, MemoryBlock block) {
	}

	/** A resolved dispatch stub awaiting thunk creation once its target is a real function. */
	private record StubTarget(Address stubAddr, Address targetAddr, int stubSize) {
	}

	/** Prefix of a dispatch stub's gate label, {@code OVLSTUB_NN_OOOO}. */
	private static final String STUB_PREFIX = "OVLSTUB_";

	/**
	 * Digit width used in OVERLAY_/RTLINK_HDR_/OVLSTUB_/OVL numbering: two, or more
	 * once a record index needs it. A fixed {@code %02d} made SPHERE.EXE (105
	 * records) collate OVERLAY_100 before OVERLAY_11 in every sorted listing.
	 */
	private static int nameWidth(int maxRecordIndex) {
		return Math.max(2, String.valueOf(maxRecordIndex).length());
	}

	/**
	 * The name width for a program, from the last record that gets an overlay block — the
	 * same record {@link #maxRecordIndex} finds among the blocks, so header blocks, overlay
	 * blocks and stub labels never disagree when a trailing record has no code.
	 */
	private static int nameWidth(List<RTLinkOverlayPage> pages, long fileSize) {
		int max = 0;
		for (RTLinkOverlayPage page : pages) {
			if (page.getCodeSize() > 0 && page.getCodeFileOffset() < fileSize) {
				max = Math.max(max, page.getPageIndex());
			}
		}
		return nameWidth(max);
	}

	/** The largest record index among {@code overlayBlocks}. */
	private static int maxRecordIndex(List<OverlayBlockInfo> overlayBlocks) {
		int max = 0;
		for (OverlayBlockInfo info : overlayBlocks) {
			max = Math.max(max, info.page().getPageIndex());
		}
		return max;
	}

	/**
	 * The overlay block holding {@code record}'s code under the current width-padded
	 * naming, or under the fixed-{@code %02d} naming of programs imported before the
	 * width fix, or null.
	 */
	private static MemoryBlock findOverlayBlock(Memory memory, int record, int width) {
		MemoryBlock block =
			memory.getBlock(String.format("OVERLAY_%0" + width + "d", record));
		if (block == null) {
			block = memory.getBlock(String.format("OVERLAY_%02d", record));
		}
		return block;
	}

	/**
	 * Index {@code overlayBlocks} by overlay record index (= page index). Stub scans
	 * look pages up by record index rather than list position, so a record skipped for
	 * having no code cannot shift every later page onto the wrong block.
	 */
	private static Map<Integer, OverlayBlockInfo> blocksByRecord(
			List<OverlayBlockInfo> overlayBlocks) {
		Map<Integer, OverlayBlockInfo> byRecord = new HashMap<>();
		for (OverlayBlockInfo info : overlayBlocks) {
			byRecord.put(info.page().getPageIndex(), info);
		}
		return byRecord;
	}

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
			RTLinkPageHeader first = new RTLinkPageHeader(reader);
			if (!first.isValid()) {
				return false;
			}
			if (first.getTotalSizeBytes() > fileLength - overlayStart) {
				return false;
			}

			// A second header, chained from the first, with the same frame size: frame_size is
			// constant along the chain in every binary checked (VICEROY 0x2bc, NEBULAR 0x1fe,
			// SPHERE 0x262, RETURN 0x25a, VMEX1-3 0x262), and two such headers are far harder
			// for unrelated appended data to fake than one.
			long secondOffset = overlayStart + first.getTotalSizeBytes();
			if (secondOffset + RTLinkPageHeader.HEADER_SIZE > fileLength) {
				return false;
			}
			reader.setPointerIndex(secondOffset);
			RTLinkPageHeader second = new RTLinkPageHeader(reader);
			return second.isValid() && second.getFrameSize() == first.getFrameSize();
		}
		catch (IOException e) {
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
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Address overlayBase = space.getAddress(overlayBaseSegment(program), 0);
		long fileSize = fileBytes.getSize();
		int width = nameWidth(pages, fileBytes.getSize());

		for (RTLinkOverlayPage page : pages) {
			monitor.checkCancelled();

			int codeSize = page.getCodeSize();
			if (codeSize <= 0) {
				log.appendMsg(
					"RTLink: Overlay page " + page.getPageIndex() + " has no code, skipping");
				continue;
			}

			// The final page's header-declared (paragraph-rounded) code size can run a
			// few bytes past the physical end of file, because the image is not padded
			// to a full paragraph. Clamp to the bytes actually present so block creation
			// does not read past FileBytes.
			long codeFileOffset = page.getCodeFileOffset();
			long available = fileSize - codeFileOffset;
			if (available <= 0) {
				log.appendMsg("RTLink: Overlay page " + page.getPageIndex() +
					" code starts past end of file, skipping");
				continue;
			}
			if (codeSize > available) {
				codeSize = (int) available;
			}

			String blockName = String.format("OVERLAY_%0" + width + "d", page.getPageIndex());

			// Note the module bases known from the relocation table in the block
			// comment; CS-relative absolute offsets in module code (e.g. switch jump
			// tables) are relative to these paragraphs, not to the page start. The
			// stub scan later contributes the modules the relocation table cannot
			// name (see mergeStubModuleBases).
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, true,
				blockName, overlayBase, fileBytes, codeFileOffset, codeSize,
				blockComment(page, page.getModuleBases()), "RTLink", true, false, true, log);

			if (block != null) {
				result.add(new OverlayBlockInfo(page, block));
				RTLinkProgram.recordModuleBases(program, blockName, page.getModuleBases());
			}
			else {
				log.appendMsg(
					"RTLink: Failed to create block for page " + page.getPageIndex());
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
	 * Set CS over every module of every overlay block to the segment the module runs in:
	 * the block's base paragraph plus the module's base paragraph.
	 * <p>
	 * In real mode {@code currentCS} reads the CS register from context (upstream PR
	 * #9703). MzLoader sets it over each resident block but knows nothing of overlays, so
	 * without this an overlay falls back to the default CS of its 64KB page: VICEROY's
	 * {@code OVL24_0EC4} read its {@code JMP CS:[BX+0x156]} table through 0x3000 instead
	 * of the module's 0x3ae7. Runs on every pass, like the DS assumption, so a One Shot
	 * gives an already-analyzed program the context too.
	 * <p>
	 * The same value goes into the {@code cseg} context field where the language has
	 * one (the dailydriver fork, not stock Ghidra): near rel16 branches then wrap inside
	 * the module's 64KB segment instead of adding linearly. It is the Ghidra-side
	 * segment, not the runtime swap-area frame; the two differ by a constant, so the
	 * wrap boundary is the same. It only affects instructions decoded after it is set,
	 * and cannot be set over decoded code at all (see {@link #setCodeSegmentField}).
	 */
	private static void assignCodeSegments(Program program, MessageLog log) {
		Register cs = program.getLanguage().getRegister("CS");
		if (cs == null) {
			return;
		}
		Register cseg = program.getLanguage().getRegister("cseg");
		ProgramContext context = program.getProgramContext();
		int modules = 0;
		int pages = 0;
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				List<Integer> bases = RTLinkProgram.moduleBases(program, block);
				if (bases == null) {
					continue;
				}
				modules += assignCodeSegments(context, cs, cseg, block, bases);
				pages++;
			}
		}
		catch (ContextChangeException e) {
			log.appendMsg("RTLink: failed to set CS over the overlays: " + e.getMessage());
			return;
		}
		if (pages > 0) {
			Msg.info(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink/Plus: Set CS over %d overlay module(s) in %d page(s)", modules, pages));
		}
	}

	static int assignCodeSegments(ProgramContext context, Register cs, Register cseg,
			MemoryBlock block, List<Integer> recordedBases) throws ContextChangeException {
		SortedSet<Integer> bases = new TreeSet<>(recordedBases);
		bases.add(0); // the page's own start, which an early record may omit
		Address start = block.getStart();
		long frame = start.getOffset() >> 4;
		int modules = 0;
		for (int base : bases) {
			Address from = start.add(base * 16L);
			if (!block.contains(from)) {
				break;
			}
			SortedSet<Integer> later = bases.tailSet(base + 1);
			Address to = later.isEmpty() ? block.getEnd()
					: min(block.getEnd(), start.add(later.first() * 16L - 1));
			BigInteger segment = BigInteger.valueOf((frame + base) & 0xffffL);
			context.setValue(cs, from, to, segment);
			if (cseg != null) {
				setCodeSegmentField(context, cseg, from, to, segment);
			}
			modules++;
		}
		return modules;
	}

	/**
	 * Ghidra refuses a context-register write over a range that already holds instructions,
	 * and {@code cseg} is a context field (CS is not). Such a range — a module first named
	 * by the stub scan after its code was decoded, or a One Shot on an analyzed program —
	 * keeps the {@code cseg} it has. Within one page that is harmless: a page is under 64KB,
	 * so the lower module's segment gives the same near targets.
	 */
	private static void setCodeSegmentField(ProgramContext context, Register cseg,
			Address from, Address to, BigInteger segment) {
		try {
			context.setValue(cseg, from, to, segment);
		}
		catch (ContextChangeException e) {
			Msg.debug(RTLinkOverlayAnalyzer.class,
				"RTLink: cseg left as is over " + from + "-" + to + ": code already decoded");
		}
	}

	private static Address min(Address a, Address b) {
		return a.compareTo(b) <= 0 ? a : b;
	}

	/** The module bases recorded for {@code block}, plus those {@code page}'s relocations name. */
	private static SortedSet<Integer> recordedModuleBases(Program program, MemoryBlock block,
			RTLinkOverlayPage page) {
		SortedSet<Integer> bases = new TreeSet<>(page.getModuleBases());
		List<Integer> recorded = RTLinkProgram.moduleBases(program, block);
		if (recorded != null) {
			bases.addAll(recorded);
		}
		return bases;
	}

	/** The overlay block's comment, naming {@code bases} as its module base paragraphs. */
	private static String blockComment(RTLinkOverlayPage page, Collection<Integer> bases) {
		StringBuilder comment = new StringBuilder(
			String.format("RTLink/Plus overlay page %d (frame=0x%X)",
				page.getPageIndex(), page.getFrameSize()));
		if (bases.size() > 1) {
			comment.append(", module base paragraphs:");
			for (int base : bases) {
				comment.append(String.format(" 0x%X", base));
			}
		}
		return comment.toString();
	}

	/**
	 * Fold the module bases observed in the dispatch stubs into each page's recorded set.
	 * <p>
	 * A page's relocation table only names a module that some relocation is <i>sited</i>
	 * in, so a module carrying no segment fixups of its own is invisible there — yet the
	 * 14-byte stubs that call into it still spell out its base paragraph. In VICEROY.EXE
	 * this is the sole module of OVERLAY_03 (0x642) and the sixth of OVERLAY_29 (0x67);
	 * both are confirmed by the segment list, whose per-page flag word marks OVERLAY_03
	 * as multi-module even though its 652 relocations are all module 0.
	 * <p>
	 * Without this the two sets disagree and {@link RTLinkSwitchTableAnalyzer} — which
	 * anchors a CS-relative displacement to the module containing the dispatch — cannot
	 * place a switch table in such a module, so it (correctly, but needlessly) rejects it.
	 */
	private void mergeStubModuleBases(Program program, List<OverlayBlockInfo> overlayBlocks,
			Map<String, SortedSet<Integer>> stubModuleBases) {
		int pagesExtended = 0;
		int basesAdded = 0;

		for (OverlayBlockInfo info : overlayBlocks) {
			String blockName = info.block().getName();
			SortedSet<Integer> fromStubs = stubModuleBases.get(blockName);
			if (fromStubs == null) {
				continue;
			}

			// Against what is recorded, not the relocation table alone, so a re-run does
			// not count the stub-only bases an earlier run already added.
			SortedSet<Integer> merged = recordedModuleBases(program, info.block(), info.page());
			int before = merged.size();
			merged.addAll(fromStubs);
			if (merged.size() == before) {
				continue;
			}

			RTLinkProgram.recordModuleBases(program, blockName, merged);
			info.block().setComment(blockComment(info.page(), merged));
			pagesExtended++;
			basesAdded += merged.size() - before;
		}

		if (pagesExtended > 0) {
			// Msg.info only, never log.appendMsg: any content in the analysis MessageLog
			// makes AutoAnalysisPlugin pop a "warnings/errors issued during analysis"
			// dialog, and this is a clean-run success count.
			Msg.info(this, String.format(
				"RTLink/Plus: Added %d stub-only module base(s) across %d overlay page(s)",
				basesAdded, pagesExtended));
		}
	}

	static void applyOverlayRelocations(Program program, MemoryBlock block,
			RTLinkOverlayPage page, MessageLog log) {
		Memory memory = program.getMemory();
		Address blockStart = block.getStart();
		int pageDisplay = page.getPageIndex();

		// The runtime fixup loop (210d:2e59 in VICEROY.EXE) addresses each patch
		// site as (frame + seg_index):offset — page-linear seg_index*16 + offset —
		// and adds a delta to the unrelocated segment word found there, regardless of
		// seg_index. The two lists differ only in what that word points at, and hence
		// in which delta it takes.
		//
		// List 1: the word is a segment in the RESIDENT IMAGE. It takes the image load
		// delta, once. MzLoader bases the image at INITIAL_SEGMENT_VAL without setting
		// the program image base, so getImageBase() would yield 0 here.
		//
		// List 2: the word is a PAGE-RELATIVE segment — a paragraph offset within the
		// page (0 = the page's own base, or one of its module bases). Every site seen
		// is the segment word of a statically encoded intra-page far call between two
		// modules of the same page (CALLF module:offset). Verified two ways: 211 of 211
		// list-2 sites across NEBULAR, ROE2MAIN and SPHERE hold a value below their
		// page's paragraph count (list-1 sites essentially never do), and the runtime
		// list-2 fixup call (VICEROY 210d:233f; byte-identical in NEBULAR and SPHERE)
		// reads the count from header +0xA, rounds the start index up to a 4-entry
		// group exactly as RTLinkPageHeader models, and adds currentFrame -
		// previousFrame on every page move — the invariant is word = file word +
		// current frame. Statically the page's "frame" is the overlay block's own base
		// segment, so that is the delta to add here; the patched word then lands the
		// call inside its own overlay block, which is also where the disassembler
		// binds it.
		//
		// The two deltas coincided at 0x1000 before the overlays were rebased above
		// the image; they are different quantities and differ in every program now, so
		// derive each one. The block's start cannot be cast to SegmentedAddress (an
		// overlay of a segmented space hands back a GenericAddress), so take its
		// paragraph from the offset.
		int loadDelta = INITIAL_SEGMENT_VAL;
		int frameDelta = (int) (blockStart.getOffset() >>> 4) & 0xffff;

		applyRelocationList(program, memory, blockStart, page.getRelocations(), loadDelta,
			pageDisplay, log);
		applyRelocationList(program, memory, blockStart, page.getSecondRelocations(),
			frameDelta, pageDisplay, log);

		// List 3 is not applied, and that is final rather than provisional: beyond being
		// empty on every page of every binary seen, the RTLink/Plus 6.10 linker has been
		// shown by construction to be incapable of emitting one (its resident-site patch
		// path announces itself and then writes nothing — see RTLinkPageHeader's class
		// comment and ~/dosbox/RTLTEST/HANDOFF.md). A nonzero count would mean a
		// different linker version, and its sites would live in the resident image, not
		// this block, with yet another base segment.
	}

	/**
	 * Add {@code delta} to the unrelocated segment word at each of {@code relocations}'
	 * sites, and record the fixups in the relocation table.
	 */
	private static void applyRelocationList(Program program, Memory memory, Address blockStart,
			List<RTLinkRelocation> relocations, int delta, int pageDisplay, MessageLog log) {
		for (RTLinkRelocation reloc : relocations) {
			int siteOffset = reloc.getSiteOffset();

			try {
				Address relocAddr = blockStart.add(siteOffset);
				short currentValue = memory.getShort(relocAddr);
				int segmentValue = (Short.toUnsignedInt(currentValue) + delta) & 0xffff;

				memory.setShort(relocAddr, (short) segmentValue);

				program.getRelocationTable().add(relocAddr, Status.APPLIED, 0,
					new long[] { reloc.getOffset(), reloc.getSegmentIndex(), segmentValue },
					2, null);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				log.appendMsg(String.format(
					"RTLink: Failed to apply relocation at offset 0x%04X in page %d: %s",
					siteOffset, pageDisplay, e.getMessage()));
			}
		}
	}

	/** Resolve the dispatch stubs and trampolines; true if it seeded the VM runtime entries. */
	private boolean discoverAndProcessStubs(Program program,
			List<OverlayBlockInfo> overlayBlocks, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		AddressSet overlayEntryPoints = new AddressSet();
		List<StubTarget> pendingThunks = new ArrayList<>();
		Map<String, SortedSet<Integer>> stubModuleBases = new HashMap<>();

		Map<Long, Integer> dispatcherSegs = discoverDispatchers(program, monitor);
		Set<Long> dispatchers = dispatcherSegs.keySet();
		if (!dispatchers.isEmpty()) {
			Msg.debug(this, "RTLink/Plus: Discovered " + dispatchers.size() +
				" overlay dispatcher entry point(s)");
		}

		int jmpfStubs = scanForJmpfStubs(program, overlayBlocks, dispatchers,
			overlayEntryPoints, pendingThunks, stubModuleBases, log, monitor);

		// The stubs are the only place a module carrying no relocations is named, so
		// fold what they revealed into each page's module base set before the switch
		// table analyzer reads it back.
		mergeStubModuleBases(program, overlayBlocks, stubModuleBases);
		// Before anything below decodes overlay code: cseg cannot be set over it afterwards.
		assignCodeSegments(program, log);

		// Resident-target trampolines share the jump table with the CALLF+JMPF
		// dispatch stubs, so only look for them once segment-0 stubs have
		// corroborated that this binary uses that scheme (a shared CALLF+JMPF pair count
		// alone is a weaker signal when the JMPF segment is a plausible real value).
		AddressSet trampolineTargets = new AddressSet();
		List<StubTarget> pendingTrampolines = new ArrayList<>();
		int trampolines = 0;
		if (jmpfStubs > 0) {
			trampolines = scanForResidentTrampolines(program, dispatchers,
				trampolineTargets, pendingTrampolines, monitor);
		}

		int total = jmpfStubs;
		if (total == 0 && trampolines == 0) {
			log.appendMsg("RTLink: No dispatch stubs found");
			return false;
		}

		FunctionManager funcMgr = program.getFunctionManager();

		if (total > 0) {
			// Disassemble the overlay code reachable from the resolved entry points and
			// promote each entry point to a function with a real body. Without this the
			// overlay pages hold no instructions, so intra-overlay calls and jumps never
			// get references and every overlay "function" is a one-byte husk.
			disassembleOverlayCode(program, overlayBlocks, overlayEntryPoints, log, monitor);

			// Now that the overlay targets are real functions, wire each dispatch stub to
			// its target as a thunk.
			for (StubTarget stub : pendingThunks) {
				monitor.checkCancelled();
				if (createThunkAtStub(funcMgr, stub.stubAddr(), stub.targetAddr(),
					stub.stubSize(), log)) {
					clearStubErrorBookmarks(program, stub, monitor);
				}
			}
		}

		if (trampolines > 0) {
			disassembleResidentTargets(program, trampolineTargets, log, monitor);
			for (StubTarget stub : pendingTrampolines) {
				monitor.checkCancelled();
				if (createThunkAtStub(funcMgr, stub.stubAddr(), stub.targetAddr(),
					stub.stubSize(), log)) {
					clearStubErrorBookmarks(program, stub, monitor);
				}
			}
		}

		Msg.info(this, "RTLink/Plus: Resolved " + total + " dispatch stub(s) and " +
			trampolines + " resident-target trampoline(s)");

		// Only a corroborated VM-nucleus binary (real CALLF+JMPF stubs) gets its runtime
		// entry points seeded.
		if (jmpfStubs == 0) {
			return false;
		}
		VmRuntimeSeeds.seed(program, dispatcherSegs, log, monitor);
		return true;
	}

	/**
	 * Discover overlay dispatcher entry points instead of hardcoding one offset.
	 * <p>
	 * Every dispatch stub begins with {@code CALLF seg:disp} immediately followed by
	 * {@code JMPF ...}. The dispatcher is therefore the CALLF target shared by a large
	 * number of such CALLF+JMPF pairs. This scans every executable non-overlay block,
	 * tallies the physical CALLF target of each candidate pair, and returns those hit at
	 * least {@link #MIN_DISPATCHER_STUB_COUNT} times. Keying on the physical (flat)
	 * address collapses the many segment:offset aliases that resolve to one dispatcher.
	 * <p>
	 * Each dispatcher maps to its <b>stub-declared segment</b> — the CS the stubs' CALLF
	 * operands carry, i.e. the segment the VM nucleus actually runs in. That segment, not
	 * the canonical segment Ghidra happens to display a nucleus address under, is what
	 * {@link #seedVmDispatchTargets} must resolve the dispatch immediates against.
	 */
	private Map<Long, Integer> discoverDispatchers(Program program, TaskMonitor monitor)
			throws CancelledException {
		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Map<Long, Integer> counts = new HashMap<>();
		Map<Long, Integer> stubSegments = new HashMap<>();

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_CALLF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address jmpfAddr = searchAddr.add(5);
					if (CodeSeeds.isResidentCode(memory, jmpfAddr) &&
						memory.getByte(jmpfAddr) == OPCODE_JMPF) {
						int off = Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
						int seg = Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
						long target = space.getAddress(seg, off).getOffset();
						counts.merge(target, 1, Integer::sum);
						stubSegments.putIfAbsent(target, seg);
					}
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}

		Map<Long, Integer> dispatchers = new HashMap<>();
		for (Map.Entry<Long, Integer> e : counts.entrySet()) {
			if (e.getValue() >= MIN_DISPATCHER_STUB_COUNT) {
				dispatchers.put(e.getKey(), stubSegments.get(e.getKey()));
			}
		}
		return dispatchers;
	}

	/**
	 * Disassemble overlay code starting from the resolved stub entry points, following
	 * intra-page flow but staying within the overlay blocks, then create a function with
	 * a computed body at each entry point.
	 * <p>
	 * This is what makes overlay code visible to the rest of Ghidra: the disassembler
	 * creates flow references for the near calls and jumps between overlay routines (which
	 * {@code OperandReferenceAnalyzer} never creates for 16-bit spaces), and the follow-on
	 * far-call analyzer then wires overlay-to-main references.
	 */
	private void disassembleOverlayCode(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet overlayEntryPoints, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (overlayEntryPoints.isEmpty()) {
			return;
		}

		AddressSet overlayRange = new AddressSet();
		for (OverlayBlockInfo info : overlayBlocks) {
			overlayRange.add(info.block().getStart(), info.block().getEnd());
		}

		monitor.setMessage("RTLink: Disassembling overlay code...");
		DisassembleCommand disCmd =
			new DisassembleCommand(overlayEntryPoints, overlayRange, true);
		if (!disCmd.applyTo(program, monitor)) {
			log.appendMsg("RTLink: Overlay disassembly reported: " + disCmd.getStatusMsg());
		}
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating overlay functions...");
		CreateFunctionCmd funcCmd =
			new CreateFunctionCmd(overlayEntryPoints, SourceType.ANALYSIS);
		funcCmd.applyTo(program, monitor);

		CodeSeeds.verifyBecameCode(program, overlayEntryPoints, "overlay entry point", log,
			monitor);

		AddressSetView disassembled = disCmd.getDisassembledAddressSet();
		long byteCount = disassembled == null ? 0 : disassembled.getNumAddresses();
		Msg.debug(this, String.format(
			"RTLink/Plus: Disassembled %d overlay byte(s) from %d entry point(s)",
			byteCount, overlayEntryPoints.getNumAddresses()));
	}

	/**
	 * Scan for dispatch stubs by finding JMPF instructions with segment 0x0000, then
	 * validating that a CALLF to a {@link #discoverDispatchers discovered dispatcher}
	 * precedes them.
	 * <p>
	 * Stub layout (12 or 14 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo 00 00   JMPF 0000:offset
	 *   [10-11] pp pp             page_id (bits 0-13 = 1-based descriptor index)
	 *   [12-13] mm mm             module_word (14-byte form only)
	 * </pre>
	 * page_id is a 1-based descriptor index over the overlay records: page_id N targets
	 * record N - 1, so page_id 1 is record 0 — a real code page, not (as an earlier
	 * revision assumed) a non-code global table.
	 * The JMPF offset is relative to the target module's base paragraph within the
	 * page: 12-byte stubs target module 0, so it is the in-page code offset directly;
	 * 14-byte stubs carry the module's base paragraph in module_word, and the in-page
	 * code offset is JMPF offset + module_word * 16.
	 * <p>
	 * Nothing in page_id flags the stub length (bits 14-15 are always clear), so the
	 * two forms are told apart structurally: if the bytes at +12 begin another
	 * dispatcher stub (a CALLF whose target is a discovered dispatcher), the stub is
	 * 12 bytes; otherwise a word at +12 smaller than the page's total paragraph count
	 * is a module_word. The module_word cannot be validated against the page's
	 * relocation seg_index values ({@link RTLinkOverlayPage#getModuleBases()}) — a
	 * module referenced only by stubs never appears there. Every module_word observed
	 * here is collected into {@code stubModuleBases}, keyed by overlay block name, so
	 * {@link #mergeStubModuleBases} can complete each page's set with exactly those
	 * modules the relocation table cannot name.
	 */
	private int scanForJmpfStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			Set<Long> dispatchers, AddressSet overlayEntryPoints,
			List<StubTarget> pendingThunks, Map<String, SortedSet<Integer>> stubModuleBases,
			MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (overlayBlocks.isEmpty() || dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Map<Integer, OverlayBlockInfo> blocksByRecord = blocksByRecord(overlayBlocks);
		int width = nameWidth(maxRecordIndex(overlayBlocks));
		int count = 0;
		int moduleResolved = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_JMPF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					// Need 5 bytes before (CALLF) and 7 bytes after (JMPF + page_id)
					Address callfAddr = searchAddr.subtract(5);
					Address pageIdAddr = searchAddr.add(5);

					if (!CodeSeeds.isResidentCode(memory, callfAddr) ||
						!CodeSeeds.isResidentCode(memory, pageIdAddr.add(1))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetSegment =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
					if (targetSegment != 0x0000) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Validate CALLF opcode and that it targets a discovered dispatcher.
					byte callfOpcode = memory.getByte(callfAddr);
					int callfOffset =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(1)));
					int callfSegment =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(3)));
					long callfTarget = space.getAddress(callfSegment, callfOffset).getOffset();
					if (callfOpcode != OPCODE_CALLF || !dispatchers.contains(callfTarget)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int jmpfOffset =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
					int pageId = Short.toUnsignedInt(memory.getShort(pageIdAddr));
					// The stored value is a 1-based descriptor index: descriptor N is
					// overlay record N - 1, so page_id 1 targets record 0 (a real code
					// page — see the class javadoc). pageNumber is the record index,
					// shared by the OVLSTUB/OVL label convention and (since the
					// record-0 fix) the OVERLAY_NN block names.
					int descriptorIndex = pageId & PAGE_ID_MASK;
					int pageNumber = descriptorIndex - 1;

					OverlayBlockInfo target = blocksByRecord.get(pageNumber);
					if (target == null) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Distinguish the 12- and 14-byte stub forms (see the method javadoc):
					// the bytes at +12 either begin the next stub (12-byte form, module 0)
					// or hold the target module's base paragraph within the page.
					int stubSize = 12;
					int moduleBase = 0;
					Address moduleWordAddr = callfAddr.add(12);
					if (CodeSeeds.isResidentCode(memory, moduleWordAddr.add(1)) &&
						!isDispatcherCallf(memory, space, dispatchers, moduleWordAddr)) {
						int word = Short.toUnsignedInt(memory.getShort(moduleWordAddr));
						if (word < target.page().getHeader().getTotalParagraphs()) {
							stubSize = 14;
							moduleBase = word;
						}
					}
					int targetOffset = jmpfOffset + moduleBase * 16;

					Address targetAddr = target.block().getStart().add(targetOffset);

					if (!target.block().contains(targetAddr)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Only now that the stub has fully checked out is its module_word
					// trustworthy enough to record as one of the page's module bases.
					if (moduleBase != 0) {
						stubModuleBases
								.computeIfAbsent(target.block().getName(), k -> new TreeSet<>())
								.add(moduleBase);
					}

					Address stubAddr = callfAddr;
					refManager.addMemoryReference(stubAddr, targetAddr,
						RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

					CodeSeeds.label(symbolTable,
						String.format(STUB_PREFIX + "%0" + width + "d_%04X", pageNumber,
							targetOffset),
						stubAddr);
					CodeSeeds.label(symbolTable,
						String.format("OVL%0" + width + "d_%04X", pageNumber, targetOffset),
						targetAddr);

					overlayEntryPoints.add(targetAddr);
					pendingThunks.add(new StubTarget(stubAddr, targetAddr, stubSize));
					if (moduleBase != 0) {
						moduleResolved++;
					}
					count++;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}
		if (moduleResolved > 0) {
			Msg.debug(this, "RTLink/Plus: " + moduleResolved +
				" stub(s) resolved through a nonzero module base");
		}
		return count;
	}

	/**
	 * Returns true if the 5 bytes at {@code addr} form a far call to one of the
	 * discovered overlay dispatchers — i.e. the start of another dispatch stub.
	 */
	private static boolean isDispatcherCallf(Memory memory, SegmentedAddressSpace space,
			Set<Long> dispatchers, Address addr) {
		try {
			if (!CodeSeeds.isResidentCode(memory, addr) || !CodeSeeds.isResidentCode(memory, addr.add(4))) {
				return false;
			}
			if (memory.getByte(addr) != OPCODE_CALLF) {
				return false;
			}
			int off = Short.toUnsignedInt(memory.getShort(addr.add(1)));
			int seg = Short.toUnsignedInt(memory.getShort(addr.add(3)));
			return dispatchers.contains(space.getAddress(seg, off).getOffset());
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Scan for resident-target trampolines in the RTLink jump table.
	 * <p>
	 * Trampoline layout (10 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo ss ss   JMPF seg:off     (relocated resident target)
	 * </pre>
	 * RTLink routes far calls from (movable) overlay code into resident code through
	 * these shims: the dispatcher entry re-vectors the caller's far return address in
	 * case its overlay page moves, then the JMPF tail-jumps to the real function —
	 * semantically a plain far call. Trampolines are told apart from overlay dispatch
	 * stubs by the JMPF segment: dispatch stubs carry the unrelocated {@code 0000},
	 * trampolines a real segment that lands in resident executable memory.
	 * <p>
	 * Each trampoline is queued for conversion into a thunk of its JMPF target. Left
	 * as plain functions they degrade decompilation at every call site: having no RET
	 * of their own, convention analysis leaves them on the default (near) convention,
	 * parameters are modeled one stack slot too low, and every caller decompiles with
	 * a junk leading argument that swallows a real one. A thunk delegates name,
	 * signature and (far) calling convention to the target.
	 */
	private int scanForResidentTrampolines(Program program, Set<Long> dispatchers,
			AddressSet trampolineTargets, List<StubTarget> pendingThunks,
			TaskMonitor monitor) throws CancelledException {
		if (dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		int count = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_JMPF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address callfAddr = searchAddr.subtract(5);
					if (!CodeSeeds.isResidentCode(memory, callfAddr) ||
						!CodeSeeds.isResidentCode(memory, searchAddr.add(4))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetSegment =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
					if (targetSegment == 0x0000) {
						// Unrelocated segment: an overlay dispatch stub, not a
						// trampoline (handled by scanForJmpfStubs).
						searchAddr = searchAddr.add(1);
						continue;
					}

					if (!isDispatcherCallf(memory, space, dispatchers, callfAddr)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetOffset =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
					Address targetAddr = space.getAddress(targetSegment, targetOffset);

					MemoryBlock targetBlock = memory.getBlock(targetAddr);
					if (targetBlock == null || targetBlock.isOverlay() ||
						!targetBlock.isExecute() || !targetBlock.isInitialized()) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// A jump back into the trampoline's own bytes is not a trampoline.
					long delta = targetAddr.getOffset() - callfAddr.getOffset();
					if (delta >= 0 && delta < 10) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					trampolineTargets.add(targetAddr);
					pendingThunks.add(new StubTarget(callfAddr, targetAddr, 10));
					count++;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}

		if (count > 0) {
			Msg.debug(this,
				"RTLink/Plus: Found " + count + " resident-target trampoline(s)");
		}
		return count;
	}

	/**
	 * Disassemble the resident trampoline targets and promote each to a function, so
	 * {@link #createThunkAtStub} has real functions to thunk to. Many targets are
	 * reachable only through the trampolines (far calls from overlay code), so regular
	 * flow analysis alone may never get there. Targets that land inside an existing
	 * function's body are left alone here and skipped by the thunk pass.
	 */
	private void disassembleResidentTargets(Program program, AddressSet targets,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (targets.isEmpty()) {
			return;
		}

		AddressSet residentRange = new AddressSet();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isOverlay() && block.isExecute() && block.isInitialized()) {
				residentRange.add(block.getStart(), block.getEnd());
			}
		}

		monitor.setMessage("RTLink: Disassembling trampoline targets...");
		DisassembleCommand disCmd = new DisassembleCommand(targets, residentRange, true);
		if (!disCmd.applyTo(program, monitor)) {
			log.appendMsg(
				"RTLink: Trampoline target disassembly reported: " + disCmd.getStatusMsg());
		}
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating trampoline target functions...");
		CreateFunctionCmd funcCmd = new CreateFunctionCmd(targets, SourceType.ANALYSIS);
		funcCmd.applyTo(program, monitor);

		CodeSeeds.verifyBecameCode(program, targets, "trampoline target", log, monitor);
	}

	/**
	 * Wire {@code stubAddr} to {@code targetAddr} as a thunk.
	 *
	 * @return true if the stub is resolved (a thunk to its target now exists at it),
	 *         false if resolution failed or the site was skipped — the caller only
	 *         clears the stub's stale ERROR bookmarks when this returns true, so a
	 *         genuine decode failure keeps its mark.
	 */
	static boolean createThunkAtStub(FunctionManager funcMgr, Address stubAddr,
			Address targetAddr, int stubSize, MessageLog log) {
		if (!wireThunkAtStub(funcMgr, stubAddr, targetAddr, stubSize, log)) {
			return false;
		}
		showTargetName(funcMgr.getFunctionAt(stubAddr));
		return true;
	}

	/**
	 * Let a stub thunk display its target's name, so every call through the stub
	 * decompiles as a call to the overlay function rather than to the gate.
	 * <p>
	 * A thunk created over an existing label takes that label as its own name, and an
	 * explicitly named thunk prints that name at its call sites. So reset an
	 * analysis-given {@code OVLSTUB_} name to default (a default-named thunk shows its
	 * target's name, renames included). The gate name moves into the stub's plate
	 * comment: it cannot stay a symbol, because Ghidra renames a default-named function
	 * to any label created at its entry, in any namespace. A name anyone else gave the
	 * stub stays.
	 */
	private static void showTargetName(Function stub) {
		Symbol symbol = stub.getSymbol();
		String gate = symbol.getName();
		if (symbol.getSource() != SourceType.ANALYSIS || !gate.startsWith(STUB_PREFIX)) {
			return;
		}
		try {
			stub.setName(null, SourceType.DEFAULT);
			CodeUnit cu = stub.getProgram().getListing().getCodeUnitAt(stub.getEntryPoint());
			if (cu != null) {
				cu.setComment(CommentType.PLATE,
					gatePlate(gate, cu.getComment(CommentType.PLATE)));
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.warn(RTLinkOverlayAnalyzer.class,
				"RTLink: could not show the target name on stub " + gate + ": " +
					e.getMessage());
		}
	}

	/** {@code existing} plate comment plus the line naming {@code gate}, once. */
	static String gatePlate(String gate, String existing) {
		String line = "RTLink dispatch stub " + gate;
		if (existing == null || existing.isBlank()) {
			return line;
		}
		return existing.contains(line) ? existing : existing + "\n" + line;
	}

	private static boolean wireThunkAtStub(FunctionManager funcMgr, Address stubAddr,
			Address targetAddr, int stubSize, MessageLog log) {
		// A CALLF+JMPF pair inside a larger function's body is fallthrough-reachable
		// code, not a free-standing stub — the overlay manager's own code contains
		// guarded dispatcher calls (TEST flag / JNZ past / CALLF dispatcher / JMPF)
		// whose tail is byte-identical to a trampoline. Carving a thunk there would
		// split the containing function, so leave the site alone.
		Function containing = funcMgr.getFunctionContaining(stubAddr);
		if (containing != null && !containing.getEntryPoint().equals(stubAddr)) {
			Msg.debug(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink: skipping stub thunk at %s -> %s: embedded in %s at %s",
				stubAddr, targetAddr, containing.getName(), containing.getEntryPoint()));
			return false;
		}

		Function overlayFunc = funcMgr.getFunctionAt(targetAddr);
		if (overlayFunc == null) {
			Program program = funcMgr.getProgram();
			if (program.getListing().getInstructionAt(targetAddr) == null) {
				// The stub's target never became code. Creating a function anyway
				// would plant a 1-byte husk over undefined bytes -- worse than no
				// function at all, because it looks resolved to every downstream
				// consumer. Leave the stub unthunked and say so.
				log.appendMsg(String.format(
					"RTLink: no code at target %s for stub %s; stub left unthunked",
					targetAddr, stubAddr));
				return false;
			}
			// The target is code but the bulk CreateFunctionCmd did not cover it
			// (e.g. the repair path found a new stub). Create it with a real
			// flow-computed body, never a fabricated 1-byte one.
			new CreateFunctionCmd(targetAddr).applyTo(program);
			overlayFunc = funcMgr.getFunctionAt(targetAddr);
			if (overlayFunc == null) {
				log.appendMsg(String.format(
					"RTLink: could not create target function at %s for stub %s " +
						"(target is likely inside another function's body)",
					targetAddr, stubAddr));
				return false;
			}
		}

		// A thunk delegates its signature to its target, so a far call site only decodes
		// correctly when the target carries a far convention. Stamp it before wiring.
		stampFarConvention(overlayFunc, log);

		// A no-return flag on the overlay target truncates the decompilation of every
		// caller of every stub that forwards to it: stub thunks delegate hasNoReturn()
		// to their target. Ghidra's no-return discovery mis-fires on dispatch stubs
		// while overlay flow is still unresolved (the stub's JMPF 0000:offset decodes
		// as a jump into unmapped memory), and setNoReturn(true) on the stub thunk
		// lands on the overlay target. If the target's disassembled body demonstrably
		// returns, the flag is stale — clear it.
		if (overlayFunc.hasNoReturn() && bodyReturns(overlayFunc)) {
			// A repair, not a failure: Msg.info, not the analysis MessageLog.
			Msg.info(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink: clearing stale no-return flag on %s at %s (body returns)",
				overlayFunc.getName(), targetAddr));
			overlayFunc.setNoReturn(false);
		}

		Function existingStub = funcMgr.getFunctionAt(stubAddr);
		if (existingStub != null) {
			// Already the correct thunk (e.g. a re-run) — nothing to do.
			if (existingStub.isThunk() &&
				overlayFunc.equals(existingStub.getThunkedFunction(false))) {
				return true;
			}
			try {
				// Clear any no-return flag discovered while the stub was still a
				// plain function before converting it: a dispatch stub returns iff
				// its overlay target returns.
				existingStub.setNoReturn(false);
				existingStub.setThunkedFunction(overlayFunc);
				return true;
			}
			catch (IllegalArgumentException e) {
				// A plain function was already carved at the stub (auto-analysis
				// reaches it from a real CALLF before we run) and cannot be
				// converted in place. Remove it and recreate below as a thunk so
				// the stub still forwards to its overlay target.
				Msg.info(RTLinkOverlayAnalyzer.class, String.format(
					"RTLink: recreating stub thunk at %s -> %s (%s)",
					stubAddr, targetAddr, e.getMessage()));
				funcMgr.removeFunction(stubAddr);
			}
		}

		try {
			AddressSet stubBody = new AddressSet(stubAddr, stubAddr.add(stubSize - 1));
			funcMgr.createThunkFunction(null, null, stubAddr, stubBody,
				overlayFunc, SourceType.ANALYSIS);
			return true;
		}
		catch (OverlappingFunctionException e) {
			log.appendMsg(String.format(
				"RTLink: could not create stub thunk at %s -> %s: %s",
				stubAddr, targetAddr, e.getMessage()));
			return false;
		}
	}

	/**
	 * Drop the disassembler's stale ERROR bookmarks from a stub we just resolved, and
	 * remember the stub's body so {@link #analysisEnded} can sweep it again.
	 * <p>
	 * A dispatch stub's {@code JMPF 0000:offset} points into unmapped memory until the
	 * overlay manager patches it at run time, so every disassembly of the stub hits
	 * "Could not follow disassembly flow into non-existing memory" and drops an ERROR
	 * "Bad Instruction" bookmark. This analyzer relocates the page, resolves the stub
	 * and wires it to a real thunk target — which makes that mark a fossil — but nothing
	 * removed it: a fresh VICEROY.EXE import carried 540 ERROR bookmarks, every one of
	 * them on a correctly resolved stub. An error channel that is 100% false positives
	 * is worse than no channel: it is the disassembler's own record of what it could not
	 * decode, and it was reporting 540 broken things in a DB where nothing was broken.
	 * <p>
	 * Only resolved stubs are cleared and recorded. A stub whose resolution genuinely
	 * failed keeps its bookmark (and its log line), so {@code filter=error} still means
	 * something.
	 */
	private void clearStubErrorBookmarks(Program program, StubTarget stub,
			TaskMonitor monitor) throws CancelledException {
		AddressSet stubBody;
		try {
			stubBody = new AddressSet(stub.stubAddr(), stub.stubAddr().add(stub.stubSize() - 1));
		}
		catch (AddressOutOfBoundsException e) {
			// Stub body runs off the end of its block — nothing to clear.
			return;
		}
		// Clear both severities: a resolved stub whose overlay target offset is 0 carries a
		// JMPF 0000:0000 whose literal (unrelocated) operand the disassembler flags as a
		// WARNING ("flow into non-existing memory at 0000:0000"), while a conflicting decode
		// leaves an ERROR — both are stale once the stub is a thunk to its real target.
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(stubBody, BookmarkType.ERROR, monitor);
		bookmarkMgr.removeBookmarks(stubBody, BookmarkType.WARNING, monitor);
		resolvedStubBodies.add(stubBody);
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
		catch (CancelledException e) {
			// DUMMY monitor never cancels
		}

		if (resolvedStubBodies.isEmpty()) {
			return;
		}
		AddressSet stubs = resolvedStubBodies;
		resolvedStubBodies = new AddressSet();

		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		// Both severities are stale on a resolved stub (see clearStubErrorBookmarks): a
		// conflicting decode leaves an ERROR, an offset-0 stub's JMPF 0000:0000 leaves a
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
		catch (CancelledException e) {
			return; // DUMMY monitor never cancels
		}
		Msg.info(this, "RTLink/Plus: Cleared " + stale +
			" stale Bad Instruction bookmark(s) on resolved dispatch stubs");
	}

	/**
	 * Returns true if {@code func}'s disassembled body contains a return instruction —
	 * proof that a no-return flag on it is wrong.
	 */
	private static boolean bodyReturns(Function func) {
		InstructionIterator it =
			func.getProgram().getListing().getInstructions(func.getBody(), true);
		while (it.hasNext()) {
			if (it.next().getFlowType() == RefType.TERMINATOR) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Stamp {@code __cdecl16far} on a stub/trampoline target whose signature Ghidra has
	 * not yet pinned down. A thunk delegates its signature to its target, so a far call
	 * site only decodes correctly when the target carries a far convention; left on the
	 * x86-16 default (near) convention the target models its parameters one stack slot
	 * too low and every caller decompiles with a junk leading argument that swallows a
	 * real one. Every function reached through a jump-table dispatch stub or a resident
	 * trampoline is far-called by construction, so this is safe for exactly that set.
	 * User-provided signatures are never touched, and the default/unknown-convention
	 * guard makes re-runs idempotent (a second pass sees the convention already set).
	 */
	private static void stampFarConvention(Function overlayFunc, MessageLog log) {
		SourceType sigSource = overlayFunc.getSignatureSource();
		if (sigSource != SourceType.DEFAULT && sigSource != SourceType.ANALYSIS) {
			return;
		}
		String convention = overlayFunc.getCallingConventionName();
		boolean conventionUnset = overlayFunc.getCallingConvention() == null ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention);
		if (!conventionUnset) {
			return;
		}
		try {
			overlayFunc.setCallingConvention(FAR_CALLING_CONVENTION);
		}
		catch (InvalidInputException e) {
			log.appendMsg(String.format("RTLink: could not set %s on %s at %s: %s",
				FAR_CALLING_CONVENTION, overlayFunc.getName(), overlayFunc.getEntryPoint(),
				e.getMessage()));
		}
	}

	/**
	 * Re-run dispatch-stub discovery and thunk wiring — including resident-target
	 * trampolines — on a program whose overlays were created by a prior (possibly
	 * older) run of this analyzer, without re-importing.
	 * <p>
	 * Everything this does is idempotent: existing labels, references and functions are
	 * kept (a plain function converted to a thunk keeps its user-defined name), correct
	 * thunks are left untouched, and {@link #createThunkAtStub} repairs stubs that
	 * ended up as plain functions as well as overlay targets carrying a stale
	 * no-return flag (which silently truncates the decompilation of every caller of
	 * every stub forwarding to them). Returns true if that also seeded the VM runtime
	 * entries.
	 */
	private boolean repairStubThunks(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			return false;
		}
		FileBytes fileBytes = allFileBytes.get(0);
		try (FileBytesProvider provider = new FileBytesProvider(fileBytes)) {
			BinaryReader reader = new BinaryReader(provider, true);
			OldDOSHeader header = new OldDOSHeader(reader);
			long overlayStart = (computeImageEnd(header) + 15) & ~15L;
			List<RTLinkOverlayPage> allPages =
				RTLinkOverlayPage.parseAllPages(reader, overlayStart, fileBytes.getSize());
			if (allPages.size() < 2) {
				return false;
			}

			// Rebuild the OverlayBlockInfo list from the existing blocks, mirroring
			// createOverlayBlocks()'s skip logic so stub page indexing lines up.
			// Programs imported before the record-0 fix name record i's block
			// OVERLAY_(i-1) and have no block for record 0 at all. Detect that legacy
			// scheme by the absence of a block for the last code-bearing record, and
			// keep pairing each record with the block that holds its code, so One Shot
			// still repairs old DBs (whose record-0 stubs stay unresolved — resolving
			// them needs a re-import).
			Memory memory = program.getMemory();
			int lastCodeRecord = -1;
			for (RTLinkOverlayPage page : allPages) {
				if (page.getCodeSize() > 0) {
					lastCodeRecord = page.getPageIndex();
				}
			}
			int width = nameWidth(allPages, fileBytes.getSize());
			boolean legacyNames = lastCodeRecord >= 0 &&
				findOverlayBlock(memory, lastCodeRecord, width) == null;
			List<OverlayBlockInfo> overlayBlocks = new ArrayList<>();
			for (RTLinkOverlayPage page : allPages) {
				if (page.getCodeSize() <= 0) {
					continue;
				}
				int nameIndex = page.getPageIndex() - (legacyNames ? 1 : 0);
				if (nameIndex < 0) {
					continue; // legacy program: no block exists for record 0
				}
				MemoryBlock block = findOverlayBlock(memory, nameIndex, width);
				if (block == null) {
					// Unexpected layout (blocks renamed/removed); leave the program alone.
					return false;
				}
				overlayBlocks.add(new OverlayBlockInfo(page, block));
				// Retrofit the module base record onto programs imported before it
				// existed, so overlay switch-table recovery works there on re-analysis.
				// discoverAndProcessStubs() then merges in the stub-only modules.
				RTLinkProgram.recordModuleBases(program, block.getName(),
					recordedModuleBases(program, block, page));
			}

			return discoverAndProcessStubs(program, overlayBlocks, log, monitor);
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendMsg("RTLink: stub thunk retrofit failed: " + e.getMessage());
			return false;
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
		int width = nameWidth(allPages, fileBytes.getSize());
		for (RTLinkOverlayPage page : allPages) {
			monitor.checkCancelled();

			int headerAndRelocSize = page.getHeader().getOverheadSizeBytes();
			Address headerBase = AddressSpace.OTHER_SPACE.getAddress(0);
			String name = String.format("RTLINK_HDR_%0" + width + "d", page.getPageIndex());

			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				name, headerBase, fileBytes, page.getFileOffset(), headerAndRelocSize,
				"RTLink page " + page.getPageIndex() + " header", "RTLink",
				false, false, false, log);

			if (headerBlock == null) {
				continue;
			}

			try {
				Address addr = headerBlock.getStart();
				RTLinkPageHeader header = page.getHeader();
				DataUtilities.createData(program, addr, header.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				markupRelocations(program, addr.add(header.getRelocOffset()),
					page.getRelocations(), monitor);
				markupRelocations(program, addr.add(header.getSecondRelocOffset()),
					page.getSecondRelocations(), monitor);
				markupRelocations(program, addr.add(header.getThirdRelocOffset()),
					page.getThirdRelocations(), monitor);
			}
			catch (Exception e) {
				log.appendMsg(
					"RTLink: Failed to markup header for page " + page.getPageIndex());
			}
		}
	}
}
