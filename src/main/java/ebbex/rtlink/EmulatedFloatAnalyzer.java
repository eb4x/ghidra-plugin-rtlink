package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Rewrites the DOS floating-point emulator's {@code INT 34h}-{@code INT 3Ch} calls into the
 * x87 instructions they stand for, so 16-bit float code disassembles.
 * <p>
 * See {@link EmulatedFloatPatcher} for the encoding, the evidence for it, and why the
 * rewrite has to be driven by the disassembler rather than by a byte scan.
 * <p>
 * Each emulator call the disassembler decodes is at a real instruction boundary — flow
 * reached it — so patching it is safe, and the bytes after it, which it had been reading as
 * code, become the operands they always were. Re-disassembling from the patched site
 * resynchronizes the stream and exposes the next call, so the pass runs to a fixpoint. This
 * needs no special handling for overlay code: {@link RTLinkOverlayAnalyzer} disassembles the
 * overlay pages earlier, in {@code FORMAT_ANALYSIS}, and their instructions arrive here like
 * any others.
 */
public class EmulatedFloatAnalyzer extends AbstractAnalyzer {

	/** Comment prefix of the one ERROR bookmark that survives a successful re-disassembly. */
	private static final String REPEATED_BYTE_RUN = "Maximum run of repeated byte";

	/** Emulator calls rewritten in this program, so far, across all passes. */
	private int rewritten;

	private static final String NAME = "DOS Emulated Floating Point";
	private static final String DESCRIPTION =
		"Rewrites the Microsoft/Borland floating-point emulator's INT 34h-3Ch calls into " +
			"the x87 instructions they encode (CD 3n modrm -> 9B D8+n modrm), the same " +
			"patch the DOS runtime applies when a coprocessor is present, so the code " +
			"disassembles as floating point instead of derailing on the operand bytes.";

	public EmulatedFloatAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// As early as instructions exist: everything downstream — functions, references,
		// the decompiler — should only ever see the corrected code.
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		if (!Processor.findOrPossiblyCreateProcessor("x86").equals(processor) ||
			program.getLanguage().getLanguageDescription().getSize() != 16) {
			return false;
		}
		try {
			return EmulatedFloatPatcher.isEmulated(program, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			return false;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		// Record the verdict while the evidence still exists: the rewrite consumes the very
		// bytes the detector counts, so a later canAnalyze() — a One Shot re-run, say —
		// would otherwise find none and decline.
		EmulatedFloatPatcher.recordEmulated(program);

		// Collect first, patch second: patching clears and re-disassembles code, which
		// would invalidate a live InstructionIterator.
		List<Instruction> calls = new ArrayList<>();
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = instructions.next();
			if (EmulatedFloatPatcher.emulatorVector(insn) >= 0) {
				calls.add(insn);
			}
		}

		int patched = 0;
		for (Instruction call : calls) {
			monitor.checkCancelled();
			if (EmulatedFloatPatcher.patch(program, call, monitor)) {
				patched++;
			}
		}

		if (patched > 0) {
			rewritten += patched;
			// The re-disassembly above resynchronizes each stream, which uncovers emulator
			// calls that were previously buried inside mis-decoded operand bytes. Those
			// arrive as newly added instructions, so this analyzer runs again on them; the
			// process converges when a pass finds none.
			//
			// Msg.info, never log.appendMsg: content in the analysis MessageLog makes
			// AutoAnalysisPlugin pop a "warnings/errors issued during analysis" dialog.
			Msg.info(this, String.format(
				"Emulated FP: Rewrote %d emulator call(s) into x87 instructions", patched));
		}
		return true;
	}

	/**
	 * Sweep away the "Bad Instruction" marks that the rewrite made obsolete.
	 * <p>
	 * Every emulator call derailed the instruction stream after it, and the disassembler
	 * bookmarked what it could not decode in the wreckage. Once the call is rewritten and
	 * the stream re-disassembled, those marks describe code that no longer exists — an
	 * address now covered by a real instruction is, by definition, not a place the
	 * disassembler failed. Left behind they would swamp the genuine failures: ROE2MAIN ends
	 * with 354 marks of which only a handful are real.
	 * <p>
	 * Done at the end of analysis, for the same reason {@link RTLinkOverlayAnalyzer} does:
	 * this pass runs early, and later passes go on stamping marks of their own.
	 */
	@Override
	public void analysisEnded(Program program) {
		if (rewritten == 0) {
			return;
		}

		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();
		List<Bookmark> stale = new ArrayList<>();

		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			Bookmark bookmark = iterator.next();
			// "Maximum run of repeated byte instructions" marks a run the disassembler did
			// decode; it is a judgement about the code, not a failure to read it, so an
			// instruction being present there says nothing about whether it is still true.
			if (bookmark.getComment().startsWith(REPEATED_BYTE_RUN)) {
				continue;
			}
			if (listing.getInstructionContaining(bookmark.getAddress()) != null) {
				stale.add(bookmark);
			}
		}

		for (Bookmark bookmark : stale) {
			bookmarks.removeBookmark(bookmark);
		}
		if (!stale.isEmpty()) {
			Msg.info(this, String.format(
				"Emulated FP: Cleared %d stale Bad Instruction bookmark(s) left by the " +
					"emulator calls' mis-decode",
				stale.size()));
		}
		rewritten = 0;
	}
}
