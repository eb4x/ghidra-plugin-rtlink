package ebbex.rtlink;

import java.math.BigInteger;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

/**
 * The link-time modules inside each overlay page: their base paragraphs, recorded per block
 * from the relocation table and the dispatch stubs, and the code segment each one runs in.
 */
final class ModuleSegments {

	private ModuleSegments() {
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
	static void assign(Program program, MessageLog log) {
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
				modules += assign(context, cs, cseg, block, bases);
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

	/** Set CS (and {@code cseg}) over each module of {@code block}; returns the module count. */
	static int assign(ProgramContext context, Register cs, Register cseg, MemoryBlock block,
			List<Integer> recordedBases) throws ContextChangeException {
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
	private static SortedSet<Integer> recordedBases(Program program, MemoryBlock block,
			RTLinkOverlayPage page) {
		SortedSet<Integer> bases = new TreeSet<>(page.getModuleBases());
		List<Integer> recorded = RTLinkProgram.moduleBases(program, block);
		if (recorded != null) {
			bases.addAll(recorded);
		}
		return bases;
	}

	/** The overlay block's comment, naming {@code bases} as its module base paragraphs. */
	static String blockComment(RTLinkOverlayPage page, Collection<Integer> bases) {
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
	static void mergeStubBases(Program program, List<OverlayBlockInfo> overlayBlocks,
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
			SortedSet<Integer> merged = recordedBases(program, info.block(), info.page());
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
			Msg.info(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink/Plus: Added %d stub-only module base(s) across %d overlay page(s)",
				basesAdded, pagesExtended));
		}
	}
}
