package ebbex.rtlink;

import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;

/**
 * Apply an overlay page's segment relocations to its block, statically, the way the runtime's
 * fixup loop applies them when it loads the page.
 */
final class OverlayRelocations {

	private OverlayRelocations() {
	}

	static void apply(Program program, MemoryBlock block, RTLinkOverlayPage page,
			MessageLog log) {
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
		int loadDelta = RTLinkOverlayAnalyzer.INITIAL_SEGMENT_VAL;
		int frameDelta = (int) (blockStart.getOffset() >>> 4) & 0xffff;

		applyList(program, memory, blockStart, page.getRelocations(), loadDelta, pageDisplay,
			log);
		applyList(program, memory, blockStart, page.getSecondRelocations(), frameDelta,
			pageDisplay, log);

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
	private static void applyList(Program program, Memory memory, Address blockStart,
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
}
