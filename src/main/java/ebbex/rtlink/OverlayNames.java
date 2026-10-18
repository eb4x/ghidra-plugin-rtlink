package ebbex.rtlink;

import java.util.List;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The record numbering in the names {@link RTLinkOverlayAnalyzer} gives its blocks and labels:
 * {@code OVERLAY_NN}, {@code RTLINK_HDR_NN}, {@code OVLSTUB_NN_OOOO} and {@code OVLNN_OOOO}.
 */
final class OverlayNames {

	/** Prefix of a dispatch stub's gate label, {@code OVLSTUB_NN_OOOO}. */
	static final String STUB_PREFIX = "OVLSTUB_";

	private OverlayNames() {
	}

	/**
	 * Digit width used in OVERLAY_/RTLINK_HDR_/OVLSTUB_/OVL numbering: two, or more
	 * once a record index needs it. A fixed {@code %02d} made SPHERE.EXE (105
	 * records) collate OVERLAY_100 before OVERLAY_11 in every sorted listing.
	 */
	static int width(int maxRecordIndex) {
		return Math.max(2, String.valueOf(maxRecordIndex).length());
	}

	/**
	 * The name width for a program, from the last record that gets an overlay block — the
	 * same record {@link #maxRecordIndex} finds among the blocks, so header blocks, overlay
	 * blocks and stub labels never disagree when a trailing record has no code.
	 */
	static int width(List<RTLinkOverlayPage> pages, long fileSize) {
		int max = 0;
		for (RTLinkOverlayPage page : pages) {
			if (page.getCodeSize() > 0 && page.getCodeFileOffset() < fileSize) {
				max = Math.max(max, page.getPageIndex());
			}
		}
		return width(max);
	}

	/** The largest record index among {@code overlayBlocks}. */
	static int maxRecordIndex(List<OverlayBlockInfo> overlayBlocks) {
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
	static MemoryBlock findOverlayBlock(Memory memory, int record, int width) {
		MemoryBlock block =
			memory.getBlock(String.format("OVERLAY_%0" + width + "d", record));
		if (block == null) {
			block = memory.getBlock(String.format("OVERLAY_%02d", record));
		}
		return block;
	}
}
