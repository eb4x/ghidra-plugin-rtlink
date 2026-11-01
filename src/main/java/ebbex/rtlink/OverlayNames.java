package ebbex.rtlink;

import java.util.List;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The record numbering in the names {@link RTLinkOverlayAnalyzer} gives its blocks and labels:
 * {@code OVERLAY_NN}, {@code RTLINK_HDR_NN}, {@code OVLSTUB_NN_OOOO} and {@code OVLNN_OOOO}.
 */
final class OverlayNames {

	/** Prefix of an overlay page's code block, {@code OVERLAY_NN}. */
	static final String BLOCK_PREFIX = "OVERLAY_";

	/** Prefix of an overlay page's header block, {@code RTLINK_HDR_NN}. */
	static final String HEADER_PREFIX = "RTLINK_HDR_";

	/** Prefix of a dispatch stub's gate label, {@code OVLSTUB_NN_OOOO}. */
	static final String STUB_PREFIX = "OVLSTUB_";

	/** Prefix of a dispatch stub's target label, {@code OVLNN_OOOO}. */
	static final String TARGET_PREFIX = "OVL";

	private OverlayNames() {
	}

	/** The code block of {@code record}: {@code OVERLAY_NN}. */
	static String blockName(int record, int width) {
		return BLOCK_PREFIX + number(record, width);
	}

	/** The header block of {@code record}: {@code RTLINK_HDR_NN}. */
	static String headerName(int record, int width) {
		return HEADER_PREFIX + number(record, width);
	}

	/** The gate label of a stub into {@code record} at {@code offset}: {@code OVLSTUB_NN_OOOO}. */
	static String stubLabel(int record, int offset, int width) {
		return STUB_PREFIX + number(record, width) + String.format("_%04X", offset);
	}

	/** The label of a stub's target in {@code record} at {@code offset}: {@code OVLNN_OOOO}. */
	static String targetLabel(int record, int offset, int width) {
		return TARGET_PREFIX + number(record, width) + String.format("_%04X", offset);
	}

	private static String number(int record, int width) {
		return String.format("%0" + width + "d", record);
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
	 * blocks and stub labels never disagree when a trailing record has no code. Every parsed
	 * page's code starts inside the file ({@link RTLinkOverlayPage#parseAllPages}).
	 */
	static int width(List<RTLinkOverlayPage> pages) {
		int max = 0;
		for (RTLinkOverlayPage page : pages) {
			if (page.codeSize() > 0) {
				max = Math.max(max, page.pageIndex());
			}
		}
		return width(max);
	}

	/** The largest record index among {@code overlayBlocks}. */
	static int maxRecordIndex(List<OverlayBlockInfo> overlayBlocks) {
		int max = 0;
		for (OverlayBlockInfo info : overlayBlocks) {
			max = Math.max(max, info.page().pageIndex());
		}
		return max;
	}

	/** The overlay block holding {@code record}'s code, or null. */
	static MemoryBlock findOverlayBlock(Memory memory, int record, int width) {
		return memory.getBlock(blockName(record, width));
	}
}
