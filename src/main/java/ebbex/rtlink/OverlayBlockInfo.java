package ebbex.rtlink;

import ghidra.program.model.mem.MemoryBlock;

/** An overlay page and the memory block {@link RTLinkOverlayAnalyzer} created for its code. */
record OverlayBlockInfo(RTLinkOverlayPage page, MemoryBlock block) {
}
