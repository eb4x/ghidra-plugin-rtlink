package ebbex.rtlink;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The CS-relative switch tables of resident blocks whose segment is not 64KB-page aligned —
 * the case {@code currentCS} resolves against the wrong paragraph (see
 * {@link RTLinkSwitchTableAnalyzer}).
 */
final class ResidentSwitchTables {

	private ResidentSwitchTables() {
	}

	/**
	 * The table of a resident dispatch at {@code displacement}, read at the block's true
	 * paragraph, or null. Page-aligned blocks are left alone: {@code currentCS} already
	 * resolves them correctly.
	 */
	static List<Address> recover(Program program, Instruction instruction, MemoryBlock block,
			int displacement) {
		if (!isUnalignedSegment(block)) {
			return null;
		}
		int entries = CsDispatch.entryCount(instruction, block);
		if (entries < 0) {
			return null;
		}

		SegmentedAddressSpace space = X86.space(program);
		int segment = X86.segment(block); // segmented: isUnalignedSegment

		// The table and every entry must live inside the segment they are addressed from; a
		// 16-bit offset that would wrap means the guard was misread, so give up rather than
		// invent targets.
		long lastByte = (long) displacement + 2L * entries - 1;
		if (lastByte > 0xffffL) {
			return null;
		}
		Address table = space.getAddress(segment, displacement);
		if (!block.contains(table) || !block.contains(space.getAddress(segment, (int) lastByte))) {
			return null;
		}
		return CaseTable.readAll(program, table, entries, offset -> {
			Address destination = space.getAddress(segment, offset);
			return block.contains(destination) ? destination : null;
		});
	}

	/**
	 * True if {@code block} is based at a paragraph that is not a 64KB-page boundary —
	 * exactly the case {@code currentCS} gets wrong. Page-aligned blocks already resolve
	 * correctly and must not be touched.
	 */
	private static boolean isUnalignedSegment(MemoryBlock block) {
		int segment = X86.segment(block);
		return segment >= 0 && segment != X86.pageSegment(block.getStart());
	}
}
