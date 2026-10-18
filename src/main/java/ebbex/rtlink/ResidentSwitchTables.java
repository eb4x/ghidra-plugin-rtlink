package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
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
		int segment = ((SegmentedAddress) block.getStart()).getSegment();

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

		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < entries; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				Address destination = space.getAddress(segment, offset);
				if (!block.contains(destination)) {
					return null;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * True if {@code block} is based at a paragraph that is not a 64KB-page boundary —
	 * exactly the case {@code currentCS} gets wrong. Page-aligned blocks already resolve
	 * correctly and must not be touched.
	 */
	private static boolean isUnalignedSegment(MemoryBlock block) {
		if (!(block.getStart() instanceof SegmentedAddress start)) {
			return false;
		}
		int pageSegment = (int) ((start.getOffset() >> 4) & 0xf000L);
		return start.getSegment() != pageSegment;
	}
}
