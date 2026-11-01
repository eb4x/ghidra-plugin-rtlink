package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The CS-relative switch tables of overlay pages, read relative to the base of the
 * link-time module the dispatch sits in.
 */
final class OverlaySwitchTables {

	private OverlaySwitchTables() {
	}

	/**
	 * Overlay variant of {@link ResidentSwitchTables#recover}. The dispatch's module is the
	 * one whose recorded base paragraph is nearest at or below it, ending at the next base
	 * (or the block end); the table displacement and every table entry are offsets from that
	 * base, mirroring the module's runtime CS.
	 * <p>
	 * The recorded base set is not exhaustive — a module referenced by no relocation
	 * does not appear — and a missing base would make this resolve against the previous
	 * module. Two things guard against that: an entry may not land in the middle of an
	 * existing instruction (overlay code reachable from dispatch stubs is already
	 * disassembled when this runs), and none may land inside the table's own bytes.
	 * <p>
	 * <b>What the bases do not do is bound anything.</b> They are paragraph anchors taken
	 * from relocation seg_index values and stub module words, not module boundaries, and
	 * real module content crosses them — so the <i>entries</i> are bounded by the block
	 * (NEBULAR.EXE OVERLAY_78: dispatch at 0x31a anchored at base 0x30 has its default and
	 * one case at 0x356, past the recorded anchor 0x35), and so is an <i>adjacent</i>
	 * table. A table that begins at the byte right after the dispatch — the inline form
	 * the compiler emits — <b>proves its own anchor</b>: an anchor error is a nonzero
	 * multiple of 16, so a wrong base could not have put the table there. Only a
	 * non-adjacent table, which has nothing but the anchor behind it, still has to fit in
	 * the window up to the next base.
	 * <p>
	 * That distinction is not academic: NEBULAR's OVERLAY_25 (dispatch 0x321, table 0x326,
	 * 10 entries) and OVERLAY_26 (dispatch 0xa15, table 0xa1a, 6 entries) both anchor
	 * correctly and then run a few bytes past the next anchor — 0x330 and 0xa20 — because
	 * that anchor sits inside their table. Rejecting them on it handed both to
	 * DecompilerSwitchAnalyzer, which scattered their cases across resident segments
	 * 1f95, 2078 and 2000 and left a dozen p-code errors chasing the result.
	 */
	static List<Address> recover(Program program, Instruction instruction, MemoryBlock block) {
		int displacement = CsDispatch.displacement(instruction);
		if (displacement < 0) {
			return null;
		}
		int entries = CsDispatch.entryCount(instruction, block);
		if (entries < 0) {
			return null;
		}
		List<Integer> bases = RTLinkProgram.moduleBases(program, block);
		if (bases == null) {
			return null; // no record (block predates it and no re-analysis ran) — leave alone
		}

		Address start = block.getStart();
		long blockSize = block.getEnd().subtract(start) + 1;
		long dispatchOffset = instruction.getMinAddress().subtract(start);
		long moduleStart = -1;
		long moduleEnd = blockSize;
		for (int base : bases) {
			long paragraphOffset = base * 16L;
			if (paragraphOffset <= dispatchOffset) {
				moduleStart = paragraphOffset;
			}
			else {
				moduleEnd = Math.min(paragraphOffset, blockSize);
				break;
			}
		}
		if (moduleStart < 0) {
			return null;
		}

		if ((long) displacement + 2L * entries - 1 > 0xffffL) {
			return null;
		}
		long tableOffset = moduleStart + displacement;
		long tableEnd = tableOffset + 2L * entries;
		// An adjacent table vouches for its own anchor, so the block is bound enough; a
		// table anywhere else has only the anchor behind it and must fit the module window.
		long limit = tableOffset == dispatchOffset + CsDispatch.DISPATCH_LENGTH ? blockSize
				: moduleEnd;
		if (tableEnd > limit) {
			return null;
		}
		Address table = start.add(tableOffset);

		Set<Address> destinations = new LinkedHashSet<>();
		Listing listing = program.getListing();
		try {
			for (int i = 0; i < entries; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				long destinationOffset = moduleStart + offset;
				if (destinationOffset >= blockSize) {
					return null;
				}
				if (destinationOffset >= tableOffset && destinationOffset < tableEnd) {
					return null; // a case target inside its own table: the base is wrong
				}
				Address destination = start.add(destinationOffset);
				Instruction existing = listing.getInstructionContaining(destination);
				if (existing != null && !existing.getMinAddress().equals(destination)) {
					return null; // mid-instruction target: the base resolution is wrong
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException _) {
			return null;
		}
		return new ArrayList<>(destinations);
	}
}
