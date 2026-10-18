package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair F — delete the instructions decoded out of zero fill.
 * <p>
 * The DGROUP data segment is mapped executable (there is code down there among the
 * data), so its zeroed regions are fair game for anything that disassembles at an
 * address it did not check — and something does: a switch's <i>default</i> case is
 * disassembled without a reference to it (see {@code DecompilerSwitchAnalysisCmd}),
 * so a garbage default target leaves a run of instructions behind that nothing
 * points at and nothing reaches. NEBULAR carries two such islands and SPHERE three,
 * dozens of {@code ADD [BX+SI],AL} apiece — the instruction {@code 00 00} decodes
 * to — running until the disassembler's repeated-byte limiter gives up and leaves
 * the ERROR mark that is the only trace of any of it.
 * <p>
 * <b>The test is on the bytes in memory, never on the instruction.</b> A {@code 00
 * 00} instruction is perfectly real: SPHERE has one inside {@code OVL023_03D4}
 * ({@code MOV SI,[BP-0x3e]; ADD [BX+SI],AL; JMP ...} — a byte store), sitting
 * between {@code 76 c4} and {@code eb c2}. What condemns an island is that it lies
 * inside a run of at least {@value #FILLER_MIN_RUN} zero bytes, which no instruction
 * stream is. Only zero is claimed: a run of {@code 0x90} is a NOP sled, which is
 * real code, and no other fill occurs here.
 * <p>
 * Even then the island is only cleared if nothing claims it: no instruction in it
 * may be referenced, be a function entry, or be fallen into from outside the island
 * — the last is what keeps this off the handler table behind a non-returning call,
 * which {@link NonReturningCalls} owns. Instructions that merely
 * <i>overlap</i> the island are left alone too: {@code MOV AX,0} is {@code b8 00
 * 00}, and two of its three bytes are zero.
 */
final class FillerIslands {

	/**
	 * The only byte that is fill by construction. A run of {@code 0x90} is a NOP sled,
	 * which is real code; zero is the only value this corpus fills with.
	 */
	static final byte FILLER_BYTE = 0x00;

	/**
	 * Zeros shorter than this are an immediate or a small field; a run this long is
	 * fill, and no instruction stream looks like it.
	 */
	static final int FILLER_MIN_RUN = 16;

	/** Bound on the walk out of an island; the real ones run to hundreds of bytes. */
	private static final int FILLER_MAX_ISLAND = 0x2000;

	private FillerIslands() {
	}

	/** Clear every unclaimed island of instructions decoded from fill; returns how many. */
	static int clear(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Set<Address> visited = new LinkedHashSet<>();
		int cleared = 0;

		for (Instruction instruction : listing.getInstructions(true)) {
			monitor.checkCancelled();
			if (visited.contains(instruction.getMinAddress()) ||
				!isFillerInstruction(instruction)) {
				continue;
			}
			AddressSetView island = fillerIsland(program, instruction.getMinAddress());
			if (island == null) {
				visited.add(instruction.getMinAddress());
				continue;
			}
			List<Instruction> junk = islandInstructions(program, island, visited);
			if (junk == null || junk.isEmpty()) {
				continue; // something claims it: not ours
			}

			AddressSet extents = new AddressSet();
			for (Instruction one : junk) {
				extents.add(one.getMinAddress(), one.getMaxAddress());
			}
			// Only the instructions, never the island: a zeroed table someone has typed
			// lives in fill too, and clearing the range would take the data with it.
			for (AddressRange range : extents.getAddressRanges()) {
				listing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);
			}
			// Bookmarks, though, are swept over the whole span the junk covered, plus
			// the byte after it. The marks do not all sit on instructions: the one for
			// the conflict between two chains decoded a byte out of phase sits in the
			// hole *between* them (NEBULAR's is at 2078:18eb, between an instruction
			// ending at 18ea and one starting at 18ec), and a clear that followed the
			// instruction extents alone would step right over it.
			AddressSet span = new AddressSet(extents.getMinAddress(), extents.getMaxAddress());
			ClearFlowAndRepairCmd.clearBadBookmarks(program, ErrorMarks.markedRange(span),
				monitor);
			cleared += junk.size();
		}
		sweepBookmarksInFill(program, monitor);
		return cleared;
	}

	/**
	 * Drop the ERROR bookmarks left standing on undefined bytes inside fill. Such a
	 * mark describes junk that no longer exists — the disassembler never takes its
	 * bookmarks back, so one survives the removal of the very instructions it was
	 * complaining about, whether this pass cleared them or an earlier run of it
	 * did. (That is not hypothetical: an already-repaired program otherwise keeps the
	 * mark for its phase break forever, because there is no longer any instruction
	 * there to sweep it alongside.)
	 */
	private static void sweepBookmarksInFill(Program program, TaskMonitor monitor)
			throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> fossils = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Bookmark bookmark = iterator.next();
			Address at = bookmark.getAddress();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				listing.getInstructionContaining(at) == null &&
				listing.getDefinedDataContaining(at) == null &&
				fillerIsland(program, at) != null) {
				fossils.add(bookmark);
			}
		}
		for (Bookmark fossil : fossils) {
			bookmarks.removeBookmark(fossil);
		}
	}

	/**
	 * The maximal run of zero bytes containing {@code seed}, or null when {@code seed} is
	 * not itself zero or that run is too short to be fill (or too long to be worth walking).
	 */
	private static AddressSetView fillerIsland(Program program, Address seed) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(seed);
		if (block == null) {
			return null;
		}
		Address low = seed;
		Address high = seed;
		try {
			if (memory.getByte(seed) != FILLER_BYTE) {
				return null; // next to fill is not in it
			}
			for (int i = 0; i < FILLER_MAX_ISLAND; i++) {
				Address previous = low.previous();
				if (previous == null || !block.contains(previous) ||
					memory.getByte(previous) != FILLER_BYTE) {
					break;
				}
				low = previous;
			}
			for (int i = 0; i < FILLER_MAX_ISLAND; i++) {
				Address next = high.next();
				if (next == null || !block.contains(next) ||
					memory.getByte(next) != FILLER_BYTE) {
					break;
				}
				high = next;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		if (high.subtract(low) + 1 < FILLER_MIN_RUN) {
			return null; // a short run of zeros is an immediate, not fill
		}
		return new AddressSet(low, high);
	}

	/**
	 * Every instruction lying wholly inside {@code island}, or null when any of them is
	 * claimed by real code — referenced, a function entry, or fallen into from outside
	 * the island. Instructions that merely straddle the island's edge are neither
	 * cleared nor held against it.
	 */
	private static List<Instruction> islandInstructions(Program program,
			AddressSetView island, Set<Address> visited) {
		Listing listing = program.getListing();
		List<Instruction> junk = new ArrayList<>();

		for (Instruction instruction : listing.getInstructions(island, true)) {
			Address start = instruction.getMinAddress();
			if (!island.contains(start) || !island.contains(instruction.getMaxAddress())) {
				continue; // straddles the edge: not decoded from fill alone
			}
			visited.add(start);
			if (CodeEvidence.isEvidenced(program, instruction)) {
				return null; // referenced, named, or a function entry: leave it be
			}
			junk.add(instruction);
		}

		for (Instruction one : junk) {
			Address fallFrom = one.getFallFrom();
			if (fallFrom == null) {
				continue;
			}
			Instruction predecessor = listing.getInstructionContaining(fallFrom);
			if (predecessor == null || !island.contains(predecessor.getMinAddress())) {
				return null; // real code runs into this: it is not ours to delete
			}
		}
		return junk;
	}

	/** True when every byte of {@code instruction} is the fill byte. */
	private static boolean isFillerInstruction(Instruction instruction) {
		byte[] bytes = X86.bytes(instruction);
		for (byte value : bytes) {
			if (value != FILLER_BYTE) {
				return false;
			}
		}
		return bytes.length > 0;
	}
}
