package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair B — conflict-bookmark arbitration.
 * <p>
 * When the disassembler cannot decode a flow target because junk already covers it, it stamps
 * an ERROR "Bad Instruction" bookmark <i>at the blocked address</i> ("Failed to disassemble at
 * X due to conflicting instruction (flow from Z)" — see {@code Disassembler.markCallConflict}).
 * For each such bookmark, if the blocked address has evidence (a flow reference, or
 * fall-through from an instruction whose fall-from chain reaches a function entry, a
 * referenced address, or a user symbol) and every conflicting instruction chain has none, the
 * junk is cleared ({@link ClearFlowAndRepairCmd}, which prunes anything with outside evidence)
 * and the blocked address disassembled. Both-sides-evidenced conflicts are declined with a
 * warning; no-evidence conflicts (e.g. disassembly islands over zeroed data, seeded refless by
 * pattern search) are left exactly as they are. On ROE2MAIN this recovers a trampoline
 * {@code CALLF} at {@code 1a5e:001c}, two overlay PUSHes at {@code OVERLAY_052::044721}, and a
 * function epilogue at {@code 122e:51be} whose bookmark names the page-segment alias
 * {@code 1000:749e} — same flat byte, which is why the moved-mark guard compares parsed
 * addresses, never strings.
 * <p>
 * Junk buried this way is known to come from passes that disassemble without leaving
 * references — {@code DecompilerSwitchAnalysisCmd} gives its default case no reference and
 * resolves decompiler-recovered flat offsets into page-segment addresses (an upstream gap,
 * noted here rather than patched: adding a default-case reference would change flow modeling
 * for every program this fork opens).
 * <p>
 * Ordering inside a repair is load-bearing, learned the hard way from
 * {@code ClearFlowAndRepairCmd.repairFallThroughsInto}: the CALL's fall-through must be
 * overridden <i>before</i> the clear (or the repair step walks backward, finds the live
 * fall-through, and regenerates the junk), and a junk instruction's unevidenced fall-from
 * chain must be cleared <i>with</i> it (or its predecessor resurrects it).
 */
final class ConflictArbitration {

	/** Backward fall-from walk bound; exhaustion counts as evidence (never clear). */
	private static final int JUNK_CHAIN_WALK_LIMIT = 64;

	private static final String FAILED_AT = "Failed to disassemble at ";

	private ConflictArbitration() {
	}

	/**
	 * Arbitrate every "Failed to disassemble ... due to conflicting instruction" bookmark: the
	 * bookmark sits at the buried address; when the buried side has evidence and the junk side
	 * has none, the junk loses. Returns the number of buried runs recovered.
	 */
	static int arbitrate(Program program, TaskMonitor monitor) throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> conflicts = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().startsWith(FAILED_AT) &&
				bookmark.getComment().contains("due to conflicting instruction")) {
				conflicts.add(bookmark);
			}
		}

		int repaired = 0;
		for (Bookmark bookmark : conflicts) {
			monitor.checkCancelled();
			Address buried = bookmark.getAddress();

			if (movedMark(program, bookmark)) {
				continue; // stamped at the flow source, not the blocked address
			}
			if (listing.getInstructionAt(buried) != null) {
				continue; // already repaired (idempotency for one-shot re-runs)
			}

			int length = pseudoLength(program, buried);
			if (length <= 0) {
				continue; // the buried bytes do not decode; nothing to arbitrate
			}

			AddressSet junkStarts = collectJunkClearStarts(program, buried, length);
			if (junkStarts == null) {
				Msg.warn(RTLinkFlowRepairAnalyzer.class,
					"RTLink: conflict at " + buried +
						" has evidence on both sides; left for manual review");
				continue;
			}
			if (junkStarts.isEmpty()) {
				continue; // no conflicting instruction found anymore
			}

			AddressSet evidence = new AddressSet();
			if (!buriedHasEvidence(program, buried, junkStarts, evidence)) {
				continue; // no evidence: leave it exactly as it is
			}

			new ClearFlowAndRepairCmd(junkStarts, evidence, false, false, true)
					.applyTo(program, monitor);
			if (listing.getInstructionAt(buried) == null) {
				new DisassembleCommand(buried, null, true).applyTo(program, monitor);
			}
			if (listing.getInstructionAt(buried) == null) {
				continue; // repair failed; the disassembler re-marks as needed
			}

			fixupAround(program, buried, evidence, monitor);
			bookmarks.removeBookmark(bookmark);
			repaired++;
		}
		return repaired;
	}

	/**
	 * Drop the conflict bookmarks whose blocked address now holds an instruction. The
	 * disassembler stamps these when it cannot decode a flow target, and never takes
	 * them back — so a mark survives its own repair, including repairs made by a pass
	 * that cleared the junk without re-marking (ROE2MAIN's {@code 122e:51be} is left
	 * that way by {@link EmulatedFloatPatcher}: the junk it complains about is long
	 * gone, and the code it blocked is recovered by {@link CodeGaps}).
	 */
	static int sweepRepaired(Program program, TaskMonitor monitor) throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> stale = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().startsWith(FAILED_AT) &&
				listing.getInstructionAt(bookmark.getAddress()) != null) {
				stale.add(bookmark);
			}
		}
		for (Bookmark bookmark : stale) {
			bookmarks.removeBookmark(bookmark);
		}
		return stale.size();
	}

	/**
	 * True when the bookmark was relocated away from the blocked address
	 * ({@code Disassembler.markInstructionError} moves marks that cannot be placed
	 * in uninitialized memory). Compared as parsed <i>addresses</i>, never strings:
	 * ROE2MAIN's bookmark at {@code 122e:51be} names {@code 1000:749e} — the same
	 * flat byte through the page segment.
	 */
	private static boolean movedMark(Program program, Bookmark bookmark) {
		String comment = bookmark.getComment();
		int start = FAILED_AT.length();
		int end = comment.indexOf(" due to ");
		if (end <= start) {
			return false; // unparseable: trust the bookmark address
		}
		Address named = program.getAddressFactory().getAddress(comment.substring(start, end));
		return named != null && !named.equals(bookmark.getAddress());
	}

	/** The decoded length of the buried instruction, or -1 if it does not decode. */
	private static int pseudoLength(Program program, Address buried) {
		try {
			// Null, not an exception, is how undecodable bytes are reported.
			PseudoInstruction decoded = new PseudoDisassembler(program).disassemble(buried);
			return decoded == null ? -1 : decoded.getLength();
		}
		catch (Exception e) {
			return -1;
		}
	}

	/**
	 * The clear seeds for the junk burying {@code buried}: the instruction covering
	 * it, every instruction starting inside its would-be extent, and each one's
	 * unevidenced fall-from chain root (a junk predecessor left alone would just
	 * fall through and resurrect the junk). Returns null when any junk instruction
	 * turns out to carry evidence of its own — that is a both-sides conflict this
	 * pass must not decide.
	 */
	private static AddressSet collectJunkClearStarts(Program program, Address buried,
			int length) {
		Listing listing = program.getListing();
		AddressSet junkStarts = new AddressSet();

		List<Instruction> conflicting = new ArrayList<>();
		Instruction covering = listing.getInstructionContaining(buried);
		if (covering != null && !covering.getMinAddress().equals(buried)) {
			conflicting.add(covering);
		}
		for (int i = 1; i < length; i++) {
			Instruction inside = listing.getInstructionAt(buried.add(i));
			if (inside != null) {
				conflicting.add(inside);
			}
		}

		for (Instruction junk : conflicting) {
			Address root = junkChainRoot(program, junk);
			if (root == null) {
				return null; // evidenced junk: both sides real, decline
			}
			junkStarts.add(root, root);
			junkStarts.add(junk.getMinAddress(), junk.getMinAddress());
		}
		return junkStarts;
	}

	/**
	 * Walk {@code junk}'s fall-from chain to its root, requiring every node to be
	 * unevidenced. Null means a node carried evidence (or the walk bound was hit,
	 * which is treated the same — never clear what cannot be proven junk).
	 */
	private static Address junkChainRoot(Program program, Instruction junk) {
		Listing listing = program.getListing();
		Instruction current = junk;
		for (int i = 0; i < JUNK_CHAIN_WALK_LIMIT; i++) {
			if (CodeEvidence.isEvidenced(program, current)) {
				return null;
			}
			Address fallFrom = current.getFallFrom();
			if (fallFrom == null) {
				return current.getMinAddress();
			}
			Instruction predecessor = listing.getInstructionContaining(fallFrom);
			if (predecessor == null) {
				return current.getMinAddress();
			}
			Address predecessorFt = predecessor.getFallThrough();
			if (predecessorFt == null ||
				!predecessorFt.equals(current.getMinAddress())) {
				return current.getMinAddress(); // not actually flowed into
			}
			current = predecessor;
		}
		return null; // bound exhausted: treat as evidenced
	}

	/**
	 * Evidence that {@code buried} is real code, collected into {@code evidence}
	 * (the protected set for the clear): a flow reference from outside the junk, or
	 * fall-through from an instruction whose own fall-from chain carries evidence.
	 */
	private static boolean buriedHasEvidence(Program program, Address buried,
			AddressSetView junkStarts, AddressSet evidence) {
		Listing listing = program.getListing();
		boolean found = false;

		for (Reference reference : program.getReferenceManager().getReferencesTo(buried)) {
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			Address from = reference.getFromAddress();
			Instruction source = listing.getInstructionContaining(from);
			if (source == null || junkStarts.contains(source.getMinAddress())) {
				continue;
			}
			evidence.add(source.getMinAddress(), source.getMaxAddress());
			found = true;
		}

		Address before = buried.previous();
		Instruction predecessor = before == null ? null : listing.getInstructionContaining(before);
		if (predecessor != null && buried.equals(predecessor.getFallThrough()) &&
			!junkStarts.contains(predecessor.getMinAddress()) &&
			evidencedThroughChain(program, predecessor)) {
			evidence.add(predecessor.getMinAddress(), predecessor.getMaxAddress());
			found = true;
		}

		if (program.getSymbolTable().isExternalEntryPoint(buried)) {
			found = true;
		}
		return found;
	}

	/** Evidence via the bounded fall-from chain: any node directly evidenced. */
	private static boolean evidencedThroughChain(Program program, Instruction instruction) {
		Listing listing = program.getListing();
		Instruction current = instruction;
		for (int i = 0; i < JUNK_CHAIN_WALK_LIMIT && current != null; i++) {
			if (CodeEvidence.isEvidenced(program, current)) {
				return true;
			}
			Address fallFrom = current.getFallFrom();
			if (fallFrom == null) {
				return false;
			}
			current = listing.getInstructionContaining(fallFrom);
		}
		return false;
	}

	/**
	 * After a successful resurrection: absorb the recovered flow into the evidence
	 * function's body, and promote the buried address to a function when something
	 * calls it directly.
	 */
	private static void fixupAround(Program program, Address buried,
			AddressSetView evidence, TaskMonitor monitor) throws CancelledException {
		CodeEvidence.promoteIfCalled(program, buried, monitor);
		if (!evidence.isEmpty()) {
			Function owner = program.getFunctionManager()
					.getFunctionContaining(evidence.getMinAddress());
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(program, program.getListing()
						.getInstructionAt(owner.getEntryPoint()), monitor);
			}
		}
	}
}
