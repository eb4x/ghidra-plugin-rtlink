package ebbex.rtlink;

import java.util.Iterator;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Buried-code repair — relocation fall-throughs.
 * <p>
 * An address carrying a loader relocation is a patched <i>operand word</i> (MZ header
 * relocations and the RTLink overlay relocations both record the 2-byte segment word itself;
 * see {@code MzLoader.processRelocations} and
 * {@code OverlayRelocations.apply}), so it can never be the first byte of
 * a real instruction. A CALL whose fall-through lands exactly on such a word therefore never
 * returns there, whatever its callee does. The corpus shape is MSC's startup error exit —
 * {@code MOV AX,0xFF; PUSH AX; PUSH CS; CALL word ptr [__exit_vector]} followed by an inline
 * {@code dw DGROUP} (VICEROY {@code 1d1d:0241}, NEBULAR {@code 1417:00fd}, SPHERE
 * {@code 160f:0109}, ROE2MAIN {@code 122e:011c}) — where the junk parsed from the relocated
 * word buries the directly-called routine that follows it. The repair: mark the call
 * {@link FlowOverride#CALL_RETURN}, clear the junk, seal the word as data so no later pass can
 * decode it again, and resurrect the referenced follower. Synthetic relocation records with a
 * nonzero type (e.g. {@code EmulatedFloatPatcher}'s rewrite audit trail, stamped at
 * instruction starts) are excluded; only type-0 segment-word relocations carry the invariant.
 */
final class RelocationFallthroughs {

	/** How far past a relocated word to look for a referenced, buried follower. */
	private static final int FOLLOWER_SCAN_LIMIT = 8;

	private RelocationFallthroughs() {
	}

	/**
	 * For every type-0 (segment word) relocation whose address is the fall-through of a CALL:
	 * override the call to {@link FlowOverride#CALL_RETURN}, clear any junk decoded from the
	 * word, drop the ERROR bookmarks confined to it, seal it as word data, and resurrect
	 * referenced code buried behind it. Returns the number repaired.
	 */
	static int repair(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		int repaired = 0;

		Iterator<Relocation> relocations = program.getRelocationTable().getRelocations();
		while (relocations.hasNext()) {
			monitor.checkCancelled();
			Relocation relocation = relocations.next();
			if (relocation.getType() != 0) {
				continue; // synthetic record (e.g. emulated-FP rewrite), not a word patch
			}
			Address word = relocation.getAddress();

			Instruction caller = callFallingThroughTo(program, word);
			if (caller == null) {
				continue;
			}
			if (listing.getDefinedDataAt(word) != null) {
				continue; // already sealed by an earlier run
			}

			// Kill the fall-through FIRST: the clear's repair step re-disassembles
			// fall-throughs into the cleared range, and must not find this one.
			caller.setFlowOverride(FlowOverride.CALL_RETURN);

			if (listing.getInstructionAt(word) != null) {
				new ClearFlowAndRepairCmd(word, false, false, true)
						.applyTo(program, monitor);
			}

			program.getBookmarkManager()
					.removeBookmarks(new AddressSet(word, word.add(1)),
						BookmarkType.ERROR, monitor);

			sealRelocationWord(program, word);
			resurrectAfterWord(program, word, monitor);
			repaired++;
		}
		return repaired;
	}

	/**
	 * The evidenced CALL instruction whose fall-through is exactly {@code word}, or
	 * null. A relocation that is the <i>operand</i> of a live instruction (a
	 * {@code CALLF} segment word, a {@code MOV AX,SEG} immediate) sits inside an
	 * instruction that starts before it, and is skipped.
	 */
	private static Instruction callFallingThroughTo(Program program, Address word) {
		Listing listing = program.getListing();
		if (CodeEvidence.splitsInstruction(program, word)) {
			return null; // operand of a live instruction
		}
		Address before = word.previous();
		if (before == null) {
			return null;
		}
		Instruction caller = listing.getInstructionContaining(before);
		if (caller == null || !caller.getFlowType().isCall()) {
			return null;
		}
		Address fallThrough = caller.getFallThrough();
		if (fallThrough == null || !fallThrough.equals(word)) {
			return null;
		}
		// The caller itself must be real code: junk callers repair nothing.
		if (program.getFunctionManager()
				.getFunctionContaining(caller.getMinAddress()) == null &&
			!CodeEvidence.isEvidenced(program, caller)) {
			return null;
		}
		return caller;
	}

	/**
	 * Define the loader-patched word as data so no later pass can ever decode junk
	 * from it again. Failure to place the data (bytes claimed by something else in
	 * the meantime) is tolerated: the {@code CALL_RETURN} override alone already
	 * removes the flow that created the junk.
	 */
	private static void sealRelocationWord(Program program, Address word) {
		try {
			DataUtilities.createData(program, word, WordDataType.dataType, 2,
				ClearDataMode.CHECK_FOR_SPACE);
			program.getListing()
					.setComment(word, CommentType.EOL,
						"Loader-relocated segment word: data, never code " +
							"(RTLink Buried Code Repair)");
		}
		catch (Exception e) {
			Msg.warn(RTLinkFlowRepairAnalyzer.class,
				"RTLink: could not seal relocated word at " + word + ": " + e.getMessage());
		}
	}

	/**
	 * Bring back the code the junk was covering. Evidence first: every
	 * flow-referenced but undefined address within {@value #FOLLOWER_SCAN_LIMIT}
	 * bytes after the word is disassembled (the corpus followers are all direct
	 * call targets — e.g. NEBULAR {@code 1417:0104}, called from {@code 1417:00b1}).
	 * When nothing is referenced and nothing is defined, fall back to the idiom: the
	 * inline word is followed by an optional single zero pad byte, then code
	 * (ROE2MAIN has no pad; the other three do).
	 */
	private static void resurrectAfterWord(Program program, Address word,
			TaskMonitor monitor) {
		Listing listing = program.getListing();
		AddressSet targets = new AddressSet();
		Address after = word.add(2);
		for (int i = 0; i < FOLLOWER_SCAN_LIMIT; i++) {
			Address candidate = after.add(i);
			if (listing.getInstructionAt(candidate) != null) {
				// Code already lives here — either it was never buried, or the clear
				// pruned it as evidenced. Nothing to disassemble, but a routine that
				// something calls still deserves to be a function.
				CodeEvidence.promoteIfCalled(program, candidate, monitor);
				return;
			}
			if (CodeEvidence.hasFlowReferenceTo(program, candidate)) {
				targets.add(candidate);
			}
		}
		if (targets.isEmpty() && listing.getUndefinedDataAt(after) != null) {
			try {
				byte pad = program.getMemory().getByte(after);
				targets.add(pad == 0 ? after.add(1) : after);
			}
			catch (MemoryAccessException _) {
				return;
			}
		}
		if (targets.isEmpty()) {
			return;
		}
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);
		for (Address target : targets.getAddresses(true)) {
			CodeEvidence.promoteIfCalled(program, target, monitor);
		}
	}
}
