package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Repairs <b>buried code</b>: real, evidenced instructions that stay undisassembled
 * because junk from a bad flow covers their bytes. Runs dead last, after every pass
 * that plants flows or stamps conflict bookmarks, and enforces one invariant —
 * <i>referenced code always wins over unreferenced junk</i>.
 * <p>
 * <b>Detector A — relocation fall-throughs.</b> An address carrying a loader
 * relocation is a patched <i>operand word</i> (MZ header relocations and the RTLink
 * overlay relocations both record the 2-byte segment word itself; see
 * {@code MzLoader.processRelocations} and
 * {@code RTLinkOverlayAnalyzer.applyOverlayRelocations}), so it can never be the
 * first byte of a real instruction. A CALL whose fall-through lands exactly on such
 * a word therefore never returns there, whatever its callee does. The corpus shape
 * is MSC's startup error exit — {@code MOV AX,0xFF; PUSH AX; PUSH CS;
 * CALL word ptr [__exit_vector]} followed by an inline {@code dw DGROUP} (VICEROY
 * {@code 1d1d:0241}, NEBULAR {@code 1417:00fd}, SPHERE {@code 160f:0109}, ROE2MAIN
 * {@code 122e:011c}) — where the junk parsed from the relocated word buries the
 * directly-called routine that follows it. The repair: mark the call
 * {@link FlowOverride#CALL_RETURN}, clear the junk, seal the word as data so no
 * later pass can decode it again, and resurrect the referenced follower.
 * Synthetic relocation records with a nonzero type (e.g.
 * {@code EmulatedFloatPatcher}'s rewrite audit trail, stamped at instruction
 * starts) are excluded; only type-0 segment-word relocations carry the invariant.
 * <p>
 * <b>Detector B — conflict-bookmark arbitration.</b> When the disassembler cannot
 * decode a flow target because junk already covers it, it stamps an ERROR
 * "Bad Instruction" bookmark <i>at the blocked address</i> ("Failed to disassemble
 * at X due to conflicting instruction (flow from Z)" — see
 * {@code Disassembler.markCallConflict}). For each such bookmark, if the blocked
 * address has evidence (a flow reference, or fall-through from an instruction whose
 * fall-from chain reaches a function entry, a referenced address, or a user symbol)
 * and every conflicting instruction chain has none, the junk is cleared
 * ({@link ClearFlowAndRepairCmd}, which prunes anything with outside evidence) and
 * the blocked address disassembled. Both-sides-evidenced conflicts are declined
 * with a warning; no-evidence conflicts (e.g. disassembly islands over zeroed data,
 * seeded refless by pattern search) are left exactly as they are. On ROE2MAIN this
 * recovers a trampoline {@code CALLF} at {@code 1a5e:001c}, two overlay PUSHes at
 * {@code OVERLAY_052::044721}, and a function epilogue at {@code 122e:51be} whose
 * bookmark names the page-segment alias {@code 1000:749e} — same flat byte, which
 * is why the moved-mark guard compares parsed addresses, never strings.
 * <p>
 * Junk buried this way is known to come from passes that disassemble without
 * leaving references — {@code DecompilerSwitchAnalysisCmd} gives its default case
 * no reference and resolves decompiler-recovered flat offsets into page-segment
 * addresses (an upstream gap, noted here rather than patched: adding a default-case
 * reference would change flow modeling for every program this fork opens).
 * <p>
 * Ordering inside a repair is load-bearing, learned the hard way from
 * {@code ClearFlowAndRepairCmd.repairFallThroughsInto}: the CALL's fall-through
 * must be overridden <i>before</i> the clear (or the repair step walks backward,
 * finds the live fall-through, and regenerates the junk), and a junk instruction's
 * unevidenced fall-from chain must be cleared <i>with</i> it (or its predecessor
 * resurrects it).
 */
public class RTLinkFlowRepairAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink Buried Code Repair";
	private static final String DESCRIPTION =
		"Repairs code buried under junk instructions from bad flows: removes the " +
			"impossible fall-through of calls that land on loader-relocated segment " +
			"words, and arbitrates the disassembler's conflicting-instruction " +
			"bookmarks in favor of referenced code over unreferenced junk; recovers " +
			"routines reached only through a CS:imm far pointer (interrupt hooks, " +
			"registered handlers, return vectors) and runs of routines nothing reaches. " +
			"Re-run as a one-shot to repair conflicts introduced after the initial pass.";

	/** Backward fall-from walk bound; exhaustion counts as evidence (never clear). */
	private static final int JUNK_CHAIN_WALK_LIMIT = 64;

	/** How far past a relocated word to look for a referenced, buried follower. */
	private static final int FOLLOWER_SCAN_LIMIT = 8;

	/** A gap shorter than this cannot be a routine, and a longer one is not a gap. */
	private static final int MIN_GAP_LENGTH = 2;
	private static final int MAX_GAP_LENGTH = 64;

	/** A run of whole routines may be longer; past this an undefined run is not a gap. */
	private static final int MAX_ROUTINE_RUN_LENGTH = 1024;

	/** The one-byte alignment pad MSC puts between routines to start the next on a word. */
	private static final byte NOP = (byte) 0x90;

	/** Rounds to run the gap filler for; it converges in two or three on this corpus. */
	private static final int GAP_FILL_ROUNDS = 10;

	/** How far above a gap a jump back marks the gap as a detached block of that routine. */
	private static final int DETACHED_BLOCK_REACH = 0x100;

	/** {@code JMPF CS:[disp16]} — CS prefix, opcode FF /5, mod=00 r/m=110. */
	private static final byte[] FAR_JUMP_VECTOR = { 0x2e, (byte) 0xff, 0x2e };

	/** {@code CALLF CS:[disp16]} — the same through opcode FF /3. */
	private static final byte[] FAR_CALL_VECTOR = { 0x2e, (byte) 0xff, 0x1e };

	/** How far back from an {@code INT 21h} to look for the AH it was given. */
	private static final int DOS_EXIT_SCAN_LIMIT = 4;

	/** Instructions to follow when measuring the junk behind a non-returning call. */
	private static final int MAX_JUNK_RUN = 256;

	/**
	 * The only byte that is fill by construction. A run of {@code 0x90} is a NOP sled,
	 * which is real code; zero is the only value this corpus fills with.
	 */
	private static final byte FILLER_BYTE = 0x00;

	/**
	 * Zeros shorter than this are an immediate or a small field; a run this long is
	 * fill, and no instruction stream looks like it.
	 */
	private static final int FILLER_MIN_RUN = 16;

	/** Bound on the walk out of an island; the real ones run to hundreds of bytes. */
	private static final int FILLER_MAX_ISLAND = 0x2000;

	private long lastTxId = -1;

	public RTLinkFlowRepairAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Dead last: every pass that disassembles, plants flows or stamps conflict
		// bookmarks — including DecompilerSwitchAnalyzer at CODE_ANALYSIS and all
		// four RTLink analyzers — has finished its first wave by then.
		setPriority(AnalysisPriority.LOW_PRIORITY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		if (!RTLinkOverlayAnalyzer.isOverlayAnalyzed(program)) {
			return false; // canAnalyze accepts any segmented MZ; these repairs are RTLink's
		}
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			return true; // our own repairs re-trigger byte analysis; run once per txn
		}
		lastTxId = txId;

		int fallthroughs = repairRelocationFallthroughs(program, monitor);
		int vectors = resolveFarVectorFlows(program, monitor);
		fallthroughs += sealCallsThatCannotReturn(program, monitor);
		// After E, never before it: the junk table behind a non-returning call is
		// fallen into (from the call), so F would refuse to touch it. E removes the
		// cause; F only clears islands that never had one.
		int filler = clearFillerIslands(program, monitor);
		int conflicts = arbitrateConflictBookmarks(program, monitor);

		// Filling a gap creates a function, and a function is what identifies the
		// stranded epilogue of the routine above it — so each round exposes the next. A
		// routine reached through a far pointer brings its own calls and pointers along.
		// Run to a fixpoint rather than leaving code for a second invocation to find.
		int gaps = 0;
		int pointed = 0;
		for (int round = 0; round < GAP_FILL_ROUNDS; round++) {
			int claimed = FarCodePointers.recover(program, monitor);
			int filled = fillCodeGaps(program, monitor);
			if (claimed + filled == 0) {
				break;
			}
			pointed += claimed;
			gaps += filled;
		}
		// Last: a conflict mark whose blocked address now holds code is a fossil,
		// whether this analyzer cleared the junk or an earlier pass already had.
		sweepRepairedConflictBookmarks(program, monitor);

		// Msg.info only — content in the MessageLog pops the analysis warnings dialog.
		if (vectors > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Followed %d far jump(s)/call(s) through a code-segment vector",
				vectors));
		}
		if (fallthroughs > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Sealed %d fall-through(s) behind non-returning calls",
				fallthroughs));
		}
		if (conflicts > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Recovered %d buried instruction run(s) from junk conflicts",
				conflicts));
		}
		if (pointed > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Recovered %d routine(s) reached through a CS:imm far pointer",
				pointed));
		}
		if (gaps > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Disassembled %d unreached code gap(s) between routines", gaps));
		}
		if (filler > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Cleared %d instruction(s) decoded from zero fill", filler));
		}
		return true;
	}

	/**
	 * Detector A. For every type-0 (segment word) relocation whose address is the
	 * fall-through of a CALL: override the call to {@link FlowOverride#CALL_RETURN},
	 * clear any junk decoded from the word, drop the ERROR bookmarks confined to it,
	 * seal it as word data, and resurrect referenced code buried behind it.
	 */
	static int repairRelocationFallthroughs(Program program, TaskMonitor monitor)
			throws CancelledException {
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
		Instruction covering = listing.getInstructionContaining(word);
		if (covering != null && !covering.getMinAddress().equals(word)) {
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
			!isEvidencedInstruction(program, caller)) {
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
					.setComment(word, CodeUnit.EOL_COMMENT,
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
				promoteIfCalled(program, candidate, monitor);
				return;
			}
			if (hasFlowReferenceTo(program, candidate)) {
				targets.add(candidate);
			}
		}
		if (targets.isEmpty() && listing.getUndefinedDataAt(after) != null) {
			try {
				byte pad = program.getMemory().getByte(after);
				targets.add(pad == 0 ? after.add(1) : after);
			}
			catch (MemoryAccessException e) {
				return;
			}
		}
		if (targets.isEmpty()) {
			return;
		}
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);
		for (Address target : targets.getAddresses(true)) {
			promoteIfCalled(program, target, monitor);
		}
	}

	/**
	 * Detector D. Follow the far jumps and calls that go through a vector in the code
	 * segment — {@code JMPF CS:[imm16]} and {@code CALLF CS:[imm16]}.
	 * <p>
	 * Ghidra will not follow an indirect far flow, so whatever it lands on is never
	 * disassembled and, having no reference, is never found by anything else either.
	 * The vendor driver every binary in this corpus links does exactly this: its fatal
	 * error handler is reached only through {@code JMPF CS:[0x656]}, and the vector is
	 * a plain far pointer sitting initialized in the image (VICEROY {@code 275d:0656}
	 * → {@code 275d:0660}). Eighty-three bytes of real code — redirect stdout to
	 * stderr, print the message, wait for a key, {@code MOV AX,0x4C01; INT 21h} — that
	 * no pass had ever decoded.
	 * <p>
	 * The vector is only followed when its four bytes are initialized and point into
	 * mapped executable memory. A zero (or unrelocated) vector is patched at runtime
	 * and resolves to nothing here — that is the RTLink dispatch-stub form, and it
	 * belongs to {@link RTLinkOverlayAnalyzer}.
	 */
	static int resolveFarVectorFlows(Program program, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		ReferenceManager references = program.getReferenceManager();
		AddressSet targets = new AddressSet();
		int resolved = 0;

		for (Instruction instruction : listing.getInstructions(true)) {
			monitor.checkCancelled();
			boolean isCall = matchesBytes(instruction, FAR_CALL_VECTOR);
			if (!isCall && !matchesBytes(instruction, FAR_JUMP_VECTOR)) {
				continue;
			}
			Address target = farPointerAt(program, instruction, vectorOffset(instruction));
			if (target == null) {
				continue;
			}
			// Since GP-7349 Ghidra resolves the vector itself and plants the reference, but
			// a target only that reference reaches may still be undecoded: done means both.
			boolean referenced = hasReferenceTo(instruction, target);
			boolean decoded = listing.getInstructionAt(target) != null;
			if (referenced && decoded) {
				continue; // idempotent for one-shot re-runs
			}
			if (!referenced) {
				references.addMemoryReference(instruction.getMinAddress(), target,
					isCall ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP, SourceType.ANALYSIS,
					Reference.MNEMONIC);
			}
			if (!decoded) {
				targets.add(target);
			}
			resolved++;
		}

		if (!targets.isEmpty()) {
			new DisassembleCommand(targets, null, true).applyTo(program, monitor);
			for (Address target : targets.getAddresses(true)) {
				monitor.checkCancelled();
				if (listing.getInstructionAt(target) != null &&
					program.getFunctionManager().getFunctionContaining(target) == null) {
					new CreateFunctionCmd(target).applyTo(program, monitor);
				}
			}
		}
		return resolved;
	}

	/** The {@code disp16} of a {@code JMPF/CALLF CS:[imm16]}, read from its bytes. */
	private static int vectorOffset(Instruction instruction) {
		try {
			byte[] bytes = instruction.getBytes();
			return (bytes[3] & 0xff) | ((bytes[4] & 0xff) << 8);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/**
	 * The {@code seg:off} far pointer stored at {@code CS:offset}, or null when it is
	 * not initialized, not mapped, or does not point at executable memory.
	 */
	private static Address farPointerAt(Program program, Instruction instruction, int offset) {
		if (offset < 0 || !(instruction.getMinAddress() instanceof SegmentedAddress at)) {
			return null;
		}
		SegmentedAddressSpace space = (SegmentedAddressSpace) at.getAddressSpace();
		Address vector = space.getAddress(at.getSegment(), offset);
		MemoryBlock block = program.getMemory().getBlock(vector);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		try {
			int pointerOffset = program.getMemory().getShort(vector) & 0xffff;
			int pointerSegment = program.getMemory().getShort(vector.add(2)) & 0xffff;
			if (pointerSegment == 0) {
				return null; // unrelocated: patched at runtime, not ours to follow
			}
			Address target = space.getAddress(pointerSegment, pointerOffset);
			MemoryBlock targetBlock = program.getMemory().getBlock(target);
			if (targetBlock == null || !targetBlock.isExecute() ||
				!targetBlock.isInitialized()) {
				return null;
			}
			return target;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Detector E. A call to a routine that terminates the program cannot return, so
	 * the bytes after it are not code.
	 * <p>
	 * The corpus shape is the vendor driver's handler-registration routine: its table
	 * is full, so it aborts — {@code PUSH CS; CALL abort}, where {@code abort} sets up
	 * a message and tail-jumps (through the vector {@link #resolveFarVectorFlows} has
	 * just followed) into a handler ending in {@code MOV AX,0x4C01; INT 21h}. DOS
	 * function {@code 4Ch} does not come back. What sits after that call is the
	 * handler table itself — sixty-odd zero bytes the disassembler decodes until its
	 * repeated-byte limiter gives up, leaving the one benign-looking ERROR bookmark
	 * each binary used to carry.
	 * <p>
	 * Non-return is established, never guessed: a function qualifies only if it
	 * contains no return instruction at all, and every one of its terminal
	 * instructions is either the DOS-exit idiom or a jump into another function that
	 * qualifies (a fixpoint, so a tail-jump chain is followed). Everything else is
	 * assumed to return.
	 */
	static int sealCallsThatCannotReturn(Program program, TaskMonitor monitor)
			throws CancelledException {
		markDosExits(program, monitor);
		Set<Function> terminating = terminatingFunctions(program, monitor);
		if (terminating.isEmpty()) {
			return 0;
		}
		Listing listing = program.getListing();
		int sealed = 0;

		for (Function function : terminating) {
			monitor.checkCancelled();
			if (!function.hasNoReturn()) {
				function.setNoReturn(true);
			}
			for (Reference reference : program.getReferenceManager()
					.getReferencesTo(function.getEntryPoint())) {
				monitor.checkCancelled();
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Instruction call = listing.getInstructionAt(reference.getFromAddress());
				if (call == null || call.getFlowOverride() == FlowOverride.CALL_RETURN ||
					call.getFallThrough() == null) {
					continue;
				}
				Address fallThrough = call.getFallThrough();
				AddressSetView junk = fallThroughRun(program, fallThrough);
				call.setFlowOverride(FlowOverride.CALL_RETURN);

				// Clear the junk outright rather than through ClearFlowAndRepairCmd:
				// that command spares any block something references, and this junk is
				// referenced — the bytes behind the driver's abort are its handler
				// table, and constant propagation has (rightly) resolved the routine's
				// own CS:[BX] loads onto them. Those data references are the very
				// evidence that the bytes are not code. The call cannot return here, so
				// nothing decoded from here is an instruction; the walk stops at the
				// first address anything actually flows to, so real code is never taken.
				if (!junk.isEmpty()) {
					listing.clearCodeUnits(junk.getMinAddress(), junk.getMaxAddress(),
						false);
					ClearFlowAndRepairCmd.clearBadBookmarks(program, markedRange(junk),
						monitor);
				}
				sealed++;
			}
		}
		return sealed;
	}

	/**
	 * Tell Ghidra what DOS already knows: {@code INT 21h} with {@code AH = 4Ch}
	 * terminates the process, so nothing follows it.
	 * <p>
	 * Left unmarked, the exit is just another instruction with a fall-through, and
	 * whatever bytes come after it are pulled into the routine that exits. That is how
	 * ROE2MAIN's fatal handler came to swallow the routine below it — a body of 123
	 * bytes where VICEROY's, whose successor was already a function, is 83 — and the
	 * stray {@code RETF} it thereby contained was enough to make the handler look like
	 * it returns. Overriding the flow to a terminator fixes the bodies, and with them
	 * everything downstream that reasons about what a routine does at its end.
	 */
	private static void markDosExits(Program program, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Instruction> exits = new ArrayList<>();
		for (Instruction instruction : listing.getInstructions(true)) {
			monitor.checkCancelled();
			if (instruction.getFlowOverride() == FlowOverride.NONE &&
				isDosExit(program, instruction)) {
				exits.add(instruction);
			}
		}
		for (Instruction exit : exits) {
			monitor.checkCancelled();
			Address after = exit.getMaxAddress().next();
			exit.setFlowOverride(FlowOverride.RETURN);
			Function owner =
				program.getFunctionManager().getFunctionContaining(exit.getMinAddress());
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(program,
					listing.getInstructionAt(owner.getEntryPoint()), monitor);
			}
			if (after != null) {
				dropFallThroughMarks(program, after);
			}
		}
	}

	/**
	 * Drop the disassembler's ERROR marks at {@code after}, the address an exit used to fall
	 * into, once nothing flows there any more. Where the bytes after the exit are already
	 * data when disassembly reaches them — the smoke sample's abort vector, typed as a
	 * pointer as soon as the indirect {@code JMPF CS:[vector]} above reads it (GP-7349) — the
	 * fall-through left "Failed to disassemble … due to conflicting data" there, which the
	 * exit, now terminal, no longer explains.
	 */
	private static void dropFallThroughMarks(Program program, Address after) {
		for (Reference reference : program.getReferenceManager().getReferencesTo(after)) {
			if (reference.getReferenceType().isFlow()) {
				return;
			}
		}
		Instruction above = program.getListing().getInstructionContaining(after.previous());
		if (above != null && after.equals(above.getFallThrough())) {
			return;
		}
		BookmarkManager bookmarks = program.getBookmarkManager();
		for (Bookmark bookmark : bookmarks.getBookmarks(after, BookmarkType.ERROR)) {
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory())) {
				bookmarks.removeBookmark(bookmark);
			}
		}
	}

	/**
	 * The run of instructions the disassembler decoded straight through from
	 * {@code start}, plus the byte after it — where a run it abandoned (a long stretch
	 * of one repeated byte, say) leaves its ERROR mark.
	 */
	private static AddressSetView fallThroughRun(Program program, Address start) {
		AddressSet run = new AddressSet();
		Listing listing = program.getListing();
		Address at = start;
		for (int i = 0; i < MAX_JUNK_RUN && at != null; i++) {
			Instruction instruction = listing.getInstructionAt(at);
			if (instruction == null) {
				break;
			}
			if (!at.equals(start) && isEvidencedInstruction(program, instruction)) {
				break; // something really flows here: the run has left the junk
			}
			run.add(instruction.getMinAddress(), instruction.getMaxAddress());
			at = instruction.getFallThrough();
		}
		return run;
	}

	/**
	 * The junk's addresses plus the byte after it: a run the disassembler abandoned
	 * leaves its ERROR mark one past the last instruction it managed to decode, so the
	 * mark lies just outside the junk itself. Only the bookmark sweep may reach that
	 * byte — clearing it would take the next real instruction with it.
	 */
	private static AddressSetView markedRange(AddressSetView junk) {
		AddressSet marked = new AddressSet(junk);
		Address after = junk.getMaxAddress().next();
		if (after != null) {
			marked.add(after, after);
		}
		return marked;
	}

	/**
	 * The functions that never return: those with no return instruction whose every
	 * terminal path exits through DOS {@code INT 21h/4Ch}, directly or by tail-jumping
	 * into another such function.
	 */
	private static Set<Function> terminatingFunctions(Program program, TaskMonitor monitor)
			throws CancelledException {
		Set<Function> terminating = new LinkedHashSet<>();
		boolean grew = true;
		while (grew) {
			grew = false;
			for (Function function : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				if (terminating.contains(function) || function.isThunk()) {
					continue;
				}
				if (isTerminating(program, function, terminating)) {
					terminating.add(function);
					grew = true;
				}
			}
		}
		return terminating;
	}

	/**
	 * True when {@code function} has no return instruction and each of its terminal
	 * instructions either is the DOS exit idiom or jumps into a function already known
	 * to terminate.
	 * <p>
	 * That verdict is only as good as the body is complete, so every way out of the body
	 * is accounted for: a fall-through or a conditional branch that leaves it — a body cut
	 * short by a disassembly conflict, or a branch to a shared return in another routine —
	 * is a path this test cannot see the end of, and the routine is assumed to return.
	 */
	private static boolean isTerminating(Program program, Function function,
			Set<Function> terminating) {
		Listing listing = program.getListing();
		AddressSetView body = function.getBody();
		InstructionIterator instructions = listing.getInstructions(body, true);
		boolean sawTerminalPath = false;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			FlowType flow = instruction.getFlowType();
			if (isDosExit(program, instruction)) {
				sawTerminalPath = true;
				continue;
			}
			// An unconditional jump is a tail call, and it is recognized by the
			// instruction rather than by its flow type: once Ghidra's shared-return pass
			// has been over a tail jump it carries a CALL flow override, and the flow
			// type then describes what Ghidra made of it, not what the code does.
			String mnemonic = instruction.getMnemonicString();
			boolean tailCall = "JMP".equals(mnemonic) || "JMPF".equals(mnemonic);
			if (flow.isTerminal() && !tailCall) {
				return false; // a return: it comes back
			}
			if (!tailCall) {
				if (leavesBody(program, instruction, body, terminating)) {
					return false;
				}
				continue; // an ordinary call or a branch within the routine: not an exit
			}
			// A tail call terminates only if what it lands in does. Destinations come
			// from the references, not from getFlows(): the same override that hides the
			// jump's nature also empties its flow list.
			Set<Address> destinations = jumpDestinations(program, instruction);
			if (destinations.isEmpty()) {
				return false; // where it goes is unknown: assume it comes back
			}
			for (Address destination : destinations) {
				if (function.getBody().contains(destination)) {
					continue; // a jump inside the routine — a loop, not an exit
				}
				Function target = program.getFunctionManager().getFunctionAt(destination);
				if (target == null || !terminating.contains(target)) {
					return false;
				}
				sawTerminalPath = true;
			}
		}
		return sawTerminalPath;
	}

	/**
	 * True if {@code instruction}, which is neither a return nor a tail jump, can continue
	 * outside {@code body}: its fall-through lands outside it, or a conditional branch goes
	 * somewhere other than the body or a function known to terminate.
	 */
	private static boolean leavesBody(Program program, Instruction instruction,
			AddressSetView body, Set<Function> terminating) {
		Address fallThrough = instruction.getFallThrough();
		if (fallThrough != null && !body.contains(fallThrough)) {
			return true;
		}
		if (!instruction.getFlowType().isConditional() || !instruction.getFlowType().isJump()) {
			return false;
		}
		for (Address destination : instruction.getFlows()) {
			if (body.contains(destination)) {
				continue;
			}
			Function target = program.getFunctionManager().getFunctionAt(destination);
			if (target == null || !terminating.contains(target)) {
				return true;
			}
		}
		return false;
	}

	/** Where an unconditional jump goes, however its reference happens to be typed. */
	private static Set<Address> jumpDestinations(Program program, Instruction instruction) {
		Set<Address> destinations = new LinkedHashSet<>();
		for (Address flow : instruction.getFlows()) {
			destinations.add(flow);
		}
		for (Reference reference : program.getReferenceManager()
				.getReferencesFrom(instruction.getMinAddress())) {
			RefType type = reference.getReferenceType();
			if (type.isCall() || type.isJump()) {
				destinations.add(reference.getToAddress());
			}
		}
		return destinations;
	}

	/**
	 * True for {@code INT 21h} whose {@code AH} is provably {@code 4Ch} — the DOS
	 * terminate-process call, loaded as {@code MOV AH,4Ch} ({@code B4 4C}) or
	 * {@code MOV AX,4Cxx} ({@code B8 xx 4C}).
	 * <p>
	 * A wrong verdict is never revisited and seals every caller's fall-through, so this
	 * proves rather than guesses. It walks back along the fall-through chain only — never
	 * into the routine above — and gives up where another path joins (a flow reference to
	 * any instruction after the load) or where anything else writes {@code AH}, whatever the
	 * form ({@code MOV AH,[mem]}, {@code POP AX}, {@code XOR AX,AX}). A write to {@code AL}
	 * alone leaves {@code AH} intact and is stepped over. The test is on the bytes, not on
	 * the operands Ghidra happens to display.
	 */
	private static boolean isDosExit(Program program, Instruction instruction) {
		if (!hasBytes(instruction, 0xcd, 0x21)) {
			return false;
		}
		Register ah = program.getRegister("AH");
		Instruction at = instruction;
		for (int i = 0; i < DOS_EXIT_SCAN_LIMIT; i++) {
			if (hasFlowReferenceTo(program, at.getMinAddress())) {
				return false; // another path joins here, with an AH of its own
			}
			Address from = at.getFallFrom();
			Instruction previous = from == null ? null : program.getListing().getInstructionAt(from);
			if (previous == null) {
				return false;
			}
			if (writesOverlapping(previous, ah)) {
				return hasBytes(previous, 0xb4, 0x4c) ||
					(hasBytes(previous, 0xb8) && byteAt(previous, 2) == 0x4c);
			}
			at = previous;
		}
		return false;
	}

	/** True if {@code instruction} writes {@code register} or any register overlapping it. */
	private static boolean writesOverlapping(Instruction instruction, Register register) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register written &&
				(written.contains(register) || register.contains(written))) {
				return true;
			}
		}
		return false;
	}

	/** True if {@code instruction}'s bytes start with {@code expected}. */
	private static boolean hasBytes(Instruction instruction, int... expected) {
		if (instruction.getLength() < expected.length) {
			return false;
		}
		for (int i = 0; i < expected.length; i++) {
			if (byteAt(instruction, i) != expected[i]) {
				return false;
			}
		}
		return true;
	}

	/** The unsigned byte at {@code offset} into {@code instruction}, or -1 past its end. */
	private static int byteAt(Instruction instruction, int offset) {
		try {
			return offset < instruction.getLength() ? instruction.getByte(offset) & 0xff : -1;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** True if a flow out of this instruction already goes to {@code target}. */
	private static boolean hasReferenceTo(Instruction instruction, Address target) {
		for (Reference reference : instruction.getReferencesFrom()) {
			if (reference.getReferenceType().isFlow() && reference.getToAddress().equals(target)) {
				return true;
			}
		}
		return false;
	}

	/** True when the instruction's first bytes are exactly {@code pattern}. */
	private static boolean matchesBytes(Instruction instruction, byte[] pattern) {
		try {
			byte[] bytes = instruction.getBytes();
			if (bytes.length != pattern.length + 2) {
				return false; // pattern plus its disp16
			}
			for (int i = 0; i < pattern.length; i++) {
				if (bytes[i] != pattern[i]) {
					return false;
				}
			}
			return true;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * Detector F. Delete the instructions decoded out of zero fill.
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
	 * which {@link #sealCallsThatCannotReturn} owns. Instructions that merely
	 * <i>overlap</i> the island are left alone too: {@code MOV AX,0} is {@code b8 00
	 * 00}, and two of its three bytes are zero.
	 */
	static int clearFillerIslands(Program program, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		Set<Address> visited = new LinkedHashSet<>();
		int cleared = 0;

		for (Instruction instruction : listing.getInstructions(true)) {
			monitor.checkCancelled();
			if (visited.contains(instruction.getMinAddress()) ||
				!isFillerInstruction(program, instruction)) {
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
			ClearFlowAndRepairCmd.clearBadBookmarks(program, markedRange(span), monitor);
			cleared += junk.size();
		}
		sweepBookmarksInFill(program, monitor);
		return cleared;
	}

	/**
	 * Drop the ERROR bookmarks left standing on undefined bytes inside fill. Such a
	 * mark describes junk that no longer exists — the disassembler never takes its
	 * bookmarks back, so one survives the removal of the very instructions it was
	 * complaining about, whether this analyzer cleared them or an earlier run of it
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
			if (listing.getInstructionContaining(at) == null &&
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
	 * The maximal run of zero bytes containing {@code seed}, or null when that run is
	 * too short to be fill (or too long to be worth walking).
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
			if (isEvidencedInstruction(program, instruction)) {
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
	private static boolean isFillerInstruction(Program program, Instruction instruction) {
		try {
			byte[] bytes = instruction.getBytes();
			for (byte value : bytes) {
				if (value != FILLER_BYTE) {
					return false;
				}
			}
			return bytes.length > 0;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * Detector B. Arbitrate every "Failed to disassemble ... due to conflicting
	 * instruction" bookmark: the bookmark sits at the buried address; when the
	 * buried side has evidence and the junk side has none, the junk loses.
	 */
	static int arbitrateConflictBookmarks(Program program, TaskMonitor monitor)
			throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> conflicts = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().startsWith("Failed to disassemble at ") &&
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
	 * gone, and the code it blocked is recovered by {@link #fillCodeGaps}).
	 */
	static int sweepRepairedConflictBookmarks(Program program, TaskMonitor monitor)
			throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> stale = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().startsWith("Failed to disassemble at ") &&
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
		int start = "Failed to disassemble at ".length();
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
	 * analyzer must not decide.
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
			if (isEvidencedInstruction(program, current)) {
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
	 * Direct evidence that {@code instruction} is real code: a flow reference to
	 * its entry, a function entry, an external entry point, or a non-default
	 * symbol. Function <i>containment</i> is deliberately not evidence — junk gets
	 * absorbed into function bodies.
	 */
	private static boolean isEvidencedInstruction(Program program, Instruction instruction) {
		Address entry = instruction.getMinAddress();
		if (hasFlowReferenceTo(program, entry)) {
			return true;
		}
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			return true;
		}
		if (program.getSymbolTable().isExternalEntryPoint(entry)) {
			return true;
		}
		Symbol primary = program.getSymbolTable().getPrimarySymbol(entry);
		return primary != null && primary.getSource() != SourceType.DEFAULT;
	}

	private static boolean hasFlowReferenceTo(Program program, Address address) {
		for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
			if (reference.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
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
			if (isEvidencedInstruction(program, current)) {
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
		promoteIfCalled(program, buried, monitor);
		if (!evidence.isEmpty()) {
			Function owner = program.getFunctionManager()
					.getFunctionContaining(evidence.getMinAddress());
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(program, program.getListing()
						.getInstructionAt(owner.getEntryPoint()), monitor);
			}
		}
	}

	/**
	 * Detector C. Disassemble the code gaps that flow never reaches.
	 * <p>
	 * A routine whose entry nothing references and whose bytes were cleared out from
	 * under the pattern seeders is reachable by no pass at all: it is simply left as
	 * undefined bytes between two runs of code. ROE2MAIN has both halves of one such
	 * routine — the prologue at {@code 122e:51a0} ({@code PUSH BP; MOV BP,SP;
	 * SUB SP,0x12}, byte-for-byte its sibling {@code FUN_122e_5177}) and its epilogue
	 * at {@code 122e:51be} ({@code MOV SP,BP; POP BP; RETF}) — orphaned when
	 * {@link EmulatedFloatPatcher} cleared the emulator-call window around them and
	 * re-disassembled by flow, which reaches neither.
	 * <p>
	 * The gap is claimed only when its bytes account for themselves exactly: every
	 * instruction decodes, and the run ends precisely on the boundary of the next
	 * defined code unit — one byte over or under and this is not an in-phase run of
	 * code. That alone would also swallow alignment padding, so the gap must in
	 * addition <i>look like</i> a routine: it begins with a frame prologue, or it ends
	 * with a return right where the next function begins (a stranded epilogue), or the
	 * instruction above it falls straight into it. A run of one repeated byte is
	 * padding by definition and is never claimed — which is what keeps this off the
	 * zero-filled islands in the C library's data.
	 * <p>
	 * A longer gap is claimed only as a run of <b>whole routines</b>: the code above it
	 * ends in a return, and the gap splits exactly into routines that
	 * each end in a return or an unconditional jump, separated at most by the single
	 * {@code NOP} that puts the next routine on an even address. Every branch that lands
	 * inside the gap must land on an instruction of the decode. VICEROY's
	 * {@code OVERLAY_30::03a40a} is the shape: three library routines linked in with
	 * their module, 158 bytes that nothing calls, which no flow and no single-routine
	 * rule reaches. Each routine becomes a function.
	 */
	static int fillCodeGaps(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		List<GapClaim> claims = new ArrayList<>();

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			monitor.checkCancelled();
			if (!block.isExecute() || !block.isInitialized()) {
				continue;
			}
			AddressIterator undefined = listing.getUndefinedRanges(
				new AddressSet(block.getStart(), block.getEnd()), true, monitor)
					.getAddresses(true);
			Address gapStart = null;
			Address previous = null;
			while (undefined.hasNext()) {
				monitor.checkCancelled();
				Address current = undefined.next();
				if (gapStart == null) {
					gapStart = current;
				}
				else if (previous != null && !current.equals(previous.next())) {
					claimGap(program, block, gapStart, previous, claims);
					gapStart = current;
				}
				previous = current;
			}
			if (gapStart != null && previous != null) {
				claimGap(program, block, gapStart, previous, claims);
			}
		}

		int filled = 0;
		for (GapClaim claim : claims) {
			monitor.checkCancelled();
			filled += claim.wholeRoutines() ? fillRoutines(program, claim, monitor)
					: fillGap(program, claim.starts().get(0), monitor);
		}
		return filled;
	}

	/**
	 * What the gap filler will disassemble in one gap: its start, or the start of every
	 * routine in it when it is a run of whole routines.
	 */
	private record GapClaim(AddressSet gap, List<Address> starts, boolean wholeRoutines) {
	}

	private static void claimGap(Program program, MemoryBlock block, Address start,
			Address end, List<GapClaim> claims) {
		GapClaim claim = recoverableGap(program, start, end);
		if (claim == null) {
			return;
		}
		List<Address> starts = claim.starts().stream().map(a -> inSegmentOf(block, a)).toList();
		claims.add(new GapClaim(claim.gap(), starts, claim.wholeRoutines()));
	}

	private static int fillGap(Program program, Address start, TaskMonitor monitor) {
		// Fall-through only: flow out of the gap is already disassembled, and a runaway
		// would be exactly the mis-phased decode this guards against.
		new DisassembleCommand(start, null, false).applyTo(program, monitor);
		if (program.getListing().getInstructionAt(start) == null) {
			return 0;
		}
		promoteIfPrologue(program, start, monitor);
		return 1;
	}

	private static int fillRoutines(Program program, GapClaim claim, TaskMonitor monitor) {
		// Named one by one: a claim this wide is worth being able to audit.
		Msg.info(RTLinkFlowRepairAnalyzer.class, String.format(
			"RTLink/Plus: Unreached run of %d routine(s) at %s", claim.starts().size(),
			claim.starts()));
		List<Address> decoded = new ArrayList<>();
		for (Address start : claim.starts()) {
			// Following flow, but only inside the gap: a routine's own branches are
			// what reach the code past its first unconditional jump.
			new DisassembleCommand(start, claim.gap(), true).applyTo(program, monitor);
			if (program.getListing().getInstructionAt(start) != null) {
				decoded.add(start);
			}
		}
		// Last entry first: of entries sharing a tail, the one that falls into it owns it,
		// and each earlier one then keeps only the bytes up to its jump into that tail.
		for (Address start : decoded.reversed()) {
			if (program.getFunctionManager().getFunctionContaining(start) == null) {
				new CreateFunctionCmd(start).applyTo(program, monitor);
			}
		}
		return decoded.size();
	}

	/**
	 * The same byte, addressed through the paragraph its block is based at.
	 * <p>
	 * Iterating a segmented space hands back addresses built from the flat offset, and
	 * {@code SegmentedAddressSpace} renders those through the 64KB <i>page</i> segment
	 * ({@code getDefaultSegmentFromFlat}) — so a gap in a block based at {@code 122e}
	 * arrives as {@code 1000:7480}. It is the same location and compares equal, but a
	 * function created at it is named for the page, and every label the repair leaves
	 * behind reads as if it belonged to a segment the code never runs in.
	 */
	private static Address inSegmentOf(MemoryBlock block, Address address) {
		if (!(block.getStart() instanceof SegmentedAddress start) ||
			!(address.getAddressSpace() instanceof SegmentedAddressSpace space) ||
			!address.getAddressSpace().equals(start.getAddressSpace())) {
			return address;
		}
		long offset = address.getOffset() - (long) start.getSegment() * 16;
		if (offset < 0 || offset > 0xffffL) {
			return address; // not addressable from this block's paragraph
		}
		return space.getAddress(start.getSegment(), (int) offset);
	}

	/**
	 * What to claim of the undefined run {@code [start, end]}, or null when it is padding
	 * or data rather than code the analysis missed. It must be in phase (it decodes
	 * exactly onto the next code unit) and shaped like code: a short gap with a
	 * prologue, a stranded epilogue or a fall-through into it, or a run of whole
	 * routines.
	 */
	private static GapClaim recoverableGap(Program program, Address start, Address end) {
		long length = end.subtract(start) + 1;
		if (length < MIN_GAP_LENGTH || length > MAX_ROUTINE_RUN_LENGTH) {
			return null;
		}
		byte[] bytes = new byte[(int) length];
		try {
			if (program.getMemory().getBytes(start, bytes) != bytes.length) {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		int pad = leadingZeros(bytes);
		if (pad > 0 && pad < FILLER_MIN_RUN && pad < length && closedAbove(program, start)) {
			// Zero padding or a zeroed variable between a routine's last jump and the next
			// routine (RTLink's rtcommon, 275d:07cf): left alone, and what follows judged
			// as a gap of its own.
			return recoverableGap(program, start.add(pad), end);
		}
		if (isRepeatedByte(bytes) || containsFillerRun(bytes)) {
			// Padding, not code — and a gap that merely *contains* a fill run is no
			// better: once an island has been cleared, the undefined bytes around it
			// may no longer be uniform, and without this a gap straddling the island's
			// edge could decode in phase and put the junk straight back.
			return null;
		}
		List<PseudoInstruction> decoded = decodeExactly(program, start, length);
		if (decoded == null) {
			return null;
		}

		AddressSet gap = new AddressSet(start, end);
		// Below a routine exit, whole routines first: each then becomes a function, where
		// the single-start claim would decode only the first one and name none
		// (RTLink's $$RTL_PRELOAD and $$RTL_SHELL_EVENT, 275d:07d5 and 275d:07df).
		List<Address> routines = splitIntoRoutines(program, gap, decoded);
		if (!routines.isEmpty()) {
			return new GapClaim(gap, routines, true);
		}
		Instruction last = decoded.get(decoded.size() - 1);
		if (length <= MAX_GAP_LENGTH && (startsWithPrologue(bytes) ||
			isStrandedEpilogue(program, end, last) || fallsInto(program, start))) {
			return new GapClaim(gap, List.of(start), false);
		}
		return null;
	}

	/**
	 * A near {@code JMP} between routines: a slot of a table of jumps that only a computed
	 * jump reaches (VICEROY {@code 210d:2016}, {@code JMP 2121} between two others), not a
	 * routine. Its target is decoded anyway; the slot itself is not claimed.
	 */
	private static boolean isJumpSlot(PseudoInstruction instruction) {
		FlowType flowType = instruction.getFlowType();
		return flowType.isJump() && !flowType.hasFallthrough() &&
			!"JMPF".equals(instruction.getMnemonicString());
	}

	/**
	 * The instructions {@code [start, start + length)} decodes to, or null unless every
	 * byte decodes and the last instruction ends exactly at the end of the run.
	 */
	private static List<PseudoInstruction> decodeExactly(Program program, Address start,
			long length) {
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		List<PseudoInstruction> decoded = new ArrayList<>();
		Address at = start;
		long consumed = 0;
		while (consumed < length) {
			PseudoInstruction instruction;
			try {
				// Undecodable bytes come back as null here, not as an exception.
				instruction = pseudo.disassemble(at);
			}
			catch (Exception e) {
				instruction = null;
			}
			if (instruction == null) {
				return null; // does not decode: not code
			}
			if (flowsNowhere(program, instruction)) {
				// A decode that jumps somewhere that does not exist is not code this
				// analyzer may claim. The shape that matters here is RTLink's own
				// dispatch stub — CALLF dispatcher; JMPF 0000:offset, whose segment is
				// deliberately left unrelocated until the overlay manager patches it at
				// runtime. Those are RTLinkOverlayAnalyzer's to resolve into thunks;
				// decoding them here produces a real instruction and a "flow into
				// non-existing memory" error nobody sweeps.
				return null;
			}
			decoded.add(instruction);
			consumed += instruction.getLength();
			at = at.add(instruction.getLength());
		}
		// Out of phase when the run overshoots the code that follows.
		return consumed == length ? decoded : null;
	}

	/**
	 * The entry of every routine in {@code gap}, or an empty list unless the gap is a run
	 * of whole routines: the code above it cannot run into it (see {@link #closedAbove}),
	 * every branch that lands in the gap lands on an instruction of the decode, and the gap
	 * splits exactly into routines, with at most one {@code NOP} padding a routine onto an
	 * even address. No routine may start on a zero byte.
	 * <p>
	 * A routine ends at an instruction without a fall-through (a return or an
	 * unconditional jump) that none of its own jumps reaches past. One that some jump
	 * does reach past is internal ({@code JMP} over an {@code else}), and the code after
	 * it must then be a target of one of the routine's jumps — or a further entry that
	 * jumps or falls straight into one of them, as hand-written runtimes share one body
	 * between entries that differ in a register they load first. A run that merely falls
	 * into the function below the gap is not claimed: short data in front of a routine
	 * decodes that way as readily as an entry does.
	 */
	private static List<Address> splitIntoRoutines(Program program, AddressSet gap,
			List<PseudoInstruction> decoded) {
		if (!closedAbove(program, gap.getMinAddress())) {
			return List.of();
		}
		Set<Address> boundaries = new LinkedHashSet<>();
		decoded.forEach(instruction -> boundaries.add(instruction.getAddress()));

		List<Address> starts = new ArrayList<>();
		Set<Address> targets = new LinkedHashSet<>(); // the current routine's jump targets
		Address furthest = null;
		int entry = -1; // the current routine's first entry, as an index into decoded
		boolean betweenRoutines = true;
		boolean padded = false;
		boolean unreached = false; // the previous instruction has no fall-through
		for (int index = 0; index < decoded.size(); index++) {
			PseudoInstruction instruction = decoded.get(index);
			Address at = instruction.getAddress();
			if (betweenRoutines) {
				if (isAlignmentPad(instruction) && !padded) {
					padded = true;
					continue;
				}
				if (startsOnZero(instruction)) {
					// ADD [BX+SI],AL: zeroed data that happens to decode, such as a
					// saved interrupt vector or a CS variable, never a routine entry.
					return List.of();
				}
				if (isJumpSlot(instruction)) {
					continue; // still between routines
				}
				starts.add(at);
				targets.clear();
				furthest = null;
				entry = index;
				betweenRoutines = false;
			}
			else if (unreached && !targets.contains(at)) {
				// Nothing in this routine reaches it, so it is either a further entry
				// into the routine's tail (PUSH DX ; MOV DX,0x2000 ; JMP tail, VICEROY
				// 210d:1df7, parallel to the first entry PUSH DX ; MOV DX,0x0800) or not
				// code at all — dead code, or data, after an inner jump. Only the first is
				// claimed.
				if (!parallelEntry(decoded, entry, index) || !joinsTail(decoded, index, targets)) {
					return List.of();
				}
				starts.add(at);
			}
			FlowType flowType = instruction.getFlowType();
			for (Address flow : instruction.getFlows()) {
				if (!gap.contains(flow)) {
					if (flowType.isJump() && backIntoRoutineAbove(program, gap, flow)) {
						// A block that jumps back into the middle of a routine is a
						// detached part of it (VICEROY 210d:05f0, below a far jump, jumps
						// back into the INT 21h hook), not a routine of its own.
						return List.of();
					}
					continue;
				}
				if (!boundaries.contains(flow)) {
					return List.of(); // a branch into the middle of an instruction
				}
				if (flowType.isJump()) {
					targets.add(flow);
					furthest = furthest == null || flow.compareTo(furthest) > 0 ? flow : furthest;
				}
			}
			unreached = !flowType.hasFallthrough();
			if (unreached && (furthest == null || furthest.compareTo(at) <= 0)) {
				betweenRoutines = true;
				padded = false;
			}
		}
		return betweenRoutines ? starts : List.of();
	}

	/**
	 * True when {@code target} lies just above the gap ({@value #DETACHED_BLOCK_REACH} bytes
	 * at most) inside a function's body but not at its entry: the gap is then a detached block
	 * of that routine. A jump into the middle of a routine further away is a tail jump into a
	 * shared exit, which library and runtime routines make routinely (getchar,
	 * {@code 1d1d:077e}).
	 */
	private static boolean backIntoRoutineAbove(Program program, AddressSet gap, Address target) {
		Address start = gap.getMinAddress();
		if (target.compareTo(start) >= 0 || start.subtract(target) > DETACHED_BLOCK_REACH) {
			return false;
		}
		Function function = program.getFunctionManager().getFunctionContaining(target);
		return function != null && !function.getEntryPoint().equals(target);
	}

	/**
	 * True when the first two instructions at {@code decoded[index]} have the mnemonics and
	 * register operands of the two at {@code decoded[entry]}: entries into one shared body
	 * that differ only in the constant they load ({@code PUSH DX ; MOV DX,imm}).
	 */
	private static boolean parallelEntry(List<PseudoInstruction> decoded, int entry, int index) {
		if (entry < 0 || index + 1 >= decoded.size()) {
			return false;
		}
		for (int i = 0; i < 2; i++) {
			PseudoInstruction first = decoded.get(entry + i);
			PseudoInstruction other = decoded.get(index + i);
			if (!first.getMnemonicString().equals(other.getMnemonicString()) ||
				first.getNumOperands() != other.getNumOperands()) {
				return false;
			}
			for (int op = 0; op < first.getNumOperands(); op++) {
				if (!Objects.equals(first.getRegister(op), other.getRegister(op))) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * True when the straight-line run from {@code decoded[index]} reaches one of
	 * {@code targets} — by a jump or by falling into it — before it stops. That is what makes
	 * code below a routine's unconditional jump another entry into the same routine.
	 */
	private static boolean joinsTail(List<PseudoInstruction> decoded, int index,
			Set<Address> targets) {
		for (int i = index; i < decoded.size(); i++) {
			PseudoInstruction instruction = decoded.get(i);
			if (i > index && targets.contains(instruction.getAddress())) {
				return true; // fell into it
			}
			for (Address flow : instruction.getFlows()) {
				if (targets.contains(flow)) {
					return true;
				}
			}
			if (!instruction.getFlowType().hasFallthrough() ||
				instruction.getFlowType().isConditional()) {
				return false;
			}
		}
		return false;
	}

	/**
	 * True when the routine above {@code start} has certainly ended there: its last
	 * instruction leaves it — a return, a far jump, or a jump to another function's entry (a
	 * tail call: VICEROY's {@code JMP rtlink_error_vm_stack_underflow} at {@code 210d:2b7a})
	 * — possibly followed by fewer than {@value #FILLER_MIN_RUN} zero bytes of padding. A near
	 * jump within the routine does not: what follows it may be a case of an unresolved switch,
	 * code of that same routine that only a computed jump reaches.
	 */
	private static boolean closedAbove(Program program, Address start) {
		Address before = start.previous();
		try {
			for (int i = 0; i < FILLER_MIN_RUN && before != null; i++) {
				Instruction above = program.getListing().getInstructionContaining(before);
				if (above != null) {
					return leavesRoutine(program, above);
				}
				if (program.getMemory().getByte(before) != FILLER_BYTE) {
					return false;
				}
				before = before.previous();
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		return false;
	}

	private static boolean leavesRoutine(Program program, Instruction instruction) {
		FlowType flowType = instruction.getFlowType();
		if (flowType.hasFallthrough()) {
			return false;
		}
		if (flowType.isTerminal() && !flowType.isJump()) {
			// RET, RETF, IRET — or a jump the Shared Return Calls analyzer made a tail call
			return true;
		}
		if (!flowType.isJump()) {
			return false;
		}
		if ("JMPF".equals(instruction.getMnemonicString())) {
			return true;
		}
		Address[] flows = instruction.getFlows();
		if (flows.length == 0) {
			return false; // an unresolved near jump: a switch, not an exit
		}
		for (Address flow : flows) {
			if (program.getFunctionManager().getFunctionAt(flow) == null) {
				return false;
			}
		}
		return true;
	}

	private static int leadingZeros(byte[] bytes) {
		int zeros = 0;
		while (zeros < bytes.length && bytes[zeros] == FILLER_BYTE) {
			zeros++;
		}
		return zeros;
	}

	private static boolean startsOnZero(PseudoInstruction instruction) {
		try {
			return instruction.getByte(0) == 0;
		}
		catch (MemoryAccessException e) {
			return true;
		}
	}

	/** A one-byte {@code NOP} at an odd address: it puts what follows on a word. */
	private static boolean isAlignmentPad(PseudoInstruction instruction) {
		return instruction.getLength() == 1 && (instruction.getAddress().getOffset() & 1) == 1 &&
			isNop(instruction);
	}

	private static boolean isNop(PseudoInstruction instruction) {
		try {
			return instruction.getByte(0) == NOP;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/** True if any flow out of {@code instruction} lands outside mapped memory. */
	private static boolean flowsNowhere(Program program, PseudoInstruction instruction) {
		for (Address flow : instruction.getFlows()) {
			if (!program.getMemory().contains(flow)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A frame prologue: {@code PUSH BP; MOV BP,SP}, or {@code ENTER n,0}, which MSC emits
	 * instead for 186+ targets (VICEROY {@code OVERLAY_30::03a40a}).
	 */
	private static boolean startsWithPrologue(byte[] bytes) {
		boolean pushBp = bytes.length >= 3 && bytes[0] == 0x55 && bytes[1] == (byte) 0x8b &&
			bytes[2] == (byte) 0xec;
		boolean enter = bytes.length >= 4 && bytes[0] == (byte) 0xc8 && bytes[3] == 0;
		return pushBp || enter;
	}

	/**
	 * True when the gap ends in a return and the next code unit starts a function —
	 * the epilogue of the routine above it, stranded when nothing flowed into it.
	 */
	private static boolean isStrandedEpilogue(Program program, Address end,
			Instruction last) {
		if (last == null || !last.getFlowType().isTerminal()) {
			return false;
		}
		Address next = end.next();
		return next != null && program.getFunctionManager().getFunctionAt(next) != null;
	}

	/** True when the instruction above the gap falls straight into it. */
	private static boolean fallsInto(Program program, Address start) {
		Address before = start.previous();
		if (before == null) {
			return false;
		}
		Instruction previous = program.getListing().getInstructionContaining(before);
		return previous != null && start.equals(previous.getFallThrough());
	}

	/** True when {@code bytes} contains a fill run — {@value #FILLER_MIN_RUN} zeros. */
	private static boolean containsFillerRun(byte[] bytes) {
		int run = 0;
		for (byte value : bytes) {
			run = value == FILLER_BYTE ? run + 1 : 0;
			if (run >= FILLER_MIN_RUN) {
				return true;
			}
		}
		return false;
	}

	private static boolean isRepeatedByte(byte[] bytes) {
		for (int i = 1; i < bytes.length; i++) {
			if (bytes[i] != bytes[0]) {
				return false;
			}
		}
		return true;
	}

	/** Make a recovered prologue a function; its callers, if any, are indirect. */
	private static void promoteIfPrologue(Program program, Address start,
			TaskMonitor monitor) {
		if (program.getFunctionManager().getFunctionContaining(start) != null) {
			return;
		}
		try {
			byte[] bytes = new byte[4]; // ENTER n,0 is four bytes
			if (program.getMemory().getBytes(start, bytes) == bytes.length &&
				startsWithPrologue(bytes)) {
				new CreateFunctionCmd(start).applyTo(program, monitor);
			}
		}
		catch (MemoryAccessException e) {
			// leave it as code without a function
		}
	}

	/** Create a function at {@code target} when it is call-referenced and unowned. */
	private static void promoteIfCalled(Program program, Address target,
			TaskMonitor monitor) {
		if (program.getListing().getInstructionAt(target) == null) {
			return;
		}
		if (program.getFunctionManager().getFunctionContaining(target) != null) {
			return;
		}
		for (Reference reference : program.getReferenceManager().getReferencesTo(target)) {
			if (reference.getReferenceType().isCall()) {
				new CreateFunctionCmd(target).applyTo(program, monitor);
				return;
			}
		}
	}
}
