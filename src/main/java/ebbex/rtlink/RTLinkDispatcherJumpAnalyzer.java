package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves the RTLink/Plus VM nucleus' constant-pair dispatch: removes the computed-jump
 * references stock resolves against the wrong segment, with the junk they decoded, and puts
 * in the true ones.
 * <p>
 * The dispatch is {@code MOV AX,entry ; MOV DX,body ; … ; MOV [SI-4],AX ; JMP DX}: it
 * patches the caller's return slot with one VM entry ({@code $$VM_CALL}, {@code $$VM_JMP},
 * …) and continues at that entry's body. {@code JMP DX} is a near jump, so the body is
 * {@code CS:DX} in the nucleus segment itself — VICEROY's {@code 210d:0e3d} goes to
 * {@code 210d:0e93} or {@code 210d:1369}, the code right after {@code $$VM_CALL}'s and
 * {@code $$VM_CALLR}'s entry checks. The bodies hold most of the VM runtime: nothing else
 * reaches them.
 * <p>
 * Stock resolves the offset against the jump's 64KB <i>page</i> ({@code currentCS} is
 * {@code (inst_next >> 4) & 0xf000} in real mode), so the x86 Constant Reference Analyzer
 * (596) plants {@code COMPUTED_JUMP} references to {@code page + imm} and — synchronously,
 * inside the same pass — disassembles junk there (on VICEROY, strings in segment
 * {@code 2047}). There is no window to pre-empt that, so this pass runs after 596/600/602
 * and before the ASCII Strings analyzer (~905): it deletes each reference an immediate
 * explains against any other base than the jump's own segment, clears the unevidenced junk
 * it seeded (returning the bytes to undefined for the string pass), drops the confined ERROR
 * bookmarks, and then adds the reference to {@code CS:imm} for every constant that feeds the
 * jump and disassembles there. Where {@code currentCS} reads CS from context (upstream PR
 * #9703, the dailydriver fork), stock already resolves correctly and only the second half has
 * anything to do.
 * <p>
 * An earlier version took the body for an offset into a runtime-selected overlay segment and
 * deleted every same-block reference too, the correct ones included, clearing the bodies —
 * 37 runtime routines of VICEROY's nucleus went with them.
 * <p>
 * The recognition fingerprint is near-unforgeable and was validated to appear exactly twice
 * (the two sibling dispatchers) in each of the four corpus binaries — VICEROY, NEBULAR,
 * SPHERE, ROE2MAIN — matching no unrelated {@code JMP reg} site: a register-indirect near
 * jump, immediately preceded by a return-slot patch {@code MOV word ptr [base-disp], reg}
 * (the {@code 89 44 fc} = {@code MOV [SI-4],AX} spelling in all four), fed by a
 * {@code MOV <jumpreg>,imm16} on the straight-line path into it.
 */
public final class RTLinkDispatcherJumpAnalyzer extends AbstractAnalyzer {

	static final String NAME = "RTLink Dispatcher Jump";
	private static final String DESCRIPTION =
		"Resolves the RTLink/Plus VM nucleus' constant-pair dispatch (MOV DX,imm16 ; " +
			"MOV [SI-disp],AX ; JMP DX): deletes the computed jumps stock resolves against the " +
			"64KB page instead of the nucleus segment, clears the junk they disassembled and " +
			"their error bookmarks, and adds the true CS:imm targets, the VM entries' bodies.";

	/** The plate comment the dispatch jump carries, saying where its targets come from. */
	static final String DISPATCHER_COMMENT =
		"RTLink/Plus VM dispatch: continues at the body of the VM entry patched into the " +
			"caller's return slot (MOV AX/MOV DX constant pair, near, this segment).";

	public RTLinkDispatcherJumpAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// After the x86 Constant Reference Analyzer (596), OperandReferenceAnalyzer (600) and
		// its scheduled disassembly (602) have all settled — so there is definitely a
		// reference and its junk to undo — but before the ASCII Strings analyzer (~905), so
		// the cleared bytes are undefined in time for it to claim the string on its own.
		setPriority(AnalysisPriority.DATA_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkProgram.isSegmentedMz(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (!RTLinkProgram.isOverlayAnalyzed(program)) {
			return false; // canAnalyze accepts any segmented MZ; the VM nucleus is RTLink's
		}
		int resolved = resolveDispatchJumps(program, set, monitor);
		RTLinkProgram.report(this, resolved,
			"RTLink/Plus: Resolved %d VM dispatch jump(s) to their entry bodies");
		return true;
	}

	/**
	 * The pass proper, exposed as a static so tests can drive it directly: recognizes the
	 * VM dispatch jumps in {@code set}, deletes the computed-jump references stock resolved
	 * against the wrong segment, clears the junk those references caused and the confined
	 * ERROR bookmarks, then references and disassembles each {@code CS:imm} body. Returns the
	 * number of dispatch jumps it changed anything on.
	 */
	static int resolveDispatchJumps(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		ReferenceManager references = program.getReferenceManager();

		// Collect the jumps first: neutralization clears code, which would disturb a live
		// instruction iterator over the same set.
		int resolved = 0;
		for (VmDispatch dispatch : VmDispatch.in(program, set, monitor)) {
			monitor.checkCancelled();
			Instruction jmp = dispatch.jump();
			List<Reference> bogus = matchedBogusRefs(program, dispatch);
			for (Reference ref : bogus) {
				monitor.checkCancelled();
				Address target = ref.getToAddress();
				// Delete the reference first, so the target's evidence test no longer counts
				// this very (bogus) reference: only genuine evidence — a real function entry,
				// a non-default symbol, or a foreign flow reference — then protects the code.
				references.delete(ref);

				Instruction targetInsn = listing.getInstructionAt(target);
				if (targetInsn == null) {
					// The bogus flow never decoded (it ran into real code); its only trace is
					// the "Failed to disassemble" mark at the target, now an orphan.
					ErrorMarks.removeUnreached(program, target);
					continue;
				}
				if (CodeEvidence.isEvidenced(program, targetInsn)) {
					// Nothing decoded there, or the target is real code that stands on its own
					// evidence: drop the bad reference but leave the code (do not over-clear).
					continue;
				}
				// Clear the whole mis-decoded flow the bogus reference seeded — not just the
				// linear fall-through, because the cascade branches (mis-decoded JCCs inside a
				// wrongly-disassembled string reach further conflict sites). ClearFlowAndRepairCmd
				// follows that flow, prunes anything with outside evidence (real code merged in),
				// re-disassembles what is legitimately reached, and — clearBadBookmarks=true —
				// drops the confined Bad-Instruction marks over the cleared range. The one inbound
				// flow (this reference) is already deleted, so nothing re-decodes the target.
				new ClearFlowAndRepairCmd(target, false, true, true).applyTo(program, monitor);
			}
			dropPageGuessMarks(program, dispatch);
			int added = resolveBodies(program, dispatch, monitor);
			if (jmp.getComment(CommentType.PLATE) == null) {
				jmp.setComment(CommentType.PLATE, DISPATCHER_COMMENT);
				// The decompiler never reads references and gets this jump wrong on its own:
				// stock switches it over the page, and even where currentCS reads CS from
				// context it gives up on it ("too many branches") or fails outright. The
				// override fixes it. Recorded on first sight only (no plate comment yet), so a
				// re-run does not bring back an override the user deleted.
				List<Address> bodies = dispatch.bodies(program);
				if (!bodies.isEmpty()) {
					RTLinkProgram.recordSwitch(program, jmp.getMinAddress(), bodies);
				}
			}
			if (!bogus.isEmpty() || added > 0) {
				resolved++;
			}
		}
		return resolved;
	}

	/**
	 * Reference every {@code CS:imm} body from the jump and disassemble the ones not yet
	 * decoded; returns how many references were added. A body is only taken in an
	 * initialized executable block, and never into an overlay space: the nucleus is resident.
	 */
	private static int resolveBodies(Program program, VmDispatch dispatch, TaskMonitor monitor) {
		int added = dispatch.referenceBodies(program);
		for (Address body : dispatch.bodies(program)) {
			if (program.getListing().getInstructionAt(body) == null &&
				program.getListing().getDefinedDataContaining(body) == null) {
				new DisassembleCommand(body, null, true).applyTo(program, monitor);
			}
		}
		return added;
	}

	/**
	 * The bogus references to delete: each ANALYSIS computed-jump reference from {@code jmp}
	 * that the constant analyzer built by resolving a {@code MOV <jumpReg>, imm16} immediate
	 * against another base than the jump's own segment. The {@code CS:imm} targets are the
	 * true ones and never match; tying each deletion to a loaded constant is the precision
	 * check. Two shapes qualify:
	 * <ul>
	 * <li><b>Against the jump's 64KB page</b>, in any block. The x86 {@code currentCS}
	 * subconstructor recomputes CS from the program counter as {@code (inst_next >> 4) &
	 * 0xf000}, so the constant analyzer's target is exactly {@code page base + imm}. That page
	 * base need not lie in the jump's own block: MzLoader makes one block per segment, and a
	 * nucleus segment that starts past its page boundary sends the target into an earlier
	 * block — the committed smoke sample does exactly that (nucleus at {@code 1012}, targets in
	 * the resident code at {@code 1000}), where the junk lands inside a real routine.</li>
	 * <li><b>Against any segment, inside the jump's own block</b> — the original rule, kept so
	 * that nothing it matched on the corpus stops matching. Ghidra may display two addresses
	 * of one 64KB page under different segment bases ({@code 20fe:0389}, {@code 2090:0593}),
	 * so this compares flat addresses: a target {@code P} formed as {@code seg*16 + imm} has
	 * {@code P - imm} a non-negative multiple of 16 on a representable segment.</li>
	 * </ul>
	 * A target in an overlay block is never matched: that is a genuinely resolved overlay
	 * target, not a page-relative guess.
	 */
	private static List<Reference> matchedBogusRefs(Program program, VmDispatch dispatch) {
		Instruction jmp = dispatch.jump();
		if (!(jmp.getMinAddress() instanceof SegmentedAddress at)) {
			return List.of();
		}
		Set<Long> immediates = dispatch.immediates();
		MemoryBlock jumpBlock = program.getMemory().getBlock(jmp.getMinAddress());
		long pageBase = (jmp.getMaxAddress().getOffset() + 1) & PAGE_MASK;
		long csBase = (long) X86.codeSegment(program, jmp, at) * 16;

		List<Reference> matched = new ArrayList<>();
		for (Reference ref : analysisComputedJumpRefs(jmp)) {
			// A segmented address' offset is its flat (physical) address.
			if (!(ref.getToAddress() instanceof SegmentedAddress target)) {
				continue; // an overlay target: resolved for real, not against a page
			}
			if (immediates.contains(target.getOffset() - csBase)) {
				continue; // CS:imm, where the near jump really goes
			}
			boolean sameBlock =
				jumpBlock != null && jumpBlock.equals(program.getMemory().getBlock(target));
			if (immediates.contains(target.getOffset() - pageBase) ||
				(sameBlock && resolvesFromImmediate(target, immediates))) {
				matched.add(ref);
			}
		}
		return matched;
	}

	/**
	 * Drop the disassembler's marks at the page-relative guesses {@code page + imm} that nothing
	 * flows to. Once {@link VmDispatch#claim} has referenced the true bodies, stock's constant
	 * propagation still tries to decode at its own guess but leaves no reference behind for
	 * {@link #matchedBogusRefs} to find — only the mark, where the guess lands mid-code: on the
	 * smoke sample {@code 1000:0067}, one byte before the float routine at {@code 1000:0068}.
	 */
	private static void dropPageGuessMarks(Program program, VmDispatch dispatch) {
		Instruction jmp = dispatch.jump();
		long pageBase = (jmp.getMaxAddress().getOffset() + 1) & PAGE_MASK;
		for (long imm : dispatch.immediates()) {
			Address guess = jmp.getMinAddress().getAddressSpace().getAddress(pageBase + imm);
			if (program.getListing().getInstructionAt(guess) == null) {
				ErrorMarks.removeUnreached(program, guess);
			}
		}
	}

	/** Flat-address bits of a 64KB page base: what {@code currentCS} keeps of the PC. */
	private static final long PAGE_MASK = 0xf0000L;

	/**
	 * True when {@code target}'s flat address could have been formed by resolving one of
	 * {@code immediates} as an offset against some 16-bit segment: {@code flat - imm} is a
	 * non-negative multiple of 16 whose quotient is a representable segment.
	 */
	private static boolean resolvesFromImmediate(SegmentedAddress target, Set<Long> immediates) {
		for (long imm : immediates) {
			long base = target.getOffset() - imm;
			if (base >= 0 && (base & 0xf) == 0 && (base >> 4) <= 0xffffL) {
				return true;
			}
		}
		return false;
	}

	/** The ANALYSIS computed-jump references from {@code jmp}: what the constant analyzer adds. */
	private static List<Reference> analysisComputedJumpRefs(Instruction jmp) {
		List<Reference> refs = new ArrayList<>();
		for (Reference ref : jmp.getReferencesFrom()) {
			if (ref.getReferenceType().isComputed() && ref.getReferenceType().isJump() &&
				ref.getSource() == SourceType.ANALYSIS) {
				refs.add(ref);
			}
		}
		return refs;
	}
}
