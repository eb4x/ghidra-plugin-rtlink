package ebbex.rtlink;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
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
public class RTLinkDispatcherJumpAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink Dispatcher Jump";
	private static final String DESCRIPTION =
		"Resolves the RTLink/Plus VM nucleus' constant-pair dispatch (MOV DX,imm16 ; " +
			"MOV [SI-disp],AX ; JMP DX): deletes the computed jumps stock resolves against the " +
			"64KB page instead of the nucleus segment, clears the junk they disassembled and " +
			"their error bookmarks, and adds the true CS:imm targets, the VM entries' bodies.";

	/** The plate comment the dispatch jump carries, saying where its targets come from. */
	static final String DISPATCHER_COMMENT =
		"RTLink/Plus VM dispatch: continues at the body of the VM entry patched into the " +
			"caller's return slot (MOV AX/MOV DX constant pair, near, this segment).";

	/** What versions up to 0.6.0 wrote there; a re-run replaces it. */
	private static final String LEGACY_DISPATCHER_COMMENT =
		"RTLink/Plus overlay dispatcher: jump target is selected at runtime (overlay " +
			"segment); static resolution intentionally suppressed.";

	/** How many instructions back to look for the constant that feeds the jump register. */
	private static final int FEEDER_WALK_LIMIT = 16;

	/** 16-bit MOV r/m16, r16. The return-slot patch's opcode (e.g. {@code 89 44 fc}). */
	private static final int OPCODE_MOV_RM_R = 0x89;

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
		if (resolved > 0) {
			// Msg.info only, never log.appendMsg: content in the analysis MessageLog makes
			// AutoAnalysisPlugin pop a "warnings/errors issued during analysis" dialog.
			Msg.info(this, String.format(
				"RTLink/Plus: Resolved %d VM dispatch jump(s) to their entry bodies", resolved));
		}
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
		List<Instruction> dispatchers = new ArrayList<>();
		for (Instruction jmp : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			if (isDispatcherJump(program, jmp)) {
				dispatchers.add(jmp);
			}
		}

		int resolved = 0;
		for (Instruction jmp : dispatchers) {
			monitor.checkCancelled();
			List<Reference> bogus = matchedBogusRefs(program, jmp);
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
					removeOrphanedErrorBookmarks(program, target);
					continue;
				}
				if (isEvidencedInstruction(program, targetInsn)) {
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
			int added = resolveBodies(program, jmp, monitor);
			String plate = jmp.getComment(CommentType.PLATE);
			if (plate == null || plate.equals(LEGACY_DISPATCHER_COMMENT)) {
				jmp.setComment(CommentType.PLATE, DISPATCHER_COMMENT);
			}
			if (!bogus.isEmpty() || added > 0) {
				resolved++;
			}
		}
		return resolved;
	}

	/**
	 * Reference every {@code CS:imm} body from {@code jmp} and disassemble the ones not yet
	 * decoded; returns how many references were added. A body is only taken in an
	 * initialized executable block, and never into an overlay space: the nucleus is resident.
	 */
	private static int resolveBodies(Program program, Instruction jmp, TaskMonitor monitor) {
		if (!(jmp.getMinAddress() instanceof SegmentedAddress at)) {
			return 0;
		}
		int segment = codeSegment(program, jmp, at);
		ReferenceManager references = program.getReferenceManager();
		int added = 0;
		for (long imm : loadedImmediates(program, jmp, jmp.getRegister(0))) {
			Address body =
				((SegmentedAddressSpace) at.getAddressSpace()).getAddress(segment, (int) imm);
			MemoryBlock block = program.getMemory().getBlock(body);
			if (block == null || !block.isExecute() || !block.isInitialized()) {
				continue;
			}
			if (!hasReferenceTo(jmp, body)) {
				references.addMemoryReference(jmp.getMinAddress(), body, RefType.COMPUTED_JUMP,
					SourceType.ANALYSIS, Reference.MNEMONIC);
				added++;
			}
			if (program.getListing().getInstructionAt(body) == null &&
				program.getListing().getDefinedDataContaining(body) == null) {
				new DisassembleCommand(body, null, true).applyTo(program, monitor);
			}
		}
		return added;
	}

	/**
	 * The jump's CS: the context value where one is asserted (MzLoader over each resident
	 * block), else its address' segment. Never the language default, which is a page guess.
	 */
	private static int codeSegment(Program program, Instruction jmp, SegmentedAddress at) {
		Register cs = program.getLanguage().getRegister("CS");
		if (cs != null) {
			RegisterValue value =
				program.getProgramContext().getNonDefaultValue(cs, jmp.getMinAddress());
			if (value != null && value.hasValue()) {
				return value.getUnsignedValue().intValue() & 0xffff;
			}
		}
		return at.getSegment();
	}

	private static boolean hasReferenceTo(Instruction jmp, Address target) {
		for (Reference ref : jmp.getReferencesFrom()) {
			if (ref.getToAddress().equals(target) && ref.getReferenceType().isJump()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Drop the disassembler's ERROR marks at {@code target} once nothing flows there any more.
	 * A bogus target that collided with real code decodes nothing and leaves only the mark
	 * {@code "Failed to disassemble at <target> due to conflicting instruction ..."}; with the
	 * reference deleted, no flow explains it. A target some other flow still reaches keeps its
	 * marks: they may describe that flow.
	 */
	private static void removeOrphanedErrorBookmarks(Program program, Address target) {
		for (Reference reference : program.getReferenceManager().getReferencesTo(target)) {
			if (reference.getReferenceType().isFlow()) {
				return;
			}
		}
		BookmarkManager bookmarks = program.getBookmarkManager();
		for (Bookmark bookmark : bookmarks.getBookmarks(target, BookmarkType.ERROR)) {
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory())) {
				bookmarks.removeBookmark(bookmark);
			}
		}
	}

	/**
	 * True when {@code jmp} is an RTLink VM dispatch jump: a register-indirect near jump,
	 * immediately preceded by a return-slot patch {@code MOV [base-disp], reg} and fed by a
	 * {@code MOV <jumpreg>, imm16}. The return-slot patch is the near-unforgeable gate — a
	 * compiler does not store into a return-offset slot and then jump through a
	 * just-constant-loaded register.
	 */
	private static boolean isDispatcherJump(Program program, Instruction jmp) {
		if (!isRegisterIndirectJump(jmp)) {
			return false;
		}
		Register jumpReg = jmp.getRegister(0);
		if (jumpReg == null) {
			return false;
		}
		if (!hasReturnSlotPatchBefore(program, jmp)) {
			return false;
		}
		return !loadedImmediates(program, jmp, jumpReg).isEmpty();
	}

	/** A near {@code JMP} through a single 16-bit register: {@code FF /4}, {@code mod == 3}. */
	private static boolean isRegisterIndirectJump(Instruction jmp) {
		if (!"JMP".equals(jmp.getMnemonicString())) {
			return false;
		}
		if (!jmp.getFlowType().isComputed() || !jmp.getFlowType().isJump()) {
			return false;
		}
		if (jmp.getNumOperands() != 1 || jmp.getRegister(0) == null) {
			return false;
		}
		byte[] bytes = instructionBytes(jmp);
		int i = skipPrefixes(bytes);
		if (i < 0 || i + 1 >= bytes.length || (bytes[i] & 0xff) != 0xff) {
			return false;
		}
		int modrm = bytes[i + 1] & 0xff;
		int mod = (modrm >> 6) & 0x3;
		int reg = (modrm >> 3) & 0x7;
		return mod == 0x3 && reg == 0x4; // /4 = JMP r/m, register form
	}

	/**
	 * True when the instruction immediately before {@code jmp} is a return-slot patch:
	 * {@code MOV word ptr [base - disp], reg16} — opcode {@code 0x89}, a memory ModRM with a
	 * base register ({@code [SI]/[DI]/[BP]/[BX]}) and a negative displacement. This is the
	 * {@code 89 44 fc} ({@code MOV [SI-4],AX}) fingerprint seen in every corpus dispatcher.
	 */
	private static boolean hasReturnSlotPatchBefore(Program program, Instruction jmp) {
		Instruction prev = program.getListing().getInstructionBefore(jmp.getMinAddress());
		if (prev == null) {
			return false;
		}
		Address after = prev.getMaxAddress().next();
		if (after == null || !after.equals(jmp.getMinAddress())) {
			return false; // must be immediately, contiguously before the jump
		}
		byte[] bytes = instructionBytes(prev);
		int i = skipPrefixes(bytes);
		if (i < 0 || i + 2 >= bytes.length || (bytes[i] & 0xff) != OPCODE_MOV_RM_R) {
			return false;
		}
		int modrm = bytes[i + 1] & 0xff;
		int mod = (modrm >> 6) & 0x3;
		int rm = modrm & 0x7;
		// Memory form with a base register: 16-bit rm 4=[SI] 5=[DI] 6=[BP] 7=[BX]; mod 1/2
		// carry a displacement (mod 0 has none, and rm 6 mod 0 is the [disp16] direct form).
		if (rm < 0x4 || mod == 0x0 || mod == 0x3) {
			return false;
		}
		long disp;
		if (mod == 0x1) {
			disp = bytes[i + 2]; // signed disp8
		}
		else { // mod == 2, signed disp16
			if (i + 3 >= bytes.length) {
				return false;
			}
			disp = (short) ((bytes[i + 2] & 0xff) | ((bytes[i + 3] & 0xff) << 8));
		}
		return disp < 0; // a return-slot patch stores below the frame pointer
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
	private static List<Reference> matchedBogusRefs(Program program, Instruction jmp) {
		if (!(jmp.getMinAddress() instanceof SegmentedAddress at)) {
			return List.of();
		}
		Register jumpReg = jmp.getRegister(0);
		Set<Long> immediates = loadedImmediates(program, jmp, jumpReg);
		MemoryBlock jumpBlock = program.getMemory().getBlock(jmp.getMinAddress());
		long pageBase = (jmp.getMaxAddress().getOffset() + 1) & PAGE_MASK;
		long csBase = (long) codeSegment(program, jmp, at) * 16;

		List<Reference> matched = new ArrayList<>();
		for (Reference ref : analysisComputedJumpRefs(jmp)) {
			if (!(ref.getToAddress() instanceof SegmentedAddress target)) {
				continue; // an overlay target: resolved for real, not against a page
			}
			if (immediates.contains(physical(target) - csBase)) {
				continue; // CS:imm, where the near jump really goes
			}
			boolean sameBlock =
				jumpBlock != null && jumpBlock.equals(program.getMemory().getBlock(target));
			if (resolvesAgainstPage(target, pageBase, immediates) ||
				(sameBlock && resolvesFromImmediate(target, immediates))) {
				matched.add(ref);
			}
		}
		return matched;
	}

	/** Flat-address bits of a 64KB page base: what {@code currentCS} keeps of the PC. */
	private static final long PAGE_MASK = 0xf0000L;

	private static long physical(SegmentedAddress address) {
		return (long) address.getSegment() * 16 + address.getSegmentOffset();
	}

	/** True when {@code target} is {@code pageBase + imm} for one of {@code immediates}. */
	private static boolean resolvesAgainstPage(SegmentedAddress target, long pageBase,
			Set<Long> immediates) {
		return immediates.contains(physical(target) - pageBase);
	}

	/**
	 * True when {@code target}'s flat address could have been formed by resolving one of
	 * {@code immediates} as an offset against some 16-bit segment: {@code physical - imm} is a
	 * non-negative multiple of 16 whose quotient is a representable segment.
	 */
	private static boolean resolvesFromImmediate(SegmentedAddress target, Set<Long> immediates) {
		long physical = physical(target);
		for (long imm : immediates) {
			long base = physical - imm;
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

	/**
	 * The {@code MOV <jumpReg>, imm16} immediates that reach {@code jmp}: a backward walk over
	 * fall-through and jump predecessors, each path ending at its first write to the register
	 * (a path whose write is anything but such a {@code MOV} contributes nothing), at most
	 * {@value #FEEDER_WALK_LIMIT} instructions deep. Reaching definitions rather than a linear
	 * scan, so that the sibling dispatcher's constants above an unconditional jump never count,
	 * and a constant the other arm overwrites is not taken for a target.
	 */
	private static Set<Long> loadedImmediates(Program program, Instruction jmp, Register jumpReg) {
		Set<Long> immediates = new LinkedHashSet<>();
		Set<Address> visited = new HashSet<>();
		Deque<Instruction> frontier = new ArrayDeque<>(predecessors(program, jmp));
		for (int depth = 0; depth < FEEDER_WALK_LIMIT && !frontier.isEmpty(); depth++) {
			Deque<Instruction> next = new ArrayDeque<>();
			for (Instruction cur : frontier) {
				if (!visited.add(cur.getMinAddress())) {
					continue;
				}
				Long imm = loadedImmediate(cur, jumpReg);
				if (imm != null) {
					immediates.add(imm);
				}
				else if (!writes(cur, jumpReg)) {
					next.addAll(predecessors(program, cur));
				}
			}
			frontier = next;
		}
		return immediates;
	}

	/** The instruction falling through to {@code instruction} and every jump landing on it. */
	private static List<Instruction> predecessors(Program program, Instruction instruction) {
		Listing listing = program.getListing();
		Address at = instruction.getMinAddress();
		List<Instruction> predecessors = new ArrayList<>();
		Instruction above = listing.getInstructionBefore(at);
		if (above != null && at.equals(above.getFallThrough())) {
			predecessors.add(above);
		}
		for (Reference reference : program.getReferenceManager().getReferencesTo(at)) {
			if (!reference.getReferenceType().isJump()) {
				continue;
			}
			Instruction source = listing.getInstructionAt(reference.getFromAddress());
			if (source != null) {
				predecessors.add(source);
			}
		}
		return predecessors;
	}

	private static boolean writes(Instruction instruction, Register register) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register written &&
				(written.contains(register) || register.contains(written))) {
				return true;
			}
		}
		return false;
	}

	/** The 16-bit immediate a {@code MOV <reg>, imm16} loads, or null if that is not this. */
	private static Long loadedImmediate(Instruction instruction, Register reg) {
		if (!"MOV".equals(instruction.getMnemonicString()) ||
			instruction.getNumOperands() != 2) {
			return null;
		}
		Register dest = instruction.getRegister(0);
		if (dest == null || !dest.equals(reg)) {
			return null;
		}
		Scalar scalar = instruction.getScalar(1);
		if (scalar == null) {
			return null;
		}
		return scalar.getUnsignedValue() & 0xffffL;
	}

	/**
	 * Whether {@code instruction} stands on its own evidence as real code — a foreign flow
	 * reference, a defined function entry, an external entry point, or a non-default symbol.
	 * Function <i>containment</i> is deliberately not evidence. Mirrors the identically named
	 * predicate in {@link RTLinkFlowRepairAnalyzer} so the two passes agree byte-for-byte.
	 */
	private static boolean isEvidencedInstruction(Program program, Instruction instruction) {
		Address entry = instruction.getMinAddress();
		for (Reference reference : program.getReferenceManager().getReferencesTo(entry)) {
			if (reference.getReferenceType().isFlow()) {
				return true;
			}
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

	/** The instruction's bytes, or an empty array if unreadable. */
	private static byte[] instructionBytes(Instruction instruction) {
		try {
			return instruction.getBytes();
		}
		catch (MemoryAccessException e) {
			return new byte[0];
		}
	}

	/** Index of the first opcode byte past any legacy prefixes, or -1 if none/only prefixes. */
	private static int skipPrefixes(byte[] bytes) {
		int i = 0;
		while (i < bytes.length && isPrefixByte(bytes[i] & 0xff)) {
			i++;
		}
		return i < bytes.length ? i : -1;
	}

	/** x86 legacy prefixes: segment overrides, operand/address size, LOCK and REP. */
	private static boolean isPrefixByte(int b) {
		switch (b) {
			case 0x26: // ES
			case 0x2e: // CS
			case 0x36: // SS
			case 0x3e: // DS
			case 0x64: // FS
			case 0x65: // GS
			case 0x66: // operand size
			case 0x67: // address size
			case 0xf0: // LOCK
			case 0xf2: // REPNE
			case 0xf3: // REP
				return true;
			default:
				return false;
		}
	}
}
