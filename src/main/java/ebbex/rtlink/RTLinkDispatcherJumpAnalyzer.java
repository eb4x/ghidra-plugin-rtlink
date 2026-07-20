/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ebbex.rtlink;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Neutralizes the bogus current-segment computed jump the stock x86 Constant Reference
 * Analyzer plants on an RTLink/Plus overlay VM dispatcher trampoline.
 * <p>
 * The dispatcher trampoline is {@code MOV DX,imm16 ; … ; MOV [SI-4],AX ; JMP DX}: it
 * patches the caller's far-return offset slot and jumps to a <i>bare offset</i> that
 * belongs to a runtime-selected overlay segment, not to the current code segment. Stock
 * Ghidra cannot model that runtime segment, so the constant analyzer (priority 596)
 * constant-propagates {@code DX} and resolves the offset against the current {@code CS},
 * planting a {@code COMPUTED_JUMP} reference into this segment and — synchronously, inside
 * the same pass — disassembling junk at that wrong target (a string decoded as code, plus
 * a non-string casualty; five Bad-Instruction ERROR bookmarks on a fresh VICEROY import).
 * <p>
 * There is no window between the reference being planted and the junk being decoded (both
 * happen in the 596 pass; see the design doc), so this cannot be pre-empted the way
 * {@link RTLinkSwitchTableAnalyzer} wins its race at 399. Instead this pass runs
 * <i>after</i> all reference/disassembly activity (596/600/602) and <i>before</i> the ASCII
 * Strings analyzer (~905): for each recognized dispatcher it deletes the bogus
 * current-segment references, clears the unevidenced junk they caused (returning the bytes
 * to undefined so the string analyzer can reclaim any string on its own), and drops the
 * confined ERROR bookmarks. The {@code JMP DX} itself is left unresolved — the truthful
 * end-state, since its target is overlay-selected at runtime.
 * <p>
 * The recognition fingerprint is near-unforgeable and was validated to appear exactly twice
 * (the two sibling dispatchers) in each of the four corpus binaries — VICEROY, NEBULAR,
 * SPHERE, ROE2MAIN — matching no unrelated {@code JMP reg} site: a register-indirect near
 * jump, immediately preceded by a return-slot patch {@code MOV word ptr [base-disp], reg}
 * (the {@code 89 44 fc} = {@code MOV [SI-4],AX} spelling in all four), fed by a
 * {@code MOV <jumpreg>,imm16}, and carrying a same-block ANALYSIS computed-jump reference.
 */
public class RTLinkDispatcherJumpAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink Dispatcher Jump";
	private static final String DESCRIPTION =
		"Neutralizes the bogus current-segment computed jump the x86 Constant Reference " +
			"Analyzer plants on an RTLink/Plus overlay dispatcher trampoline (MOV reg,imm16 ; " +
			"MOV [SI-disp],reg ; JMP reg): deletes the bad reference, clears the junk it " +
			"disassembled at the wrong target, and drops the confined error bookmarks, so the " +
			"jump is left honestly unresolved and the string pass can reclaim any string.";

	/** The comment the neutralized dispatcher jump carries, so a human knows why it is bare. */
	static final String DISPATCHER_COMMENT =
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
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		int neutralized = neutralizeDispatcherJumps(program, set, monitor);
		if (neutralized > 0) {
			// Msg.info only, never log.appendMsg: content in the analysis MessageLog makes
			// AutoAnalysisPlugin pop a "warnings/errors issued during analysis" dialog.
			Msg.info(this, String.format(
				"RTLink/Plus: Neutralized %d overlay-dispatcher computed jump(s)", neutralized));
		}
		return true;
	}

	/**
	 * The pass proper, exposed as a static so tests can drive it directly: recognizes the
	 * overlay dispatcher trampolines in {@code set}, deletes their bogus current-segment
	 * computed-jump references, clears the junk those references caused, and drops the
	 * confined ERROR bookmarks. Returns the number of dispatcher jumps neutralized.
	 */
	static int neutralizeDispatcherJumps(Program program, AddressSetView set, TaskMonitor monitor)
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

		int neutralized = 0;
		for (Instruction jmp : dispatchers) {
			monitor.checkCancelled();
			List<Reference> bogus = matchedBogusRefs(program, jmp);
			if (bogus.isEmpty()) {
				continue;
			}
			for (Reference ref : bogus) {
				monitor.checkCancelled();
				Address target = ref.getToAddress();
				// Delete the reference first, so the target's evidence test no longer counts
				// this very (bogus) reference: only genuine evidence — a real function entry,
				// a non-default symbol, or a foreign flow reference — then protects the code.
				references.delete(ref);

				Instruction targetInsn = listing.getInstructionAt(target);
				if (targetInsn == null || isEvidencedInstruction(program, targetInsn)) {
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
			// Leave JMP unresolved (the honest end-state) and say why.
			if (jmp.getComment(CommentType.PLATE) == null) {
				jmp.setComment(CommentType.PLATE, DISPATCHER_COMMENT);
			}
			neutralized++;
		}
		return neutralized;
	}

	/**
	 * True when {@code jmp} is an RTLink overlay dispatcher trampoline: a register-indirect
	 * near jump, immediately preceded by a return-slot patch {@code MOV [base-disp], reg}, fed
	 * by a {@code MOV <jumpreg>, imm16}, and carrying at least one same-block ANALYSIS
	 * computed-jump reference. The return-slot patch is the near-unforgeable gate — a compiler
	 * does not store into a return-offset slot and then jump through a just-constant-loaded
	 * register.
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
		if (!hasConstantFeeder(program, jmp, jumpReg)) {
			return false;
		}
		return !sameBlockComputedJumpRefs(program, jmp).isEmpty();
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

	/** True when a {@code MOV <jumpReg>, imm16} feeds the register within the block. */
	private static boolean hasConstantFeeder(Program program, Instruction jmp, Register jumpReg) {
		Listing listing = program.getListing();
		Instruction cur = listing.getInstructionBefore(jmp.getMinAddress());
		for (int i = 0; i < FEEDER_WALK_LIMIT && cur != null; i++) {
			if (loadedImmediate(cur, jumpReg) != null) {
				return true;
			}
			cur = listing.getInstructionBefore(cur.getMinAddress());
		}
		return false;
	}

	/**
	 * The bogus references to delete: each same-block ANALYSIS computed-jump reference from
	 * {@code jmp} whose target the constant analyzer built by resolving a
	 * {@code MOV <jumpReg>, imm16} immediate against some segment. On a confirmed dispatcher
	 * every such reference is bogus (the true target is runtime-selected); tying each deletion
	 * to a loaded constant is the precision check, and the same-block filter leaves any
	 * already-correct cross-segment overlay resolution alone.
	 * <p>
	 * The constant analyzer resolves the bare offset against the CS <i>page-base</i> segment
	 * (the 64KB block base, e.g. {@code 2000}), not the address's canonical segment (e.g.
	 * {@code 20fe}), so the target's offset-within-its-canonical-segment is <i>not</i> the
	 * immediate. The stable relationship is on the flat address: a target physical address
	 * {@code P} was formed as {@code seg*16 + imm} for some segment, i.e. {@code P - imm} is a
	 * non-negative multiple of 16 landing on a representable segment. Matching on that is
	 * robust to which segment Ghidra chose to display the target in.
	 */
	private static List<Reference> matchedBogusRefs(Program program, Instruction jmp) {
		Register jumpReg = jmp.getRegister(0);
		Set<Long> immediates = loadedImmediates(program, jmp, jumpReg);

		List<Reference> matched = new ArrayList<>();
		for (Reference ref : sameBlockComputedJumpRefs(program, jmp)) {
			SegmentedAddress target = (SegmentedAddress) ref.getToAddress();
			if (resolvesFromImmediate(target, immediates)) {
				matched.add(ref);
			}
		}
		return matched;
	}

	/**
	 * True when {@code target}'s flat address could have been formed by resolving one of
	 * {@code immediates} as an offset against some 16-bit segment: {@code physical - imm} is a
	 * non-negative multiple of 16 whose quotient is a representable segment.
	 */
	private static boolean resolvesFromImmediate(SegmentedAddress target, Set<Long> immediates) {
		long physical = (long) target.getSegment() * 16 + target.getSegmentOffset();
		for (long imm : immediates) {
			long base = physical - imm;
			if (base >= 0 && (base & 0xf) == 0 && (base >> 4) <= 0xffffL) {
				return true;
			}
		}
		return false;
	}

	/**
	 * ANALYSIS computed-jump references from {@code jmp} whose target lies in the <i>same
	 * memory block</i> as the jump — the constant analyzer resolved the bare overlay offset
	 * against the jump's own CS page, so a truthful listing has no such static target.
	 * <p>
	 * The discriminator is the memory block, not the segment number: a single 64KB CS page is
	 * one block, and Ghidra may display two addresses inside it under different segment bases
	 * (e.g. {@code 20fe:0389} and {@code 2090:0593} are both in the page based at {@code 2000}),
	 * so a segment-number test would miss half of them. A genuinely cross-overlay resolution
	 * lands in a different block and is left untouched.
	 */
	private static List<Reference> sameBlockComputedJumpRefs(Program program, Instruction jmp) {
		MemoryBlock jumpBlock = program.getMemory().getBlock(jmp.getMinAddress());
		if (jumpBlock == null) {
			return List.of();
		}
		List<Reference> refs = new ArrayList<>();
		for (Reference ref : jmp.getReferencesFrom()) {
			if (!ref.getReferenceType().isComputed() || !ref.getReferenceType().isJump()) {
				continue;
			}
			if (ref.getSource() != SourceType.ANALYSIS) {
				continue;
			}
			if (jumpBlock.equals(program.getMemory().getBlock(ref.getToAddress()))) {
				refs.add(ref);
			}
		}
		return refs;
	}

	/** Every {@code MOV <jumpReg>, imm16} immediate in the block before {@code jmp}. */
	private static Set<Long> loadedImmediates(Program program, Instruction jmp, Register jumpReg) {
		Listing listing = program.getListing();
		Set<Long> immediates = new HashSet<>();
		Instruction cur = listing.getInstructionBefore(jmp.getMinAddress());
		for (int i = 0; i < FEEDER_WALK_LIMIT && cur != null; i++) {
			Long imm = loadedImmediate(cur, jumpReg);
			if (imm != null) {
				immediates.add(imm);
			}
			cur = listing.getInstructionBefore(cur.getMinAddress());
		}
		return immediates;
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
