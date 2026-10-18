package ebbex.rtlink;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Establish the data segment (DGROUP) so the decompiler can resolve DS-relative data accesses.
 * In the small-data DOS model DS == SS == DGROUP, loaded once in the C startup (e.g.
 * {@code MOV DI,DGROUP; MOV SS,DI; PUSH SS; POP DS}). The entry's initial far jump is followed
 * into the startup, which is decoded linearly while tracking register immediates, and the value
 * moved into SS/DS is taken as DGROUP. That value is then assumed for DS over all executable
 * memory except the RTLink runtime's own blocks; without it every DS-relative global collapses
 * to a bare offset in an unmapped space (e.g. {@code *(int *)0x8542}) that ignores applied data
 * types.
 * <p>
 * Runs on every pass rather than once, because it is corrective, not just additive: a program
 * whose context once assumed DGROUP over its runtime blocks keeps it there until something
 * takes it out. Re-running is cheap (a bounded decode of the startup) and idempotent.
 */
final class DataSegmentAssumption {

	/**
	 * The overlay manager's relocation fixup loop — a byte-identical blob the linker stamps
	 * into every VM program (see the "Fingerprint" section of {@code docs/rtlink-format.md}).
	 * Used here only to locate the code segment the manager lives in.
	 */
	private static final byte[] RUNTIME_FIXUP_FINGERPRINT = {
		(byte) 0xe3, 0x19, 0x06, 0x57, (byte) 0xd1, (byte) 0xe6, (byte) 0xd1, (byte) 0xe6,
		(byte) 0xad, (byte) 0x8b, (byte) 0xf8, (byte) 0xad, 0x03, (byte) 0xc3, (byte) 0x8e,
		(byte) 0xc0, 0x26, 0x01, 0x15, (byte) 0xe2, (byte) 0xf3, (byte) 0xd1, (byte) 0xee,
		(byte) 0xd1, (byte) 0xee, 0x5f, 0x07, (byte) 0xc3
	};

	/**
	 * The error text the RTLink support code carries in its own code segment. It is what
	 * marks a binary as RTLink at all, and it is present even in section-only binaries that
	 * have no VM manager (and so no {@link #RUNTIME_FIXUP_FINGERPRINT}).
	 */
	private static final byte[] RUNTIME_SIGNATURE =
		"Internal error in .RTLink(R)/Plus run-time code.".getBytes(StandardCharsets.US_ASCII);

	/** Max instructions to decode when hunting the DGROUP load in the C startup. */
	private static final int STARTUP_SCAN_LIMIT = 200;

	private DataSegmentAssumption() {
	}

	/** Detect DGROUP and assume it for DS over every executable block but the runtime's. */
	static void assume(Program program, MessageLog log) {
		Register ds = program.getLanguage().getRegister("DS");
		if (ds == null) {
			return;
		}
		Address entry = CodeSeeds.firstEntryPoint(program);
		if (entry == null) {
			return;
		}
		Integer dgroup = detectDataSegment(program, entry);
		if (dgroup == null) {
			log.appendMsg("RTLink: could not determine DGROUP from startup; DS left unset");
			return;
		}
		ProgramContext context = program.getProgramContext();
		BigInteger value = BigInteger.valueOf(dgroup & 0xffffL);
		Set<MemoryBlock> runtime = findRuntimeCodeBlocks(program, dgroup);
		int blocks = 0;
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!block.isExecute()) {
					continue;
				}
				if (runtime.contains(block)) {
					// Clear rather than merely skip: context assumed here earlier would
					// otherwise stay forever.
					context.remove(block.getStart(), block.getEnd(), ds);
					continue;
				}
				context.setValue(ds, block.getStart(), block.getEnd(), value);
				blocks++;
			}
		}
		catch (ContextChangeException e) {
			log.appendMsg("RTLink: failed to assume DS: " + e.getMessage());
			return;
		}
		RTLinkProgram.markDataSegmentAssumed(program);
		// Msg.info only, never log.appendMsg: any content in the analysis MessageLog makes
		// AutoAnalysisPlugin.analysisEnded() pop a "There were warnings/errors issued during
		// analysis" dialog. The MessageLog above is for the paths where DS could not be assumed.
		Msg.info(RTLinkOverlayAnalyzer.class, String.format(
			"RTLink: Assuming DS = 0x%04X (DGROUP) over %d executable blocks; skipped %d " +
				"RTLink runtime block(s), where DS is not DGROUP",
			dgroup, blocks, runtime.size()));
	}

	/**
	 * The executable blocks holding the RTLink runtime, which the DS assumption does not
	 * cover.
	 *
	 * <p>{@code DS == DGROUP} is a property of compiler-generated code. The runtime is
	 * hand-written assembly, and it owns DS: the overlay manager reloads it throughout from
	 * its own saved-segment slots (in VICEROY.EXE, {@code MOV DS,word ptr CS:[0x3999]},
	 * {@code CS:[0x39a1]}, {@code CS:[0x39a5]}, and {@code MOV DS,CS} in its error paths),
	 * while the support code addresses every one of its variables CS-relative and never loads
	 * DS at all.
	 *
	 * <p>Leaving DS unset over these blocks is the honest state — we do not know what DS holds
	 * at an arbitrary point in the runtime — and it is what makes {@link RTLinkXrefAnalyzer}
	 * decline them, since both its DS-relative pass and its address-of-immediate pass are gated
	 * on a present DS value. Were DGROUP asserted here instead, a {@code MOV BX,0x44a7} naming
	 * a string in the manager's own segment would resolve to {@code DGROUP:44a7} and plant a
	 * data reference on an unrelated global.
	 *
	 * <p>Both halves of the runtime carry a signature documented in {@code docs/rtlink-format.md}:
	 * the VM manager the fixup-loop fingerprint, the support code the RTLink error text (present
	 * even in section-only binaries, which have no VM manager and so no fingerprint). DGROUP's
	 * own block is never disowned, however those signatures happen to fall.
	 */
	static Set<MemoryBlock> findRuntimeCodeBlocks(Program program, int dgroup) {
		Memory memory = program.getMemory();
		Set<MemoryBlock> runtime = new HashSet<>();
		for (byte[] signature : List.of(RUNTIME_FIXUP_FINGERPRINT, RUNTIME_SIGNATURE)) {
			Address hit = memory.findBytes(memory.getMinAddress(), signature, null, true,
				TaskMonitor.DUMMY);
			if (hit == null) {
				continue;
			}
			MemoryBlock block = memory.getBlock(hit);
			if (block == null || !block.isExecute()) {
				continue;
			}
			if (block.getStart() instanceof SegmentedAddress start &&
				start.getSegment() == dgroup) {
				continue;
			}
			runtime.add(block);
		}
		return runtime;
	}

	/**
	 * Follow the entry's initial unconditional (far) jump into the C startup, then linearly
	 * decode instructions tracking each general register's last immediate. Returns the segment
	 * value moved into SS or DS (DGROUP), or null if not found within {@link #STARTUP_SCAN_LIMIT}
	 * instructions. Decoding is done with a {@link PseudoDisassembler} so it works before the
	 * program is disassembled and commits nothing.
	 */
	private static Integer detectDataSegment(Program program, Address entry) {
		Register ss = program.getLanguage().getRegister("SS");
		Register ds = program.getLanguage().getRegister("DS");
		PseudoDisassembler disassembler = new PseudoDisassembler(program);

		// Follow the entry's first unconditional jump (entry -> ... -> startup).
		Address addr = entry;
		for (int i = 0; i < 8 && addr != null; i++) {
			PseudoInstruction instr = CodeSeeds.decode(disassembler, addr);
			if (instr == null) {
				break;
			}
			FlowType flow = instr.getFlowType();
			if (flow.isJump() && !flow.isConditional()) {
				Address[] flows = instr.getFlows();
				if (flows != null && flows.length == 1) {
					addr = flows[0];
					break;
				}
			}
			addr = nextLinear(instr);
		}
		if (addr == null) {
			addr = entry;
		}

		// Linearly decode the startup, watching for the SS/DS segment load.
		Map<Register, Long> regImm = new HashMap<>();
		for (int i = 0; i < STARTUP_SCAN_LIMIT; i++) {
			PseudoInstruction instr = CodeSeeds.decode(disassembler, addr);
			if (instr == null) {
				return null;
			}
			if ("MOV".equals(instr.getMnemonicString())) {
				Register dest = X86.movDestination(instr);
				if (dest != null && (dest.equals(ss) || dest.equals(ds))) {
					Register src = X86.movSourceRegister(instr);
					Long imm = src != null ? regImm.get(src) : null;
					if (imm != null) {
						return (int) (imm.longValue() & 0xffffL);
					}
				}
				else if (dest != null) {
					int type = instr.getOperandType(1);
					Register src = X86.movSourceRegister(instr);
					Scalar scalar = instr.getScalar(1);
					if (scalar != null && OperandType.isScalar(type) &&
						!OperandType.isAddress(type)) {
						// A true immediate (not a memory displacement like [0x2]).
						regImm.put(dest, scalar.getUnsignedValue());
					}
					else if (src != null && regImm.containsKey(src)) {
						regImm.put(dest, regImm.get(src));
					}
					else {
						regImm.remove(dest);
					}
				}
			}
			else {
				// Any other write to a tracked register invalidates its known immediate.
				for (Object result : instr.getResultObjects()) {
					if (result instanceof Register reg) {
						regImm.remove(reg);
					}
				}
			}
			addr = nextLinear(instr);
			if (addr == null) {
				return null;
			}
		}
		return null;
	}

	/** The next physical instruction address (fall-through preferred), or null past the block. */
	private static Address nextLinear(PseudoInstruction instr) {
		Address fallThrough = instr.getFallThrough();
		if (fallThrough != null) {
			return fallThrough;
		}
		try {
			return instr.getAddress().add(instr.getLength());
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}
}
