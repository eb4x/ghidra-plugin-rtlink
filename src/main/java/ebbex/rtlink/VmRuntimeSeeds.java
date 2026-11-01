package ebbex.rtlink;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Seed the RTLink VM runtime's function starts that nothing else ever reaches: the MZ entry
 * stub's two far targets, and the nucleus entries the {@code $$VM_UNK} dispatch arms select by
 * constant pair. These are real, evidenced entries reached only through data (a patched return
 * slot, a register-indirect jump), so neither auto-analysis nor the decompiler's jump-table
 * recovery ever disassembles them. Naming beyond {@code __astart}/{@code $$VM_INITW} is
 * deliberately left to FID against the vendor's {@code vmnuc} objects — the nucleus ships in at
 * least nine build variants with shifting offsets, so only body hashes, never positions,
 * identify the rest.
 * <p>
 * Everything here is a no-op where an earlier run or hand analysis already claimed the address,
 * so the pass is safe to re-run.
 */
final class VmRuntimeSeeds {

	/**
	 * The VM nucleus's constant-pair dispatch — the shape ending each of {@code $$VM_UNK}'s
	 * two arms (transcribed from {@code vmnuc.asm} in the vendor's RTLUTILS.LIB, and present
	 * byte-identically in the VICEROY variant that matches no reference build):
	 *
	 * <pre>
	 *   +0   B8 ii ii            MOV  AX, imm16     ; vendor entry ($$VM_CALL / $$VM_JMP)
	 *   +3   BA ii ii            MOV  DX, imm16     ; inner entry, past that routine's prologue
	 *   +6   2E F6 06 aa aa FF   TEST byte CS:[flag], 0xFF
	 *   +12  74 06               JE   +6
	 *   +14  B8 ii ii            MOV  AX, imm16     ; flag-set pair ($$VM_CALLR / $$VM_JMPR)
	 *   +17  BA ii ii            MOV  DX, imm16
	 *   +20  89 44 FC            MOV  [SI-4], AX    ; return-slot patch
	 *   +23  FF E2               JMP  DX
	 * </pre>
	 *
	 * AX is stored into the caller's far-return offset slot, so both AX immediates are
	 * function entries (they are exactly the {@code $$VM_*} PUBDEF symbols in the vendor
	 * object); the DX immediates are jump targets inside those routines' bodies. All four
	 * resolve against the runtime CS the dispatch stubs call the dispatcher through — not
	 * against the site's canonical segment, which is why the stock constant analyzer's
	 * same-block resolution of this very shape is bogus (and stays deleted by
	 * {@link RTLinkDispatcherJumpAnalyzer}) while this one is exact.
	 */
	private static final byte[] VM_DISPATCH_PATTERN = {
		(byte) 0xB8, 0, 0, (byte) 0xBA, 0, 0,
		0x2E, (byte) 0xF6, 0x06, 0, 0, (byte) 0xFF,
		0x74, 0x06,
		(byte) 0xB8, 0, 0, (byte) 0xBA, 0, 0,
		(byte) 0x89, 0x44, (byte) 0xFC, (byte) 0xFF, (byte) 0xE2 };
	private static final byte[] VM_DISPATCH_MASK = {
		-1, 0, 0, -1, 0, 0,
		-1, -1, -1, 0, 0, -1,
		-1, -1,
		-1, 0, 0, -1, 0, 0,
		-1, -1, -1, -1, -1 };

	/** Pattern offsets of the two AX immediates — vendor function entries. */
	private static final int[] VM_DISPATCH_FUNCTION_IMMS = { 1, 15 };
	/** Pattern offsets of the two DX immediates — mid-routine jump targets. */
	private static final int[] VM_DISPATCH_FLOW_IMMS = { 4, 18 };

	private VmRuntimeSeeds() {
	}

	/**
	 * Seed the entry stub's targets and the dispatch targets of {@code dispatchers} (physical
	 * dispatcher address to the segment its stubs call it through); returns how many function
	 * entries were seeded.
	 */
	static int seed(Program program, Map<Long, Integer> dispatchers, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		AddressSet functionSeeds = new AddressSet();
		AddressSet flowSeeds = new AddressSet();
		PseudoDisassembler disassembler = new PseudoDisassembler(program);

		seedEntryStub(program, disassembler, functionSeeds);
		seedVmDispatchTargets(program, dispatchers, disassembler, functionSeeds, flowSeeds,
			monitor);

		if (functionSeeds.isEmpty() && flowSeeds.isEmpty()) {
			return 0;
		}

		// The disassembly status is not reported: verifyBecameCode names any seed that failed.
		CodeSeeds.plant(program,
			new DisassembleCommand(functionSeeds.union(flowSeeds),
				CodeSeeds.residentCode(program.getMemory()), true),
			functionSeeds, "VM runtime entry point", log, monitor);

		int count = (int) functionSeeds.getNumAddresses();
		RTLinkProgram.recordVmRuntimeSeeds(program, count);
		Msg.info(RTLinkOverlayAnalyzer.class, String.format(
			"RTLink/Plus: Seeded %d VM runtime function entr%s and %d dispatch flow target(s)",
			count, count == 1 ? "y" : "ies", flowSeeds.getNumAddresses()));
		return count;
	}

	/**
	 * The MZ entry of an RTLink/Plus VM program is the linker's own 10-byte stub — the
	 * vendor object's public {@code $$VM_INITW}: {@code CALLF <vm init body>} followed by
	 * {@code JMPF <startup>}, both operands carrying real MZ-relocated segments. Label the
	 * stub and the startup, and seed both far targets as functions: the init body is
	 * reached from nowhere else, and the JMPF tail-jump never makes the startup a function
	 * on its own. The startup label {@code __astart} is the MSC CRT's entry symbol — the
	 * corpus toolchain; on a non-MSC RTLink binary the function start would still be
	 * right and only the name conventional.
	 */
	private static void seedEntryStub(Program program, PseudoDisassembler disassembler,
			AddressSet functionSeeds) {
		Address entry = CodeSeeds.firstEntryPoint(program);
		if (entry == null) {
			return;
		}
		Memory memory = program.getMemory();
		SegmentedAddressSpace space = X86.space(program);
		try {
			if (memory.getByte(entry) != X86.OPCODE_CALLF ||
				memory.getByte(entry.add(5)) != X86.OPCODE_JMPF) {
				return;
			}
			Address initBody = space.getAddress(
				Short.toUnsignedInt(memory.getShort(entry.add(3))),
				Short.toUnsignedInt(memory.getShort(entry.add(1))));
			Address startup = space.getAddress(
				Short.toUnsignedInt(memory.getShort(entry.add(8))),
				Short.toUnsignedInt(memory.getShort(entry.add(6))));
			if (initBody.equals(startup) || initBody.equals(entry) || startup.equals(entry)) {
				return;
			}
			if (!CodeSeeds.isResidentCode(memory, initBody) ||
				!CodeSeeds.isResidentCode(memory, startup)) {
				return;
			}
			if (CodeSeeds.decode(disassembler, initBody) == null ||
				CodeSeeds.decode(disassembler, startup) == null) {
				return;
			}
			SymbolTable symbolTable = program.getSymbolTable();
			try {
				// Additional label: the loader's `entry` stays primary.
				symbolTable.createLabel(entry, "$$VM_INITW", SourceType.ANALYSIS);
			}
			catch (InvalidInputException _) {
				// ignore
			}
			CodeSeeds.label(symbolTable, "__astart", startup);
			functionSeeds.add(initBody);
			functionSeeds.add(startup);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException _) {
			// not the stub; leave the entry alone
		}
	}

	/**
	 * Scan each resident block holding a discovered dispatcher for
	 * {@link #VM_DISPATCH_PATTERN} sites and collect their immediates — AX pairs as
	 * function seeds, DX pairs as flow-only seeds — resolved against the dispatcher's
	 * stub-declared segment. A target must land in the same block and decode as an
	 * instruction, so a wrong segment or a data immediate fails closed.
	 */
	private static void seedVmDispatchTargets(Program program, Map<Long, Integer> dispatchers,
			PseudoDisassembler disassembler, AddressSet functionSeeds, AddressSet flowSeeds,
			TaskMonitor monitor) throws CancelledException {
		if (dispatchers.isEmpty()) {
			return;
		}
		Memory memory = program.getMemory();
		SegmentedAddressSpace space = X86.space(program);

		Map<MemoryBlock, Set<Integer>> segsByBlock = new HashMap<>();
		for (Map.Entry<Long, Integer> e : dispatchers.entrySet()) {
			int seg = e.getValue();
			long off = e.getKey() - seg * 16L;
			if (off < 0 || off > 0xffff) {
				continue;
			}
			MemoryBlock block = memory.getBlock(space.getAddress(seg, (int) off));
			if (block != null && !block.isOverlay()) {
				segsByBlock.computeIfAbsent(block, _ -> new HashSet<>()).add(seg);
			}
		}

		for (Map.Entry<MemoryBlock, Set<Integer>> e : segsByBlock.entrySet()) {
			MemoryBlock block = e.getKey();
			CodeSeeds.scan(memory, block, VM_DISPATCH_PATTERN, VM_DISPATCH_MASK, monitor, match -> {
				for (int seg : e.getValue()) {
					collectDispatchImms(memory, space, block, disassembler, match, seg,
						VM_DISPATCH_FUNCTION_IMMS, functionSeeds);
					collectDispatchImms(memory, space, block, disassembler, match, seg,
						VM_DISPATCH_FLOW_IMMS, flowSeeds);
				}
				return true;
			});
		}
	}

	/** Resolve and validate the pattern immediates at {@code immOffsets} into {@code seeds}. */
	private static void collectDispatchImms(Memory memory, SegmentedAddressSpace space,
			MemoryBlock block, PseudoDisassembler disassembler, Address match, int segment,
			int[] immOffsets, AddressSet seeds) {
		for (int off : immOffsets) {
			try {
				int imm = Short.toUnsignedInt(memory.getShort(match.add(off)));
				if (imm == 0) {
					continue;
				}
				Address target = space.getAddress(segment, imm);
				if (!block.contains(target)) {
					continue;
				}
				if (CodeSeeds.decode(disassembler, target) == null) {
					continue;
				}
				seeds.add(target);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException _) {
				// skip
			}
		}
	}
}
