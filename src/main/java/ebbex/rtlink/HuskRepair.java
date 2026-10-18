package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Find and repair "husk" functions: functions whose entry holds no instruction, so their body
 * collapsed to a single byte of undefined data. A restricted disassembly (the overlay pass)
 * once silently abandoned every pending call flow the first time one landed outside the
 * restriction, so intra-page near-call targets were never disassembled, and every later
 * {@code CreateFunctionCmd} on such a target fabricated a 1-byte body over the undefined bytes.
 * Call targets reached only through code that analysis never decoded still produce them.
 * <p>
 * Each husk entry is disassembled with unrestricted flow, its body recomputed, and call targets
 * newly exposed by that code are promoted to functions of their own. Every husk found is
 * counted; entries that still fail to disassemble are reported in the analysis log with target
 * and reason. {@link RTLinkOverlayAnalyzer} runs it from {@code analysisEnded}, after every
 * round that could fabricate a husk, and from {@code added} on the One Shot path.
 */
final class HuskRepair {

	private HuskRepair() {
	}

	static void repair(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager funcMgr = program.getFunctionManager();
		Memory memory = program.getMemory();

		List<Address> husks = new ArrayList<>();
		for (Function function : funcMgr.getFunctions(true)) {
			monitor.checkCancelled();
			if (function.isThunk() || function.isExternal()) {
				continue;
			}
			Address entry = function.getEntryPoint();
			MemoryBlock block = memory.getBlock(entry);
			if (block == null || !block.isExecute() || !block.isInitialized()) {
				continue;
			}
			if (listing.getInstructionAt(entry) == null &&
				listing.getInstructionContaining(entry) == null) {
				husks.add(entry);
				Msg.debug(RTLinkOverlayAnalyzer.class, "RTLink: husk function (no code at entry) " +
					function.getName() + " at " + entry);
			}
		}
		if (husks.isEmpty()) {
			return;
		}

		monitor.setMessage("RTLink: Repairing husk functions...");
		AddressSet repaired = new AddressSet();
		AddressSet newCode = new AddressSet();
		int failed = 0;
		for (Address entry : husks) {
			monitor.checkCancelled();
			DisassembleCommand disCmd = new DisassembleCommand(entry, null, true);
			disCmd.applyTo(program, monitor);
			if (listing.getInstructionAt(entry) == null) {
				log.appendMsg(String.format(
					"RTLink: husk function at %s could not be repaired: %s", entry,
					disCmd.getStatusMsg()));
				failed++;
				continue;
			}
			repaired.add(entry);
			AddressSetView disassembled = disCmd.getDisassembledAddressSet();
			if (disassembled != null) {
				newCode.add(disassembled);
			}
		}

		// The repair exposed new code; promote its call targets to functions so the
		// husk's callees (reachable only through it) become functions too.
		AddressSet callTargets = new AddressSet();
		ReferenceManager refMgr = program.getReferenceManager();
		AddressIterator sources = refMgr.getReferenceSourceIterator(newCode, true);
		while (sources.hasNext()) {
			monitor.checkCancelled();
			for (Reference ref : refMgr.getReferencesFrom(sources.next())) {
				Address target = ref.getToAddress();
				if (ref.getReferenceType().isCall() &&
					listing.getInstructionAt(target) != null &&
					funcMgr.getFunctionAt(target) == null) {
					callTargets.add(target);
				}
			}
		}
		if (!callTargets.isEmpty()) {
			new CreateFunctionCmd(callTargets, SourceType.ANALYSIS).applyTo(program, monitor);
		}

		// Recompute each repaired function's body from its now-real flow.
		for (Address entry : repaired.getAddresses(true)) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, listing.getInstructionAt(entry),
				monitor);
		}

		Msg.info(RTLinkOverlayAnalyzer.class, String.format(
			"RTLink: Repaired %d husk function(s) (no code at entry), " +
				"%d new function(s) at exposed call targets%s",
			repaired.getNumAddresses(), callTargets.getNumAddresses(),
			failed > 0 ? ", " + failed + " unrepairable" : ""));
	}
}
