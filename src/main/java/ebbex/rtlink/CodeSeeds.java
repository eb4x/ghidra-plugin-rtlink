package ebbex.rtlink;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * What the passes that plant code where analysis never reached have in common: deciding an
 * address is resident code, decoding it without committing anything, labelling it, and
 * checking afterwards that a seed really became code.
 */
final class CodeSeeds {

	private CodeSeeds() {
	}

	/**
	 * True if {@code addr} lies in resident code memory — an initialized, executable,
	 * non-overlay block.
	 * <p>
	 * Scans iterate blocks but must range-check against <em>memory</em>, not against the block
	 * they happen to be iterating: MZ segment blocks are contiguous in flat space, and a stub
	 * can straddle the boundary between two of them. VMEX1.EXE has one — its jump table's
	 * first stub begins two bytes before the end of the preceding segment block — and a
	 * per-block check silently dropped it, leaving the stub unresolved and its
	 * {@code JMPF 0000:xxxx} to be walked into unmapped memory.
	 */
	static boolean isResidentCode(Memory memory, Address addr) {
		MemoryBlock block = memory.getBlock(addr);
		return block != null && isResidentCode(block);
	}

	/** True for an initialized, executable, non-overlay block. */
	static boolean isResidentCode(MemoryBlock block) {
		return !block.isOverlay() && block.isExecute() && block.isInitialized();
	}

	/** Every resident code block: where resident seeds may flow. */
	static AddressSet residentCode(Memory memory) {
		AddressSet resident = new AddressSet();
		for (MemoryBlock block : memory.getBlocks()) {
			if (isResidentCode(block)) {
				resident.add(block.getStart(), block.getEnd());
			}
		}
		return resident;
	}

	/** Takes or passes on one pattern match. */
	interface Match {
		/** True if the match at {@code at} was taken. */
		boolean take(Address at) throws MemoryAccessException;
	}

	/** {@link #scan} every resident code block; returns how many matches were taken. */
	static int scanResident(Memory memory, byte[] pattern, TaskMonitor monitor, Match match)
			throws CancelledException {
		int taken = 0;
		for (MemoryBlock block : memory.getBlocks()) {
			if (isResidentCode(block)) {
				taken += scan(memory, block, pattern, null, monitor, match);
			}
		}
		return taken;
	}

	/**
	 * Offer every occurrence of {@code pattern} under {@code mask} in {@code block} to
	 * {@code match}, in address order; returns how many it took. A match whose bytes cannot
	 * be read, or that reaches past the address space, is not taken.
	 */
	static int scan(Memory memory, MemoryBlock block, byte[] pattern, byte[] mask,
			TaskMonitor monitor, Match match) throws CancelledException {
		int taken = 0;
		Address at = block.getStart();
		while (at != null && at.compareTo(block.getEnd()) < 0) {
			monitor.checkCancelled();
			at = memory.findBytes(at, block.getEnd(), pattern, mask, true, monitor);
			if (at == null) {
				break;
			}
			try {
				if (match.take(at)) {
					taken++;
				}
			}
			catch (MemoryAccessException | AddressOutOfBoundsException _) {
				// not a match
			}
			at = at.add(1);
		}
		return taken;
	}

	/**
	 * Apply {@code disassembly}, make a function with a computed body at each of
	 * {@code functionEntries}, and {@link #verifyBecameCode verify} each became code;
	 * {@code what} names an entry in the progress and failure messages. Returns what the
	 * disassembly's {@code applyTo} did, for a caller that reports its status.
	 */
	static boolean plant(Program program, DisassembleCommand disassembly,
			AddressSetView functionEntries, String what, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("RTLink: Disassembling " + what + "s...");
		boolean disassembled = disassembly.applyTo(program, monitor);
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating " + what + " functions...");
		new CreateFunctionCmd(functionEntries, SourceType.ANALYSIS).applyTo(program, monitor);

		verifyBecameCode(program, functionEntries, what, log, monitor);
		return disassembled;
	}

	/** The instruction at {@code addr}, decoded without committing it, or null. */
	static PseudoInstruction decode(PseudoDisassembler disassembler, Address addr) {
		try {
			return disassembler.disassemble(addr);
		}
		catch (Exception _) {
			return null;
		}
	}

	/** The program's first external entry point (the MZ entry), or null. */
	static Address firstEntryPoint(Program program) {
		AddressIterator it = program.getSymbolTable().getExternalEntryPointIterator();
		return it.hasNext() ? it.next() : null;
	}

	/** Label {@code addr} unless it already carries a name of its own. */
	static void label(SymbolTable symbolTable, String label, Address addr) {
		try {
			Symbol existing = symbolTable.getPrimarySymbol(addr);
			if (existing == null || existing.isDynamic()) {
				symbolTable.createLabel(addr, label, SourceType.ANALYSIS);
			}
		}
		catch (InvalidInputException _) {
			// ignore
		}
	}

	/**
	 * Verify that every entry point in {@code entryPoints} was actually disassembled.
	 * A seed the disassembler could not decode leaves {@link CreateFunctionCmd} to
	 * plant a 1-byte function over the undefined bytes -- a husk that looks resolved
	 * to every downstream consumer while hiding the failure. Tear such a husk down
	 * and report the entry: no function at all is strictly better than a function
	 * with no code.
	 */
	static void verifyBecameCode(Program program, AddressSetView entryPoints, String what,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager funcMgr = program.getFunctionManager();
		for (Address entry : entryPoints.getAddresses(true)) {
			monitor.checkCancelled();
			if (listing.getInstructionAt(entry) != null) {
				continue;
			}
			if (listing.getInstructionContaining(entry) != null) {
				// Offcut into existing code, not undefined bytes: a pre-existing
				// overlap the thunk pass reports on its own terms, not a silent
				// disassembly failure.
				continue;
			}
			Function husk = funcMgr.getFunctionAt(entry);
			if (husk != null && !husk.isThunk()) {
				funcMgr.removeFunction(entry);
			}
			log.appendMsg(String.format("RTLink: %s %s could not be disassembled%s", what,
				entry, husk != null ? "; removed the 1-byte husk function created over it"
						: "; no function created"));
		}
	}
}
