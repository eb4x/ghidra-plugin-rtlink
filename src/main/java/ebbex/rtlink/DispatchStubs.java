package ebbex.rtlink;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Find the RTLink jump table's dispatch stubs and resident-target trampolines, disassemble
 * what they lead to, and wire each one to its target as a thunk. The stub formats are
 * described on {@link RTLinkOverlayAnalyzer}, and in full in {@code docs/rtlink-format.md}.
 */
final class DispatchStubs {

	private static final int PAGE_ID_MASK = 0x3FFF;

	// A real overlay dispatcher is the CALLF target shared by many stubs. Any
	// physical address hit by at least this many CALLF+JMPF stub candidates is
	// treated as a dispatcher, replacing the old hardcoded 0x0DAB dispatch offset
	// so the analyzer adapts to binaries linked with the dispatcher elsewhere.
	private static final int MIN_DISPATCHER_STUB_COUNT = 4;

	/** A resolved dispatch stub awaiting thunk creation once its target is a real function. */
	private record StubTarget(Address stubAddr, Address targetAddr, int stubSize) {
	}

	private DispatchStubs() {
	}

	/**
	 * Resolve the dispatch stubs and trampolines, adding the body of every stub resolved to
	 * {@code resolvedBodies}. The VM runtime entries are seeded here and nowhere else, and only
	 * where real CALLF+JMPF stubs corroborate the scheme.
	 */
	static void resolve(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet resolvedBodies, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		AddressSet overlayEntryPoints = new AddressSet();
		List<StubTarget> pendingThunks = new ArrayList<>();
		Map<String, SortedSet<Integer>> stubModuleBases = new HashMap<>();

		Map<Long, Integer> dispatcherSegs = discoverDispatchers(program, monitor);
		Set<Long> dispatchers = dispatcherSegs.keySet();
		if (!dispatchers.isEmpty()) {
			Msg.debug(RTLinkOverlayAnalyzer.class, "RTLink/Plus: Discovered " +
				dispatchers.size() + " overlay dispatcher entry point(s)");
		}

		int jmpfStubs = scanForJmpfStubs(program, overlayBlocks, dispatchers,
			overlayEntryPoints, pendingThunks, stubModuleBases, monitor);

		// The stubs are the only place a module carrying no relocations is named, so
		// fold what they revealed into each page's module base set before the switch
		// table analyzer reads it back.
		ModuleSegments.mergeStubBases(program, overlayBlocks, stubModuleBases);
		// Before anything below decodes overlay code: cseg cannot be set over it afterwards.
		ModuleSegments.assign(program, log);

		// Resident-target trampolines share the jump table with the CALLF+JMPF
		// dispatch stubs, so only look for them once segment-0 stubs have
		// corroborated that this binary uses that scheme (a shared CALLF+JMPF pair count
		// alone is a weaker signal when the JMPF segment is a plausible real value).
		AddressSet trampolineTargets = new AddressSet();
		List<StubTarget> pendingTrampolines = new ArrayList<>();
		int trampolines = 0;
		if (jmpfStubs > 0) {
			trampolines = scanForResidentTrampolines(program, dispatchers,
				trampolineTargets, pendingTrampolines, monitor);
		}

		if (jmpfStubs == 0 && trampolines == 0) {
			log.appendMsg("RTLink: No dispatch stubs found");
			return;
		}

		if (jmpfStubs > 0) {
			// Disassemble the overlay code reachable from the resolved entry points and
			// promote each entry point to a function with a real body. Without this the
			// overlay pages hold no instructions, so intra-overlay calls and jumps never
			// get references and every overlay "function" is a one-byte husk.
			disassembleOverlayCode(program, overlayBlocks, overlayEntryPoints, log, monitor);
			// Now that the overlay targets are real functions, wire each dispatch stub to
			// its target as a thunk.
			wireThunks(program, pendingThunks, resolvedBodies, log, monitor);
		}

		if (trampolines > 0) {
			disassembleResidentTargets(program, trampolineTargets, log, monitor);
			wireThunks(program, pendingTrampolines, resolvedBodies, log, monitor);
		}

		Msg.info(RTLinkOverlayAnalyzer.class, "RTLink/Plus: Resolved " + jmpfStubs +
			" dispatch stub(s) and " + trampolines + " resident-target trampoline(s)");

		// Only a corroborated VM-nucleus binary (real CALLF+JMPF stubs) gets its runtime
		// entry points seeded.
		if (jmpfStubs > 0) {
			VmRuntimeSeeds.seed(program, dispatcherSegs, log, monitor);
		}
	}

	/** Wire each stub to its target as a thunk, clearing the stale marks of those resolved. */
	private static void wireThunks(Program program, List<StubTarget> stubs,
			AddressSet resolvedBodies, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager funcMgr = program.getFunctionManager();
		for (StubTarget stub : stubs) {
			monitor.checkCancelled();
			if (StubThunks.create(funcMgr, stub.stubAddr(), stub.targetAddr(), stub.stubSize(),
				log)) {
				clearErrorBookmarks(program, stub, resolvedBodies, monitor);
			}
		}
	}

	/**
	 * Discover overlay dispatcher entry points instead of hardcoding one offset.
	 * <p>
	 * Every dispatch stub begins with {@code CALLF seg:disp} immediately followed by
	 * {@code JMPF ...}. The dispatcher is therefore the CALLF target shared by a large
	 * number of such CALLF+JMPF pairs. This scans every executable non-overlay block,
	 * tallies the physical CALLF target of each candidate pair, and returns those hit at
	 * least {@link #MIN_DISPATCHER_STUB_COUNT} times. Keying on the physical (flat)
	 * address collapses the many segment:offset aliases that resolve to one dispatcher.
	 * <p>
	 * Each dispatcher maps to its <b>stub-declared segment</b> — the CS the stubs' CALLF
	 * operands carry, i.e. the segment the VM nucleus actually runs in. That segment, not
	 * the canonical segment Ghidra happens to display a nucleus address under, is what
	 * {@link VmRuntimeSeeds} must resolve the dispatch immediates against.
	 */
	static Map<Long, Integer> discoverDispatchers(Program program, TaskMonitor monitor)
			throws CancelledException {
		Memory memory = program.getMemory();
		SegmentedAddressSpace space = X86.space(program);
		Map<Long, Integer> counts = new HashMap<>();
		Map<Long, Integer> stubSegments = new HashMap<>();

		CodeSeeds.scanResident(memory, new byte[] { X86.OPCODE_CALLF }, monitor, callf -> {
			Address jmpfAddr = callf.add(5);
			if (!CodeSeeds.isResidentCode(memory, jmpfAddr) ||
				memory.getByte(jmpfAddr) != X86.OPCODE_JMPF) {
				return false;
			}
			int off = Short.toUnsignedInt(memory.getShort(callf.add(1)));
			int seg = Short.toUnsignedInt(memory.getShort(callf.add(3)));
			long target = space.getAddress(seg, off).getOffset();
			counts.merge(target, 1, Integer::sum);
			stubSegments.putIfAbsent(target, seg);
			return true;
		});

		Map<Long, Integer> dispatchers = new HashMap<>();
		for (Map.Entry<Long, Integer> e : counts.entrySet()) {
			if (e.getValue() >= MIN_DISPATCHER_STUB_COUNT) {
				dispatchers.put(e.getKey(), stubSegments.get(e.getKey()));
			}
		}
		return dispatchers;
	}

	/**
	 * Disassemble overlay code starting from the resolved stub entry points, following
	 * intra-page flow but staying within the overlay blocks, then create a function with
	 * a computed body at each entry point.
	 * <p>
	 * This is what makes overlay code visible to the rest of Ghidra: the disassembler
	 * creates flow references for the near calls and jumps between overlay routines (which
	 * {@code OperandReferenceAnalyzer} never creates for 16-bit spaces), and the follow-on
	 * far-call analyzer then wires overlay-to-main references.
	 */
	private static void disassembleOverlayCode(Program program,
			List<OverlayBlockInfo> overlayBlocks, AddressSet overlayEntryPoints, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		if (overlayEntryPoints.isEmpty()) {
			return;
		}

		AddressSet overlayRange = new AddressSet();
		for (OverlayBlockInfo info : overlayBlocks) {
			overlayRange.add(info.block().getStart(), info.block().getEnd());
		}

		DisassembleCommand disCmd =
			new DisassembleCommand(overlayEntryPoints, overlayRange, true);
		if (!CodeSeeds.plant(program, disCmd, overlayEntryPoints, "overlay entry point", log,
			monitor)) {
			log.appendMsg("RTLink: Overlay disassembly reported: " + disCmd.getStatusMsg());
		}

		AddressSetView disassembled = disCmd.getDisassembledAddressSet();
		long byteCount = disassembled == null ? 0 : disassembled.getNumAddresses();
		Msg.debug(RTLinkOverlayAnalyzer.class, String.format(
			"RTLink/Plus: Disassembled %d overlay byte(s) from %d entry point(s)",
			byteCount, overlayEntryPoints.getNumAddresses()));
	}

	/**
	 * Index {@code overlayBlocks} by overlay record index (= page index). Stub scans
	 * look pages up by record index rather than list position, so a record skipped for
	 * having no code cannot shift every later page onto the wrong block.
	 */
	private static Map<Integer, OverlayBlockInfo> blocksByRecord(
			List<OverlayBlockInfo> overlayBlocks) {
		Map<Integer, OverlayBlockInfo> byRecord = new HashMap<>();
		for (OverlayBlockInfo info : overlayBlocks) {
			byRecord.put(info.page().getPageIndex(), info);
		}
		return byRecord;
	}

	/**
	 * Scan for dispatch stubs by finding JMPF instructions with segment 0x0000, then
	 * validating that a CALLF to a {@link #discoverDispatchers discovered dispatcher}
	 * precedes them.
	 * <p>
	 * Stub layout (12 or 14 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo 00 00   JMPF 0000:offset
	 *   [10-11] pp pp             page_id (bits 0-13 = 1-based descriptor index)
	 *   [12-13] mm mm             module_word (14-byte form only)
	 * </pre>
	 * page_id is a 1-based descriptor index over the overlay records: page_id N targets
	 * record N - 1, so page_id 1 is record 0 — a real code page, not (as an earlier
	 * revision assumed) a non-code global table.
	 * The JMPF offset is relative to the target module's base paragraph within the
	 * page: 12-byte stubs target module 0, so it is the in-page code offset directly;
	 * 14-byte stubs carry the module's base paragraph in module_word, and the in-page
	 * code offset is JMPF offset + module_word * 16.
	 * <p>
	 * Nothing in page_id flags the stub length (bits 14-15 are always clear), so the
	 * two forms are told apart structurally: if the bytes at +12 begin another
	 * dispatcher stub (a CALLF whose target is a discovered dispatcher), the stub is
	 * 12 bytes; otherwise a word at +12 smaller than the page's total paragraph count
	 * is a module_word. The module_word cannot be validated against the page's
	 * relocation seg_index values ({@link RTLinkOverlayPage#getModuleBases()}) — a
	 * module referenced only by stubs never appears there. Every module_word observed
	 * here is collected into {@code stubModuleBases}, keyed by overlay block name, so
	 * {@link ModuleSegments#mergeStubBases} can complete each page's set with exactly those
	 * modules the relocation table cannot name.
	 */
	private static int scanForJmpfStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			Set<Long> dispatchers, AddressSet overlayEntryPoints,
			List<StubTarget> pendingThunks, Map<String, SortedSet<Integer>> stubModuleBases,
			TaskMonitor monitor) throws CancelledException {
		if (overlayBlocks.isEmpty() || dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		SegmentedAddressSpace space = X86.space(program);
		Map<Integer, OverlayBlockInfo> blocksByRecord = blocksByRecord(overlayBlocks);
		int width = OverlayNames.width(OverlayNames.maxRecordIndex(overlayBlocks));
		int[] moduleResolved = { 0 };

		int count = CodeSeeds.scanResident(memory, new byte[] { X86.OPCODE_JMPF }, monitor, jmpf -> {
			// Need 5 bytes before (CALLF) and 7 bytes after (JMPF + page_id)
			Address callfAddr = jmpf.subtract(5);
			Address pageIdAddr = jmpf.add(5);
			if (!CodeSeeds.isResidentCode(memory, callfAddr) ||
				!CodeSeeds.isResidentCode(memory, pageIdAddr.add(1))) {
				return false;
			}

			int targetSegment = Short.toUnsignedInt(memory.getShort(jmpf.add(3)));
			if (targetSegment != 0x0000) {
				return false;
			}

			// Validate CALLF opcode and that it targets a discovered dispatcher.
			byte callfOpcode = memory.getByte(callfAddr);
			int callfOffset = Short.toUnsignedInt(memory.getShort(callfAddr.add(1)));
			int callfSegment = Short.toUnsignedInt(memory.getShort(callfAddr.add(3)));
			long callfTarget = space.getAddress(callfSegment, callfOffset).getOffset();
			if (callfOpcode != X86.OPCODE_CALLF || !dispatchers.contains(callfTarget)) {
				return false;
			}

			int jmpfOffset = Short.toUnsignedInt(memory.getShort(jmpf.add(1)));
			int pageId = Short.toUnsignedInt(memory.getShort(pageIdAddr));
			// The stored value is a 1-based descriptor index: descriptor N is
			// overlay record N - 1, so page_id 1 targets record 0 (a real code
			// page — see RTLinkOverlayAnalyzer's class javadoc). pageNumber is the
			// record index, shared by the OVLSTUB/OVL labels and the OVERLAY_NN
			// block names.
			int descriptorIndex = pageId & PAGE_ID_MASK;
			int pageNumber = descriptorIndex - 1;

			OverlayBlockInfo target = blocksByRecord.get(pageNumber);
			if (target == null) {
				return false;
			}

			// Distinguish the 12- and 14-byte stub forms (see the method javadoc):
			// the bytes at +12 either begin the next stub (12-byte form, module 0)
			// or hold the target module's base paragraph within the page.
			int stubSize = 12;
			int moduleBase = 0;
			Address moduleWordAddr = callfAddr.add(12);
			if (CodeSeeds.isResidentCode(memory, moduleWordAddr.add(1)) &&
				!isDispatcherCallf(memory, space, dispatchers, moduleWordAddr)) {
				int word = Short.toUnsignedInt(memory.getShort(moduleWordAddr));
				if (word < target.page().getHeader().getTotalParagraphs()) {
					stubSize = 14;
					moduleBase = word;
				}
			}
			int targetOffset = jmpfOffset + moduleBase * 16;

			Address targetAddr = target.block().getStart().add(targetOffset);
			if (!target.block().contains(targetAddr)) {
				return false;
			}

			// Only now that the stub has fully checked out is its module_word
			// trustworthy enough to record as one of the page's module bases.
			if (moduleBase != 0) {
				stubModuleBases
						.computeIfAbsent(target.block().getName(), k -> new TreeSet<>())
						.add(moduleBase);
				moduleResolved[0]++;
			}

			Address stubAddr = callfAddr;
			refManager.addMemoryReference(stubAddr, targetAddr,
				RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

			CodeSeeds.label(symbolTable,
				String.format(OverlayNames.STUB_PREFIX + "%0" + width + "d_%04X",
					pageNumber, targetOffset),
				stubAddr);
			CodeSeeds.label(symbolTable,
				String.format("OVL%0" + width + "d_%04X", pageNumber, targetOffset),
				targetAddr);

			overlayEntryPoints.add(targetAddr);
			pendingThunks.add(new StubTarget(stubAddr, targetAddr, stubSize));
			return true;
		});
		if (moduleResolved[0] > 0) {
			Msg.debug(RTLinkOverlayAnalyzer.class, "RTLink/Plus: " + moduleResolved[0] +
				" stub(s) resolved through a nonzero module base");
		}
		return count;
	}

	/**
	 * Returns true if the 5 bytes at {@code addr} form a far call to one of the
	 * discovered overlay dispatchers — i.e. the start of another dispatch stub.
	 */
	private static boolean isDispatcherCallf(Memory memory, SegmentedAddressSpace space,
			Set<Long> dispatchers, Address addr) {
		try {
			if (!CodeSeeds.isResidentCode(memory, addr) ||
				!CodeSeeds.isResidentCode(memory, addr.add(4))) {
				return false;
			}
			if (memory.getByte(addr) != X86.OPCODE_CALLF) {
				return false;
			}
			int off = Short.toUnsignedInt(memory.getShort(addr.add(1)));
			int seg = Short.toUnsignedInt(memory.getShort(addr.add(3)));
			return dispatchers.contains(space.getAddress(seg, off).getOffset());
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Scan for resident-target trampolines in the RTLink jump table.
	 * <p>
	 * Trampoline layout (10 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo ss ss   JMPF seg:off     (relocated resident target)
	 * </pre>
	 * RTLink routes far calls from (movable) overlay code into resident code through
	 * these shims: the dispatcher entry re-vectors the caller's far return address in
	 * case its overlay page moves, then the JMPF tail-jumps to the real function —
	 * semantically a plain far call. Trampolines are told apart from overlay dispatch
	 * stubs by the JMPF segment: dispatch stubs carry the unrelocated {@code 0000},
	 * trampolines a real segment that lands in resident executable memory.
	 * <p>
	 * Each trampoline is queued for conversion into a thunk of its JMPF target. Left
	 * as plain functions they degrade decompilation at every call site: having no RET
	 * of their own, convention analysis leaves them on the default (near) convention,
	 * parameters are modeled one stack slot too low, and every caller decompiles with
	 * a junk leading argument that swallows a real one. A thunk delegates name,
	 * signature and (far) calling convention to the target.
	 */
	private static int scanForResidentTrampolines(Program program, Set<Long> dispatchers,
			AddressSet trampolineTargets, List<StubTarget> pendingThunks,
			TaskMonitor monitor) throws CancelledException {
		if (dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		SegmentedAddressSpace space = X86.space(program);
		int count = CodeSeeds.scanResident(memory, new byte[] { X86.OPCODE_JMPF }, monitor, jmpf -> {
			Address callfAddr = jmpf.subtract(5);
			if (!CodeSeeds.isResidentCode(memory, callfAddr) ||
				!CodeSeeds.isResidentCode(memory, jmpf.add(4))) {
				return false;
			}

			int targetSegment = Short.toUnsignedInt(memory.getShort(jmpf.add(3)));
			if (targetSegment == 0x0000) {
				// Unrelocated segment: an overlay dispatch stub, not a
				// trampoline (handled by scanForJmpfStubs).
				return false;
			}
			if (!isDispatcherCallf(memory, space, dispatchers, callfAddr)) {
				return false;
			}

			int targetOffset = Short.toUnsignedInt(memory.getShort(jmpf.add(1)));
			Address targetAddr = space.getAddress(targetSegment, targetOffset);
			if (!CodeSeeds.isResidentCode(memory, targetAddr)) {
				return false;
			}

			// A jump back into the trampoline's own bytes is not a trampoline.
			long delta = targetAddr.getOffset() - callfAddr.getOffset();
			if (delta >= 0 && delta < 10) {
				return false;
			}

			trampolineTargets.add(targetAddr);
			pendingThunks.add(new StubTarget(callfAddr, targetAddr, 10));
			return true;
		});

		if (count > 0) {
			Msg.debug(RTLinkOverlayAnalyzer.class,
				"RTLink/Plus: Found " + count + " resident-target trampoline(s)");
		}
		return count;
	}

	/**
	 * Disassemble the resident trampoline targets and promote each to a function, so
	 * {@link StubThunks#create} has real functions to thunk to. Many targets are
	 * reachable only through the trampolines (far calls from overlay code), so regular
	 * flow analysis alone may never get there. Targets that land inside an existing
	 * function's body are left alone here and skipped by the thunk pass.
	 */
	private static void disassembleResidentTargets(Program program, AddressSet targets,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (targets.isEmpty()) {
			return;
		}

		DisassembleCommand disCmd = new DisassembleCommand(targets,
			CodeSeeds.residentCode(program.getMemory()), true);
		if (!CodeSeeds.plant(program, disCmd, targets, "trampoline target", log, monitor)) {
			log.appendMsg(
				"RTLink: Trampoline target disassembly reported: " + disCmd.getStatusMsg());
		}
	}

	/**
	 * Drop the disassembler's stale ERROR bookmarks from a stub we just resolved, and
	 * remember the stub's body in {@code resolvedBodies} so the analyzer's
	 * {@code analysisEnded} can sweep it again.
	 * <p>
	 * A dispatch stub's {@code JMPF 0000:offset} points into unmapped memory until the
	 * overlay manager patches it at run time, so every disassembly of the stub hits
	 * "Could not follow disassembly flow into non-existing memory" and drops an ERROR
	 * "Bad Instruction" bookmark. This analyzer relocates the page, resolves the stub
	 * and wires it to a real thunk target — which makes that mark a fossil — but nothing
	 * removed it: a fresh VICEROY.EXE import carried 540 ERROR bookmarks, every one of
	 * them on a correctly resolved stub. An error channel that is 100% false positives
	 * is worse than no channel: it is the disassembler's own record of what it could not
	 * decode, and it was reporting 540 broken things in a DB where nothing was broken.
	 * <p>
	 * Only resolved stubs are cleared and recorded. A stub whose resolution genuinely
	 * failed keeps its bookmark (and its log line), so {@code filter=error} still means
	 * something.
	 */
	private static void clearErrorBookmarks(Program program, StubTarget stub,
			AddressSet resolvedBodies, TaskMonitor monitor) throws CancelledException {
		AddressSet stubBody;
		try {
			stubBody = new AddressSet(stub.stubAddr(), stub.stubAddr().add(stub.stubSize() - 1));
		}
		catch (AddressOutOfBoundsException e) {
			// Stub body runs off the end of its block — nothing to clear.
			return;
		}
		// Clear both severities: a resolved stub whose overlay target offset is 0 carries a
		// JMPF 0000:0000 whose literal (unrelocated) operand the disassembler flags as a
		// WARNING ("flow into non-existing memory at 0000:0000"), while a conflicting decode
		// leaves an ERROR — both are stale once the stub is a thunk to its real target.
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(stubBody, BookmarkType.ERROR, monitor);
		bookmarkMgr.removeBookmarks(stubBody, BookmarkType.WARNING, monitor);
		resolvedBodies.add(stubBody);
	}
}
