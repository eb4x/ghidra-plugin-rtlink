package ebbex.rtlink;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Turn a resolved dispatch stub or resident-target trampoline into a thunk of its target, so
 * every call through it decompiles as a far call to the real function.
 */
final class StubThunks {

	// Far calling convention (x86-16.cspec: extrapop=4, stackshift=4) stamped on every
	// stub/trampoline target so thunk call sites model the far return address and decode
	// their arguments at the correct stack offsets.
	private static final String FAR_CALLING_CONVENTION = "__cdecl16far";

	private StubThunks() {
	}

	/**
	 * Wire {@code stubAddr} to {@code targetAddr} as a thunk.
	 *
	 * @return true if the stub is resolved (a thunk to its target now exists at it),
	 *         false if resolution failed or the site was skipped — the caller only
	 *         clears the stub's stale ERROR bookmarks when this returns true, so a
	 *         genuine decode failure keeps its mark.
	 */
	static boolean create(FunctionManager funcMgr, Address stubAddr, Address targetAddr,
			int stubSize, MessageLog log) {
		if (!wire(funcMgr, stubAddr, targetAddr, stubSize, log)) {
			return false;
		}
		showTargetName(funcMgr.getFunctionAt(stubAddr));
		return true;
	}

	/**
	 * Let a stub thunk display its target's name, so every call through the stub
	 * decompiles as a call to the overlay function rather than to the gate.
	 * <p>
	 * A thunk created over an existing label takes that label as its own name, and an
	 * explicitly named thunk prints that name at its call sites. So reset an
	 * analysis-given {@code OVLSTUB_} name to default (a default-named thunk shows its
	 * target's name, renames included). The gate name moves into the stub's plate
	 * comment: it cannot stay a symbol, because Ghidra renames a default-named function
	 * to any label created at its entry, in any namespace. A name anyone else gave the
	 * stub stays.
	 */
	private static void showTargetName(Function stub) {
		Symbol symbol = stub.getSymbol();
		String gate = symbol.getName();
		if (symbol.getSource() != SourceType.ANALYSIS ||
			!gate.startsWith(OverlayNames.STUB_PREFIX)) {
			return;
		}
		try {
			stub.setName(null, SourceType.DEFAULT);
			CodeUnit cu = stub.getProgram().getListing().getCodeUnitAt(stub.getEntryPoint());
			if (cu != null) {
				cu.setComment(CommentType.PLATE,
					gatePlate(gate, cu.getComment(CommentType.PLATE)));
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.warn(RTLinkOverlayAnalyzer.class,
				"RTLink: could not show the target name on stub " + gate + ": " +
					e.getMessage());
		}
	}

	/** {@code existing} plate comment plus the line naming {@code gate}, once. */
	static String gatePlate(String gate, String existing) {
		String line = "RTLink dispatch stub " + gate;
		if (existing == null || existing.isBlank()) {
			return line;
		}
		return existing.contains(line) ? existing : existing + "\n" + line;
	}

	private static boolean wire(FunctionManager funcMgr, Address stubAddr, Address targetAddr,
			int stubSize, MessageLog log) {
		// A CALLF+JMPF pair inside a larger function's body is fallthrough-reachable
		// code, not a free-standing stub — the overlay manager's own code contains
		// guarded dispatcher calls (TEST flag / JNZ past / CALLF dispatcher / JMPF)
		// whose tail is byte-identical to a trampoline. Carving a thunk there would
		// split the containing function, so leave the site alone.
		Function containing = funcMgr.getFunctionContaining(stubAddr);
		if (containing != null && !containing.getEntryPoint().equals(stubAddr)) {
			Msg.debug(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink: skipping stub thunk at %s -> %s: embedded in %s at %s",
				stubAddr, targetAddr, containing.getName(), containing.getEntryPoint()));
			return false;
		}

		Function overlayFunc = funcMgr.getFunctionAt(targetAddr);
		if (overlayFunc == null) {
			Program program = funcMgr.getProgram();
			if (program.getListing().getInstructionAt(targetAddr) == null) {
				// The stub's target never became code. Creating a function anyway
				// would plant a 1-byte husk over undefined bytes -- worse than no
				// function at all, because it looks resolved to every downstream
				// consumer. Leave the stub unthunked and say so.
				log.appendMsg(String.format(
					"RTLink: no code at target %s for stub %s; stub left unthunked",
					targetAddr, stubAddr));
				return false;
			}
			// The target is code but the bulk CreateFunctionCmd did not cover it
			// (e.g. the repair path found a new stub). Create it with a real
			// flow-computed body, never a fabricated 1-byte one.
			new CreateFunctionCmd(targetAddr).applyTo(program);
			overlayFunc = funcMgr.getFunctionAt(targetAddr);
			if (overlayFunc == null) {
				log.appendMsg(String.format(
					"RTLink: could not create target function at %s for stub %s " +
						"(target is likely inside another function's body)",
					targetAddr, stubAddr));
				return false;
			}
		}

		// A thunk delegates its signature to its target, so a far call site only decodes
		// correctly when the target carries a far convention. Stamp it before wiring.
		stampFarConvention(overlayFunc, log);

		// A no-return flag on the overlay target truncates the decompilation of every
		// caller of every stub that forwards to it: stub thunks delegate hasNoReturn()
		// to their target. Ghidra's no-return discovery mis-fires on dispatch stubs
		// while overlay flow is still unresolved (the stub's JMPF 0000:offset decodes
		// as a jump into unmapped memory), and setNoReturn(true) on the stub thunk
		// lands on the overlay target. If the target's disassembled body demonstrably
		// returns, the flag is stale — clear it.
		if (overlayFunc.hasNoReturn() && StaleNoReturns.bodyReturns(overlayFunc)) {
			// A repair, not a failure: Msg.info, not the analysis MessageLog.
			Msg.info(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink: clearing stale no-return flag on %s at %s (body returns)",
				overlayFunc.getName(), targetAddr));
			overlayFunc.setNoReturn(false);
		}

		Function existingStub = funcMgr.getFunctionAt(stubAddr);
		if (existingStub != null) {
			// Already the correct thunk (e.g. a re-run) — nothing to do.
			if (existingStub.isThunk() &&
				overlayFunc.equals(existingStub.getThunkedFunction(false))) {
				return true;
			}
			try {
				// Clear any no-return flag discovered while the stub was still a
				// plain function before converting it: a dispatch stub returns iff
				// its overlay target returns.
				existingStub.setNoReturn(false);
				existingStub.setThunkedFunction(overlayFunc);
				return true;
			}
			catch (IllegalArgumentException e) {
				// A plain function was already carved at the stub (auto-analysis
				// reaches it from a real CALLF before we run) and cannot be
				// converted in place. Remove it and recreate below as a thunk so
				// the stub still forwards to its overlay target.
				Msg.info(RTLinkOverlayAnalyzer.class, String.format(
					"RTLink: recreating stub thunk at %s -> %s (%s)",
					stubAddr, targetAddr, e.getMessage()));
				funcMgr.removeFunction(stubAddr);
			}
		}

		try {
			AddressSet stubBody = new AddressSet(stubAddr, stubAddr.add(stubSize - 1));
			funcMgr.createThunkFunction(null, null, stubAddr, stubBody,
				overlayFunc, SourceType.ANALYSIS);
			return true;
		}
		catch (OverlappingFunctionException e) {
			log.appendMsg(String.format(
				"RTLink: could not create stub thunk at %s -> %s: %s",
				stubAddr, targetAddr, e.getMessage()));
			return false;
		}
	}

	/**
	 * Stamp {@code __cdecl16far} on a stub/trampoline target whose signature Ghidra has
	 * not yet pinned down. A thunk delegates its signature to its target, so a far call
	 * site only decodes correctly when the target carries a far convention; left on the
	 * x86-16 default (near) convention the target models its parameters one stack slot
	 * too low and every caller decompiles with a junk leading argument that swallows a
	 * real one. Every function reached through a jump-table dispatch stub or a resident
	 * trampoline is far-called by construction, so this is safe for exactly that set.
	 * User-provided signatures are never touched, and the default/unknown-convention
	 * guard makes re-runs idempotent (a second pass sees the convention already set).
	 */
	private static void stampFarConvention(Function overlayFunc, MessageLog log) {
		SourceType sigSource = overlayFunc.getSignatureSource();
		if (sigSource != SourceType.DEFAULT && sigSource != SourceType.ANALYSIS) {
			return;
		}
		String convention = overlayFunc.getCallingConventionName();
		boolean conventionUnset = overlayFunc.getCallingConvention() == null ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention);
		if (!conventionUnset) {
			return;
		}
		try {
			overlayFunc.setCallingConvention(FAR_CALLING_CONVENTION);
		}
		catch (InvalidInputException e) {
			log.appendMsg(String.format("RTLink: could not set %s on %s at %s: %s",
				FAR_CALLING_CONVENTION, overlayFunc.getName(), overlayFunc.getEntryPoint(),
				e.getMessage()));
		}
	}
}
