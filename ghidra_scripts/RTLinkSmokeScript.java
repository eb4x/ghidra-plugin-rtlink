// Smoke test for the RTLink extension: run as -postScript after a fresh import and
// auto-analysis of the committed sample, src/test/smoke/rtlink-sample.exe (see the smokeTest
// gradle task and RTLinkSampleGenerator, which documents the sample's layout).
//
// Every check is exact, because the sample is ours: each RTLink analyzer must leave the one
// result its part of the sample was built to produce, and where the user would see that result
// in the decompiler, it is checked there. Each failure prints an UNEXPECTED line; the verdict
// line is printed only when all checks pass, because analyzeHeadless exits 0 even when a
// post-script throws.
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;

public class RTLinkSmokeScript extends GhidraScript {

	// Resident segments as MzLoader places them (load segment 0x1000).
	private static final String TEXT = "1000";
	private static final String NUC = "1012";
	private static final int DGROUP = 0x101a;

	private final List<String> failures = new ArrayList<>();
	private DecompInterface decompiler;

	@Override
	protected void run() throws Exception {
		decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		try {
			checkOverlayBlocks();
			checkStubs();
			checkTrampolines();
			checkEntrySeeds();
			checkDataSegment();
			checkDataReferences();
			checkIntraPageCall();
			checkSwitch();
			checkEmulatedFloat();
			checkAbortPath();
			checkDispatcherJump();
			checkNoErrorBookmarks();
		}
		finally {
			decompiler.dispose();
		}
		if (failures.isEmpty()) {
			println("SMOKE OK");
		}
		else {
			println("smoke: " + failures.size() + " check(s) failed");
		}
	}

	private void fail(String message) {
		failures.add(message);
		println("UNEXPECTED: " + message);
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			fail(message);
		}
	}

	private Address seg(String segment, int offset) {
		return toAddr(segment + ":" + String.format("%04x", offset));
	}

	/** The address of the one symbol named {@code name}, or null (reported). */
	private Address symbol(String name) {
		SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
		if (!symbols.hasNext()) {
			fail("no symbol " + name);
			return null;
		}
		return symbols.next().getAddress();
	}

	// ---------------------------------------------------------------- overlay analyzer

	private void checkOverlayBlocks() {
		List<String> names = new ArrayList<>();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName().startsWith("OVERLAY_")) {
				names.add(block.getName());
			}
		}
		check(names.equals(List.of("OVERLAY_00", "OVERLAY_01", "OVERLAY_02")),
			"overlay blocks " + names + ", expected OVERLAY_00..02");
		println("smoke: overlay blocks " + names);
	}

	/**
	 * Each stub is a thunk of the overlay function its page_id, offset and module name. The
	 * thunk shows its target's name, so calls through it decompile as calls to the overlay
	 * function; the gate name is in the stub's plate comment.
	 */
	private void checkStubs() {
		checkStub(0x00, "OVLSTUB_00_0000", "OVL00_0000");
		checkStub(0x0c, "OVLSTUB_01_0000", "OVL01_0000");
		checkStub(0x18, "OVLSTUB_01_0020", "OVL01_0020"); // 14-byte form, module base 2
		checkStub(0x26, "OVLSTUB_02_0000", "OVL02_0000");

		Function main = getFunctionContaining(seg(TEXT, 0x26));
		String c = main == null ? null : decompile(main.getEntryPoint());
		if (c == null) {
			fail("main (calling stubs 0, 1 and 3) does not decompile");
			return;
		}
		for (String callee : List.of("OVL00_0000(", "OVL01_0000(", "OVL02_0000(")) {
			check(c.contains(callee), "decompiled main does not call " + callee + ")");
		}
		check(!c.contains("OVLSTUB_"), "decompiled main calls a stub by its gate name");
	}

	private void checkStub(int offset, String gate, String targetName) {
		Address stub = seg(NUC, offset);
		Address target = symbol(targetName);
		Function thunk = getFunctionAt(stub);
		if (thunk == null || !thunk.isThunk()) {
			fail(gate + " at " + stub + " is not a thunk");
			return;
		}
		Function thunked = thunk.getThunkedFunction(false);
		check(thunked != null && thunked.getEntryPoint().equals(target),
			gate + " thunks " + (thunked == null ? null : thunked.getEntryPoint()) +
				", expected " + targetName + " at " + target);
		check(thunk.getSymbol().getSource() == SourceType.DEFAULT &&
			thunk.getName().equals(targetName),
			gate + " is named " + thunk.getName() + ", expected its target's " + targetName);
		String plate = getPlateComment(stub);
		check(plate != null && plate.contains("RTLink dispatch stub " + gate),
			gate + " is not in the stub's plate comment: " + plate);
	}

	private void checkTrampolines() {
		checkTrampoline(0x32, 0x105);
		checkTrampoline(0x3c, 0x10d);
	}

	private void checkTrampoline(int offset, int residentTarget) {
		Function thunk = getFunctionAt(seg(NUC, offset));
		Address target = seg(TEXT, residentTarget);
		Function thunked = thunk == null ? null : thunk.getThunkedFunction(false);
		check(thunked != null && thunked.getEntryPoint().equals(target),
			"trampoline at " + seg(NUC, offset) + " does not thunk " + target);
	}

	/** The $$VM_INITW entry stub and the constant-pair dispatch both seed functions. */
	private void checkEntrySeeds() {
		Address startup = symbol("__astart");
		check(seg(TEXT, 0x0a).equals(startup), "__astart at " + startup + ", expected 1000:000a");
		check(getFunctionAt(seg(TEXT, 0x0a)) != null, "__astart is not a function");
		check(getFunctionAt(seg(NUC, 0x70)) != null, "the init body is not a function");
		check(getFunctionAt(seg(NUC, 0x64)) != null, "vm_call (dispatch AX pair) is not seeded");
		check(getFunctionAt(seg(NUC, 0x69)) != null, "vm_callr (dispatch AX pair) is not seeded");
		int seeds = currentProgram.getOptions(Program.PROGRAM_INFO)
				.getInt("RTLink VM Runtime Seeds", 0);
		check(seeds == 4, seeds + " VM runtime seeds, expected 4");
	}

	/** DS is assumed to be DGROUP over resident and overlay code alike. */
	private void checkDataSegment() {
		Register ds = currentProgram.getRegister("DS");
		for (Address at : List.of(seg(TEXT, 0x1c), symbol("OVL00_0000"))) {
			if (at == null) {
				continue;
			}
			var value = currentProgram.getProgramContext().getValue(ds, at, false);
			check(value != null && value.intValue() == DGROUP,
				"DS at " + at + " is " + value + ", expected 0x101a");
		}
	}

	// ---------------------------------------------------------------- xref analyzer

	private void checkDataReferences() {
		// main: PUSH g_buffer (address-of) and MOV AX,[g_count] (dereference)
		checkReference(seg(TEXT, 0x26), DGROUP, 0x30, "address-of g_buffer");
		checkReference(seg(TEXT, 0x1f), DGROUP, 0x20, "read of g_count");
		// record 0: MOV AX,[g_flag] in overlay code
		Address ovl0 = symbol("OVL00_0000");
		if (ovl0 != null) {
			checkReference(ovl0.add(3), DGROUP, 0x22, "overlay read of g_flag");
			String c = decompile(ovl0);
			check(c != null && c.contains("101a_0022"),
				"decompiled OVL00_0000 does not name g_flag at 101a:0022");
		}
	}

	private void checkReference(Address from, int segment, int offset, String what) {
		Address to = toAddr(String.format("%04x:%04x", segment, offset));
		for (Reference ref : getReferencesFrom(from)) {
			if (ref.getToAddress().equals(to)) {
				return;
			}
		}
		fail(what + ": no reference " + from + " -> " + to);
	}

	// ---------------------------------------------------------------- list-2 relocation

	/** ovl1_a's CALLF to the page's second module lands on OVL01_0020 once list 2 is applied. */
	private void checkIntraPageCall() {
		Address caller = symbol("OVL01_0000");
		Address callee = symbol("OVL01_0020");
		if (caller == null || callee == null) {
			return;
		}
		Instruction call = getInstructionAt(caller.add(7));
		if (call == null || !"CALLF".equals(call.getMnemonicString())) {
			fail("no CALLF at " + caller.add(7));
			return;
		}
		Address[] flows = call.getFlows();
		check(flows.length == 1 && flows[0].equals(callee),
			"intra-page CALLF flows to " + java.util.Arrays.toString(flows) + ", expected " +
				callee);
	}

	// ---------------------------------------------------------------- switch analyzers

	/** The module-relative switch in record 1's second module, as the decompiler sees it. */
	private void checkSwitch() {
		Address entry = symbol("OVL01_0020");
		if (entry == null) {
			return;
		}
		DecompileResults results = decompileResults(entry);
		if (results == null) {
			return;
		}
		HighFunction high = results.getHighFunction();
		JumpTable[] tables = high.getJumpTables();
		if (tables.length != 1) {
			fail("OVL01_0020 decompiles with " + tables.length + " jump tables, expected 1");
			return;
		}
		// Case targets are page offsets: module base 0x20 plus the module-relative entries.
		Address page = entry.subtract(0x20);
		List<Address> expected = List.of(page.add(0x3b), page.add(0x40), page.add(0x45),
			page.add(0x4a));
		Address fallback = page.add(0x4f);
		List<Address> actual = new ArrayList<>();
		for (Address target : tables[0].getCases()) {
			if (!actual.contains(target) && !target.equals(fallback)) {
				actual.add(target);
			}
		}
		check(actual.equals(expected), "switch cases " + actual + ", expected " + expected);
		String c = results.getDecompiledFunction().getC();
		check(c.contains("switch"), "decompiled OVL01_0020 has no switch");
		println("smoke: switch in OVL01_0020 with " + actual.size() + " case targets");
	}

	// ---------------------------------------------------------------- emulated float

	private void checkEmulatedFloat() {
		Function fpu = getFunctionAt(seg(TEXT, 0x68));
		if (fpu == null) {
			fail("the float routine at 1000:0068 is not a function");
			return;
		}
		int interrupts = 0;
		int x87 = 0;
		for (Instruction insn : currentProgram.getListing().getInstructions(fpu.getBody(), true)) {
			String mnemonic = insn.getMnemonicString();
			if ("INT".equals(mnemonic)) {
				interrupts++;
			}
			else if (mnemonic.startsWith("F")) {
				x87++;
			}
		}
		check(interrupts == 0, interrupts + " emulator INTs left in the float routine");
		// six blocks of six, plus the ES: load from INT 3Ch; INT 3Dh becomes a plain WAIT
		check(x87 == 6 * 6 + 1, x87 + " x87 instructions in the float routine, expected 37");
		String c = decompile(fpu.getEntryPoint());
		check(c != null && !c.contains("swi("), "the float routine still decompiles to swi()");
	}

	// ---------------------------------------------------------------- flow repair

	private void checkAbortPath() {
		Function handler = getFunctionAt(seg(TEXT, 0x5f));
		check(handler != null, "the abort handler behind the code vector is not a function");
		Instruction call = getInstructionAt(seg(TEXT, 0x45));
		check(call != null && call.getFlowOverride() == FlowOverride.CALL_RETURN,
			"the call to the abort routine still falls through");
		check(getInstructionAt(seg(TEXT, 0x4a)) == null,
			"the zeroed table behind the abort call is decoded as code");
	}

	// ---------------------------------------------------------------- dispatcher jump

	/**
	 * Stock resolves the dispatcher's JMP DX against its 64KB page (1000:), not the nucleus
	 * segment (1012:), which puts the targets inside the float routine. The jump must end up
	 * with no computed reference, its plate comment saying why, and the routine undamaged.
	 */
	private void checkDispatcherJump() {
		Address jmp = seg(NUC, 0x62);
		Instruction insn = getInstructionAt(jmp);
		if (insn == null) {
			fail("no instruction at the dispatcher's JMP DX, " + jmp);
			return;
		}
		for (Reference ref : getReferencesFrom(jmp)) {
			if (ref.getReferenceType().isComputed()) {
				fail("JMP DX keeps a computed reference to " + ref.getToAddress());
			}
		}
		check(insn.getComment(CommentType.PLATE) != null,
			"the dispatcher's JMP DX was not neutralized (no plate comment)");
		// The page-relative targets 1000:0067 and 1000:006c fall mid-instruction in the
		// abort vector and the float routine's prologue.
		for (int offset : new int[] { 0x67, 0x6c }) {
			Instruction at = getInstructionContaining(seg(TEXT, offset));
			check(at == null || !at.getMinAddress().equals(seg(TEXT, offset)),
				"junk decoded at the bogus dispatcher target " + seg(TEXT, offset));
		}
		check(getInstructionAt(seg(TEXT, 0x6b)) != null,
			"the float routine's SUB SP,0x10 at 1000:006b is gone");
	}

	/** Every mis-decode the sample provokes is repaired, so no ERROR bookmark is left. */
	private void checkNoErrorBookmarks() {
		var bookmarks = currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (bookmarks.hasNext()) {
			Bookmark bookmark = bookmarks.next();
			fail("ERROR bookmark at " + bookmark.getAddress() + ": " + bookmark.getCategory() +
				" / " + bookmark.getComment());
		}
	}

	// ---------------------------------------------------------------- decompiler

	private DecompileResults decompileResults(Address entry) {
		Function function = getFunctionAt(entry);
		if (function == null) {
			fail("no function at " + entry);
			return null;
		}
		DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
		if (!results.decompileCompleted()) {
			fail("decompiling " + function.getName() + " failed: " + results.getErrorMessage());
			return null;
		}
		String c = results.getDecompiledFunction().getC();
		String error = results.getErrorMessage();
		if (c.contains("pcode error") || (error != null && error.contains("pcode error"))) {
			fail("pcode error decompiling " + function.getName());
		}
		if (c.contains("halt_baddata") || c.contains("Could not recover jumptable")) {
			fail(function.getName() + " decompiles with bad data or an unrecovered jump table");
		}
		return results;
	}

	private String decompile(Address entry) {
		DecompileResults results = decompileResults(entry);
		return results == null ? null : results.getDecompiledFunction().getC();
	}
}
