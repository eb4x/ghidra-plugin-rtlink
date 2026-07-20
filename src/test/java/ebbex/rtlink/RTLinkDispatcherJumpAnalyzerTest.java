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

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link RTLinkDispatcherJumpAnalyzer}: the overlay dispatcher trampoline in
 * miniature — {@code MOV DX,imm16 ; MOV [SI-4],AX ; JMP DX} with the stock constant
 * analyzer's bogus same-segment {@code COMPUTED_JUMP} references already planted and the
 * junk it decoded at each wrong target already present — and, as important, the cases the
 * analyzer must refuse to touch (a legitimate register-indirect jump, an already-correct
 * cross-segment resolution, an evidenced target, and any {@code JMP reg} lacking the
 * return-slot patch that makes a dispatcher a dispatcher).
 */
public class RTLinkDispatcherJumpAnalyzerTest extends AbstractGenericTest {

	// Dispatcher trampoline at 0100 (each MOV DX loads a bare overlay offset into DX; kept a
	// straight-line block so a restricted disassemble decodes it whole):
	//   0100  b8 16 00     MOV AX,0x0016
	//   0103  ba 60 01     MOV DX,0x0160     ; arm 1 -> the non-string casualty at 0160
	//   0106  b8 7c 00     MOV AX,0x007c
	//   0109  ba 80 01     MOV DX,0x0180     ; arm 2 -> the string casualty at 0180
	//   010c  89 44 fc     MOV [SI-4],AX     ; the return-slot patch (89 44 fc fingerprint)
	//   010f  ff e2        JMP DX            ; runtime-overlay-selected; bogusly resolved
	private static final String DISPATCHER = "b8 16 00 ba 60 01 b8 7c 00 ba 80 01 89 44 fc ff e2";
	private static final int DISPATCHER_LEN = 0x11;
	private static final String JMP = "0x1000:0x010f";
	private static final String TARGET_A = "0x1000:0x0160"; // non-string casualty
	private static final String TARGET_B = "0x1000:0x0180"; // string casualty

	// 0160: CLC ; STC ; CLI — non-text bytes mis-decoded as a short instruction run.
	private static final String CASUALTY_A = "f8 f9 fa";
	// 0180: "PQRS" — printable bytes (PUSH AX/CX/DX/BX) mis-decoded as code.
	private static final String CASUALTY_B = "50 51 52 53";

	/**
	 * A fresh-import miniature: the dispatcher decoded, the two casualties decoded at their
	 * wrong targets with their ERROR bookmarks, and the two bogus ANALYSIS same-segment
	 * {@code COMPUTED_JUMP} references on the {@code JMP DX} — exactly the post-596 state.
	 *
	 * @param evidencedTargetB if true, {@code 0180} carries a non-default symbol, so it must
	 *            survive the clear (the evidence rule).
	 */
	private ProgramBuilder dispatcherProgram(boolean evidencedTargetB) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DISPATCH", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x400);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", DISPATCHER);
			builder.setBytes(TARGET_A, CASUALTY_A);
			builder.setBytes(TARGET_B, CASUALTY_B);

			// Seed each region as a fresh import leaves it: the dispatcher block, then the
			// two casualties the constant analyzer's inline disassembly decoded at the wrong
			// targets. Each disassemble is restricted to the bytes it is given.
			builder.disassemble("0x1000:0x0100", DISPATCHER_LEN, true);
			builder.disassemble(TARGET_A, 3, true);
			builder.disassemble(TARGET_B, 4, true);

			Program program = builder.getProgram();
			builder.withTransaction(() -> {
				ReferenceManager refs = program.getReferenceManager();
				// The bogus current-segment computed jumps the x86 Constant Reference Analyzer
				// plants (SourceType.ANALYSIS), one per JZ arm.
				refs.addMemoryReference(builder.addr(JMP), builder.addr(TARGET_A),
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
				refs.addMemoryReference(builder.addr(JMP), builder.addr(TARGET_B),
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
				// The confined Bad-Instruction bookmarks the mis-decode left behind.
				program.getBookmarkManager().setBookmark(builder.addr(TARGET_A),
					BookmarkType.ERROR, "Bad Instruction", "conflicting data");
				program.getBookmarkManager().setBookmark(builder.addr(TARGET_B),
					BookmarkType.ERROR, "Bad Instruction", "conflicting string");
			});
			if (evidencedTargetB) {
				builder.createLabel(TARGET_B, "keep_me"); // non-default symbol: real code
			}
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	/** Run the pass inside a transaction over the whole program and hand back the count. */
	private static int neutralize(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("neutralize dispatcher jumps");
		try {
			return RTLinkDispatcherJumpAnalyzer.neutralizeDispatcherJumps(program,
				program.getMemory(), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static boolean hasComputedJumpRef(Program program, String from) {
		for (Reference ref : program.getReferenceManager()
				.getReferencesFrom(program.getAddressFactory().getAddress(from))) {
			if (ref.getReferenceType().isComputed() && ref.getReferenceType().isJump()) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void testDispatcherJumpBogusRefIsNeutralized() throws Exception {
		ProgramBuilder builder = dispatcherProgram(false);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNotNull("setup: string casualty must be decoded as code",
				listing.getInstructionAt(builder.addr(TARGET_B)));
			assertTrue("setup: the bogus computed jump must be present",
				hasComputedJumpRef(program, JMP));

			assertEquals(1, neutralize(builder));

			assertFalse("the bogus computed jump must be gone",
				hasComputedJumpRef(program, JMP));
			assertNull("no instruction may survive on the string bytes",
				listing.getInstructionAt(builder.addr(TARGET_B)));
			assertNull("the confined error bookmark must be gone",
				program.getBookmarkManager()
						.getBookmark(builder.addr(TARGET_B), BookmarkType.ERROR, "Bad Instruction"));
			assertTrue("the string range is undefined again, so the string pass can claim it",
				DataUtilities.isUndefinedRange(program, builder.addr(TARGET_B),
					builder.addr("0x1000:0x0183")));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testNonStringCasualtyIsCleared() throws Exception {
		ProgramBuilder builder = dispatcherProgram(false);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNotNull("setup: non-string casualty must be decoded",
				listing.getInstructionAt(builder.addr(TARGET_A)));

			assertEquals(1, neutralize(builder));

			assertNull("the non-string junk must be cleared too",
				listing.getInstructionAt(builder.addr(TARGET_A)));
			assertNull("its error bookmark must be gone",
				program.getBookmarkManager()
						.getBookmark(builder.addr(TARGET_A), BookmarkType.ERROR, "Bad Instruction"));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testEvidencedTargetNotCleared() throws Exception {
		ProgramBuilder builder = dispatcherProgram(true); // 0180 carries a non-default symbol
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();

			assertEquals(1, neutralize(builder));

			assertFalse("the bogus reference is still deleted", hasComputedJumpRef(program, JMP));
			assertNotNull("but evidenced code at the target is kept, not over-cleared",
				listing.getInstructionAt(builder.addr(TARGET_B)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testNeutralizationIsIdempotent() throws Exception {
		ProgramBuilder builder = dispatcherProgram(false);
		try {
			assertEquals(1, neutralize(builder));
			assertEquals("a re-run finds nothing left to do", 0, neutralize(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * A genuine {@code MOV reg,imm16 ; JMP reg} computed jump with a correct current-segment
	 * target and <b>no</b> return-slot patch before it — the decisive control. Nothing is
	 * touched.
	 * <pre>
	 *   0200  bb 50 02   MOV BX,0x0250
	 *   0203  90         NOP            ; not a return-slot patch
	 *   0204  ff e3      JMP BX
	 *   0250  c3         RET            ; real, evidenced code
	 * </pre>
	 */
	@Test
	public void testLegitComputedJumpUntouched() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("LEGIT", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x400);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0200", "bb 50 02 90 ff e3");
			builder.setBytes("0x1000:0x0250", "c3");
			builder.disassemble("0x1000:0x0200", 6, true);
			builder.disassemble("0x1000:0x0250", 1, true);
			Program program = builder.getProgram();
			builder.withTransaction(() -> program.getReferenceManager().addMemoryReference(
				builder.addr("0x1000:0x0204"), builder.addr("0x1000:0x0250"),
				RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0));
			builder.createLabel("0x1000:0x0250", "real_target");

			assertEquals(0, neutralize(builder));

			assertTrue("the legitimate computed jump's reference must survive",
				hasComputedJumpRef(program, "0x1000:0x0204"));
			assertNotNull("its target code must be untouched",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0250")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * A full dispatcher shape whose computed reference already resolves into a <i>different</i>
	 * segment — an already-correct overlay resolution. The same-segment filter leaves it alone.
	 */
	@Test
	public void testCrossSegmentComputedRefUntouched() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("XSEG", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x400);
			MemoryBlock overlay = builder.createMemory("OVL", "0x2000:0x0000", 0x400);
			builder.withTransaction(() -> {
				code.setExecute(true);
				overlay.setExecute(true);
			});
			builder.setBytes("0x1000:0x0100", DISPATCHER);
			builder.setBytes("0x2000:0x0080", "c3"); // a real overlay entry
			builder.disassemble("0x1000:0x0100", DISPATCHER_LEN, true);
			builder.disassemble("0x2000:0x0080", 1, true);
			Program program = builder.getProgram();
			builder.withTransaction(() -> program.getReferenceManager().addMemoryReference(
				builder.addr(JMP), builder.addr("0x2000:0x0080"), RefType.COMPUTED_JUMP,
				SourceType.ANALYSIS, 0));

			assertEquals(0, neutralize(builder));

			assertTrue("an already-correct cross-segment resolution must survive",
				hasComputedJumpRef(program, JMP));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The {@code MOV DX,imm16 ; JMP DX} shape with a same-segment bogus reference but <b>no</b>
	 * return-slot patch immediately before the jump (a plain NOP instead). The strict 5a gate
	 * declines it, so an arbitrary register-indirect jump is never mistaken for a dispatcher.
	 * <pre>
	 *   0100  ba 80 01   MOV DX,0x0180
	 *   0103  90         NOP            ; NOT a return-slot patch
	 *   0104  ff e2      JMP DX
	 *   0180  50 51 52 53  (would-be casualty)
	 * </pre>
	 */
	@Test
	public void testMissingReturnSlotPatchDeclined() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("NOSLOT", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x400);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "ba 80 01 90 ff e2");
			builder.setBytes(TARGET_B, CASUALTY_B);
			builder.disassemble("0x1000:0x0100", 6, true);
			builder.disassemble(TARGET_B, 4, true);
			Program program = builder.getProgram();
			builder.withTransaction(() -> program.getReferenceManager().addMemoryReference(
				builder.addr("0x1000:0x0104"), builder.addr(TARGET_B), RefType.COMPUTED_JUMP,
				SourceType.ANALYSIS, 0));

			assertEquals(0, neutralize(builder));

			assertTrue("without the return-slot patch it is not a dispatcher: ref survives",
				hasComputedJumpRef(program, "0x1000:0x0104"));
			assertNotNull("and nothing is cleared",
				program.getListing().getInstructionAt(builder.addr(TARGET_B)));
		}
		finally {
			builder.dispose();
		}
	}
}
