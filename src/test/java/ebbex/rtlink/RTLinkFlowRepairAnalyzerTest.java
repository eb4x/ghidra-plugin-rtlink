package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link RTLinkFlowRepairAnalyzer}: the two ways real code ends up buried
 * under junk in this corpus, and — as important — the cases the analyzer must refuse
 * to touch.
 * <p>
 * The layouts are the corpus idioms in miniature. The relocation case is MSC's
 * startup error exit ({@code CALL __exit_vector} followed by an inline relocated
 * {@code dw DGROUP}); the conflict case is ROE2MAIN's {@code 1a5e:001c}, where junk
 * one byte into a {@code CALLF} buries it and the real code is reached by
 * fall-through.
 */
public class RTLinkFlowRepairAnalyzerTest extends AbstractGenericTest {

	/** Run a detector inside a transaction and hand back what it repaired. */
	private static int repairRelocations(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("repair relocations");
		try {
			return RelocationFallthroughs.repair(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static int arbitrateConflicts(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("arbitrate conflicts");
		try {
			return ConflictArbitration.arbitrate(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/**
	 * {@code CALL 0x180} whose fall-through is a relocated segment word, a pad byte,
	 * then a routine that something else calls directly.
	 * <pre>
	 *   0100  e8 7d 00     CALL 0x0180        ; the exit-vector call
	 *   0103  34 12        &lt;relocated word&gt;   ; decodes as XOR AL,0x12
	 *   0105  90           &lt;pad&gt;              ; decodes as NOP
	 *   0106  b8 ff 00     MOV AX,0xff        ; real code, called from 0140
	 *   0109  c3           RET
	 *   0140  e8 c3 ff     CALL 0x0106        ; the evidence
	 *   0180  c3           RET                ; the callee
	 * </pre>
	 */
	private static final String RELOC_CODE = "e8 7d 00 34 12 90 b8 ff 00 c3";
	private static final String RELOC_CALLER = "e8 c3 ff";
	private static final String RELOC_CALLEE = "c3";
	/** {@code CALL 0x0100} — the exit call must be real code, as it is in the corpus. */
	private static final String EXIT_CALLER = "e8 dd ff";
	private static final String CALL = "0x1000:0x0100";
	private static final String WORD = "0x1000:0x0103";
	private static final String BURIED = "0x1000:0x0106";

	/**
	 * ROE2MAIN {@code 1a5e:001c} in miniature: junk seeded one byte into a
	 * {@code CALLF} that real fall-through reaches.
	 * <pre>
	 *   0100  55           PUSH BP
	 *   0101  8b ec        MOV BP,SP          ; falls through to 0103
	 *   0103  9a 3c 00 b6 27  CALLF 27b6:003c ; buried by junk at 0104
	 *   0108  c3           RET
	 *   0150  e8 ad ff     CALL 0x0100        ; evidence root
	 *   0160  e8 a1 ff     CALL 0x0104        ; evidence for the JUNK (decline test)
	 * </pre>
	 */
	private static final String CONFLICT_CODE = "55 8b ec 9a 3c 00 b6 27 c3";
	private static final String CONFLICT_CALLER = "e8 ad ff";
	private static final String JUNK_CALLER = "e8 a1 ff";
	private static final String CONFLICT_ENTRY = "0x1000:0x0100";
	private static final String CONFLICT_BURIED = "0x1000:0x0103";
	private static final String CONFLICT_JUNK = "0x1000:0x0104";

	private ProgramBuilder relocProgram(boolean withRelocation) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("RELOC", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", RELOC_CODE);
			builder.setBytes("0x1000:0x0120", EXIT_CALLER);
			builder.setBytes("0x1000:0x0140", RELOC_CALLER);
			builder.setBytes("0x1000:0x0180", RELOC_CALLEE);

			Program program = builder.getProgram();
			if (withRelocation) {
				builder.withTransaction(() -> program.getRelocationTable()
						.add(builder.addr(WORD), Status.APPLIED, 0,
							new long[] { 0x100, 0x103, 0x2000 }, 2, null));
			}
			// The two callers first — their CALL references are what make the exit call
			// and the buried routine evidenced code. Then the exit call itself, whose
			// flow decodes the relocated word as junk and runs on into the routine,
			// exactly as a fresh import does. Each disassemble is restricted to the
			// bytes it is given, so the regions are seeded one at a time.
			builder.disassemble("0x1000:0x0120", 3, true);
			builder.disassemble("0x1000:0x0140", 3, true);
			builder.disassemble("0x1000:0x0100", 10, true);
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	@Test
	public void testRelocatedWordBehindCallIsSealed() throws Exception {
		ProgramBuilder builder = relocProgram(true);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNotNull("setup: junk must be decoded from the relocated word",
				listing.getInstructionAt(builder.addr(WORD)));

			assertEquals(1, repairRelocations(builder));

			Instruction call = listing.getInstructionAt(builder.addr(CALL));
			assertEquals("the call can no longer fall through into the word",
				FlowOverride.CALL_RETURN, call.getFlowOverride());
			assertNull(call.getFallThrough());

			assertNull("junk decoded from the word must be gone",
				listing.getInstructionAt(builder.addr(WORD)));
			assertNotNull("the word must be sealed as data",
				listing.getDefinedDataAt(builder.addr(WORD)));

			Instruction buried = listing.getInstructionAt(builder.addr(BURIED));
			assertNotNull("the called routine must survive", buried);
			assertEquals("MOV", buried.getMnemonicString());
			assertNotNull("and become a function",
				program.getFunctionManager().getFunctionAt(builder.addr(BURIED)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testWithoutRelocationNothingIsTouched() throws Exception {
		ProgramBuilder builder = relocProgram(false);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();

			assertEquals("no relocation, no claim", 0, repairRelocations(builder));

			assertEquals(FlowOverride.NONE,
				listing.getInstructionAt(builder.addr(CALL)).getFlowOverride());
			assertNotNull("the junk stays: nothing proves it is not code",
				listing.getInstructionAt(builder.addr(WORD)));
			assertNull(listing.getDefinedDataAt(builder.addr(WORD)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testRelocationRepairIsIdempotent() throws Exception {
		ProgramBuilder builder = relocProgram(true);
		try {
			repairRelocations(builder);
			assertEquals("a sealed word is not repaired twice", 0,
				repairRelocations(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The SPHERE shape: the relocated word never decoded at all (its bytes are not a
	 * valid instruction), so the disassembler left an ERROR bookmark instead of junk.
	 * The call must still be sealed, and the bookmark dropped.
	 */
	@Test
	public void testUndecodableWordIsSealedAndUnbookmarked() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("SPH", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			// CALL 0x0180; then the word — left undefined, as if it had not decoded.
			builder.setBytes("0x1000:0x0100", "e8 7d 00 34 12 90 b8 ff 00 c3");
			builder.setBytes("0x1000:0x0120", EXIT_CALLER);
			builder.setBytes("0x1000:0x0180", RELOC_CALLEE);
			builder.disassemble("0x1000:0x0120", 3, true);  // evidence for the exit call
			builder.disassemble("0x1000:0x0100", 3, false); // the CALL alone, no flow

			Program program = builder.getProgram();
			Address word = builder.addr(WORD);
			builder.withTransaction(() -> {
				program.getRelocationTable().add(word, Status.APPLIED, 0,
					new long[] { 0x100, 0x103, 0x2000 }, 2, null);
				program.getBookmarkManager().setBookmark(word, BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY,
					"Unable to resolve constructor at 1000:0103 (flow from 1000:0100)");
			});

			assertEquals(1, repairRelocations(builder));
			assertEquals(FlowOverride.CALL_RETURN, program.getListing()
					.getInstructionAt(builder.addr(CALL))
					.getFlowOverride());
			assertNotNull("the word is sealed even when nothing decoded it",
				program.getListing().getDefinedDataAt(word));
			assertNull("its stale error bookmark must be gone",
				program.getBookmarkManager()
						.getBookmark(word, BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	private ProgramBuilder conflictProgram(boolean evidenceForJunk) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("CONF", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes(CONFLICT_ENTRY, CONFLICT_CODE);
			builder.setBytes("0x1000:0x0150", CONFLICT_CALLER);
			if (evidenceForJunk) {
				builder.setBytes("0x1000:0x0160", JUNK_CALLER);
			}

			// Junk first — as a stray flow would have seeded it — then the caller (whose
			// CALL reference is the evidence root), then the real code, which now cannot
			// decode the CALLF at 0103 because 0104 is taken. That is the conflict the
			// disassembler bookmarks in the wild; the mark is placed the same way it
			// does (Disassembler.markCallConflict), at the blocked address.
			builder.disassemble(CONFLICT_JUNK, 4, true);
			builder.disassemble("0x1000:0x0150", 3, true);
			if (evidenceForJunk) {
				builder.disassemble("0x1000:0x0160", 3, true);
			}
			builder.disassemble(CONFLICT_ENTRY, 9, true);

			Program program = builder.getProgram();
			builder.withTransaction(() -> {
				program.getBookmarkManager()
						.setBookmark(builder.addr(CONFLICT_BURIED), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY,
							"Failed to disassemble at 1000:0103 due to conflicting " +
								"instruction (flow from 1000:0101)");
			});
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	@Test
	public void testBuriedCodeWinsOverUnreferencedJunk() throws Exception {
		ProgramBuilder builder = conflictProgram(false);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNotNull("setup: junk must exist at 0104",
				listing.getInstructionAt(builder.addr(CONFLICT_JUNK)));
			assertNull("setup: the CALLF must be buried",
				listing.getInstructionAt(builder.addr(CONFLICT_BURIED)));

			assertEquals(1, arbitrateConflicts(builder));

			Instruction buried = listing.getInstructionAt(builder.addr(CONFLICT_BURIED));
			assertNotNull("the buried CALLF must be recovered", buried);
			assertEquals("CALLF", buried.getMnemonicString());
			assertEquals("and take all five of its bytes", 5, buried.getLength());
			assertNull("the junk must be gone",
				listing.getInstructionAt(builder.addr(CONFLICT_JUNK)));
			assertNull("and its bookmark with it",
				program.getBookmarkManager()
						.getBookmark(builder.addr(CONFLICT_BURIED), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testConflictWithEvidenceOnBothSidesIsDeclined() throws Exception {
		ProgramBuilder builder = conflictProgram(true);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();

			assertEquals("something calls the junk: this is not ours to decide", 0,
				arbitrateConflicts(builder));
			assertNotNull("the junk stays",
				listing.getInstructionAt(builder.addr(CONFLICT_JUNK)));
			assertNotNull("and so does the bookmark",
				program.getBookmarkManager()
						.getBookmark(builder.addr(CONFLICT_BURIED), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The negative control that matters: a disassembly island over data, reached by
	 * nothing, conflicting with bytes that are also reached by nothing. Neither side
	 * has evidence, so the analyzer must leave the whole thing alone.
	 */
	@Test
	public void testUnevidencedConflictIsLeftAlone() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("ISLE", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x01c0", "9a 3c 00 b6 27 c3");
			builder.disassemble("0x1000:0x01c1", 4, true); // island, referenced by nothing

			Program program = builder.getProgram();
			Address buried = builder.addr("0x1000:0x01c0");
			builder.withTransaction(() -> program.getBookmarkManager()
					.setBookmark(buried, BookmarkType.ERROR,
						Disassembler.ERROR_BOOKMARK_CATEGORY,
						"Failed to disassemble at 1000:01c0 due to conflicting " +
							"instruction (flow from 1000:01bd)"));

			assertEquals("nothing is evidenced here; nothing may be cleared", 0,
				arbitrateConflicts(builder));
			assertNotNull("the island stays",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x01c1")));
			assertNotNull("the bookmark stays",
				program.getBookmarkManager()
						.getBookmark(buried, BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testConflictArbitrationIsIdempotent() throws Exception {
		ProgramBuilder builder = conflictProgram(false);
		try {
			arbitrateConflicts(builder);
			assertEquals("a repaired conflict is not repaired twice", 0,
				arbitrateConflicts(builder));
		}
		finally {
			builder.dispose();
		}
	}

	private static int fillGaps(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("fill code gaps");
		try {
			return CodeGaps.fill(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/**
	 * ROE2MAIN {@code 122e:51a0} in miniature: a routine nothing references, whose
	 * bytes were cleared out from under the pattern seeders, so no pass ever reaches
	 * it. Its prologue and its stranded epilogue are both undefined runs bounded by
	 * code — and both decode exactly onto the code that follows them.
	 * <pre>
	 *   0100  55 8b ec 83 ec 12   PUSH BP; MOV BP,SP; SUB SP,0x12   ; gap 1 (prologue)
	 *   0106  eb 02               JMP 0x010a                        ; disassembled: the
	 *   0108  eb fc               JMP 0x0106                        ; only code flow
	 *   010a  8b e5 5d cb         MOV SP,BP; POP BP; RETF           ; gap 2 (epilogue)
	 *   010e  55 8b ec 5d cb      the next function
	 * </pre>
	 */
	@Test
	public void testUnreachedPrologueAndEpilogueAreRecovered() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("GAP", ProgramBuilder._X86_16_REAL_MODE);
		try {
			// The block starts at the routine: a gap is a run of undefined bytes
			// between code, and the block's own unused tail is not one.
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100",
				"55 8b ec 83 ec 12 eb 02 eb fc 8b e5 5d cb 55 8b ec 5d cb");
			// Only the little JMP loop is reachable, exactly as flow-only recovery
			// leaves it; the prologue above and the epilogue below stay undefined.
			builder.disassemble("0x1000:0x0106", 4, true);
			builder.disassemble("0x1000:0x010e", 5, true);
			builder.createFunction("0x1000:0x010e");

			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNull("setup: the prologue must start out buried",
				listing.getInstructionAt(builder.addr("0x1000:0x0100")));
			assertNull("setup: so must the epilogue",
				listing.getInstructionAt(builder.addr("0x1000:0x010a")));

			assertEquals("both gaps are routines, not padding", 2, fillGaps(builder));

			Instruction prologue = listing.getInstructionAt(builder.addr("0x1000:0x0100"));
			assertNotNull("the prologue must be recovered", prologue);
			assertEquals("PUSH", prologue.getMnemonicString());
			assertNotNull("and become a function",
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0100")));

			Instruction epilogue = listing.getInstructionAt(builder.addr("0x1000:0x010a"));
			assertNotNull("the stranded epilogue must be recovered", epilogue);
			assertEquals("MOV", epilogue.getMnemonicString());
			assertNotNull("all the way to its return",
				listing.getInstructionAt(builder.addr("0x1000:0x010d")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The other negative control: alignment padding and data-shaped runs between
	 * routines must never be decoded, however cleanly they would parse.
	 */
	@Test
	public void testPaddingAndOutOfPhaseGapsAreLeftAlone() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("PAD", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			// 0100: a routine; 0104..0107: four zero bytes of padding; 0108: the next
			// routine. The zeros would decode (as ADD [BX+SI],AL) and land exactly on
			// 0108 — the phase test alone would accept them. Only the repeated-byte
			// rule rejects them.
			builder.setBytes("0x1000:0x0100", "55 8b ec cb 00 00 00 00 55 8b ec cb");
			builder.disassemble("0x1000:0x0100", 4, true);
			builder.disassemble("0x1000:0x0108", 4, true);
			builder.createFunction("0x1000:0x0108");

			assertEquals("padding is not code", 0, fillGaps(builder));
			assertNull("the zeros must stay undefined", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0104")));
		}
		finally {
			builder.dispose();
		}
	}

	/** The routine above the run, the run itself (65 bytes), and the routine below. */
	private static final String ROUTINE_RUN_ABOVE = "55 8b ec 5d ca 04 00 ";
	private static final String ROUTINE_RUN_BELOW = "55 8b ec 5d cb";

	/** Routine C of the run, its {@code JA} landing on the code after its inner JMP. */
	private static final String ROUTINE_C_REACHED =
		"3b 06 4c a6 77 05 a1 4c a6 eb 03 a1 62 26 a3 62 26 cb ";

	/**
	 * VICEROY {@code OVERLAY_30::03a40a} in miniature: three library routines that
	 * nothing calls, between a routine ending in {@code RETF 4} and the next function,
	 * each padded onto an even address by one {@code NOP}. Longer than any single-routine
	 * gap, so only the whole-routine rule can claim it.
	 * <pre>
	 *   0100  55 8b ec 5d ca 04 00   routine above, ends RETF 4      ; disassembled
	 *   0107  90                     pad
	 *   0108  c8 02 00 00 ...        A: ENTER 2,0 ... INT 21h; LEAVE; RETF 4
	 *   0117  90                     pad
	 *   0118  a1 62 26 ... cb        B: copy two longs; RETF (no frame)
	 *   0135  90                     pad
	 *   0136  3b 06 4c a6 77 05 ...  C: CMP; JA 0141; MOV; JMP 0144; 0141 MOV; 0144 MOV; RETF
	 *   0148  55 8b ec 5d cb         the next function                ; disassembled
	 * </pre>
	 */
	private ProgramBuilder routineRunProgram(String routineC) throws Exception {
		return routineRunProgram(ROUTINE_RUN_ABOVE, routineC);
	}

	/** The same, with {@code above} (seven bytes) as the routine above the run. */
	private ProgramBuilder routineRunProgram(String above, String routineC) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("RUN", ProgramBuilder._X86_16_REAL_MODE);
		MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x60);
		builder.withTransaction(() -> code.setExecute(true));
		builder.setBytes("0x1000:0x0100", above + "90 " +
			"c8 02 00 00 8b 46 06 b4 4a cd 21 c9 ca 04 00 " + "90 " +
			"a1 62 26 8b 16 64 26 a3 4c a6 89 16 4e a6 " +
			"a1 6a 26 8b 16 6c 26 a3 50 a6 89 16 52 a6 cb " + "90 " + routineC +
			ROUTINE_RUN_BELOW);
		builder.disassemble("0x1000:0x0100", 7, true);
		builder.createFunction("0x1000:0x0100");
		builder.disassemble("0x1000:0x0148", 5, true);
		builder.createFunction("0x1000:0x0148");
		return builder;
	}

	@Test
	public void testRunOfWholeRoutinesIsRecovered() throws Exception {
		ProgramBuilder builder = routineRunProgram(ROUTINE_C_REACHED);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNull("setup: the run must start out undefined",
				listing.getInstructionAt(builder.addr("0x1000:0x0108")));

			assertEquals("three routines", 3, fillGaps(builder));

			for (String entry : new String[] { "0x0108", "0x0118", "0x0136" }) {
				assertNotNull("a function at " + entry, program.getFunctionManager()
						.getFunctionAt(builder.addr("0x1000:" + entry)));
			}
			assertEquals("ENTER", listing.getInstructionAt(builder.addr("0x1000:0x0108"))
					.getMnemonicString());
			assertNotNull("C's code past its inner JMP is reached by its JA",
				listing.getInstructionAt(builder.addr("0x1000:0x0141")));
			assertNull("and is part of C, not a routine of its own",
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0141")));
			assertNull("the alignment pads stay undefined",
				listing.getInstructionAt(builder.addr("0x1000:0x0107")));
			assertEquals("a second pass finds nothing left", 0, fillGaps(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The same run with C's {@code JA} aimed past {@code 0141}: the code after the inner
	 * {@code JMP} is now reached by nothing, so the run does not account for itself and
	 * none of it is claimed.
	 */
	@Test
	public void testRunWithUnreachedCodeIsLeftAlone() throws Exception {
		ProgramBuilder builder = routineRunProgram(
			"3b 06 4c a6 77 08 a1 4c a6 eb 03 a1 62 26 a3 62 26 cb ");
		try {
			assertEquals("code nothing reaches is not a routine", 0, fillGaps(builder));
			assertNull("so the run stays undefined", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0108")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * VICEROY {@code 1b22:0006}: a routine of the run that starts on zero bytes. Here C
	 * opens with four of them, which decode in phase as {@code ADD [BX+SI],AL} but are
	 * data (a saved interrupt vector, there), so the run is not claimed.
	 */
	@Test
	public void testRunStartingOnZerosIsLeftAlone() throws Exception {
		ProgramBuilder builder = routineRunProgram(
			"00 00 00 00 8b 16 64 26 a1 4c a6 a3 62 26 a3 62 26 cb ");
		try {
			assertEquals("zeros are no routine entry", 0, fillGaps(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The run below a far jump that Shared Return Calls made a tail call
	 * ({@code CALL_TERMINATOR}): the routine above has left, as surely as by a return, and
	 * the run is claimed.
	 */
	@Test
	public void testRunBelowATailCallIsRecovered() throws Exception {
		// 0100: NOP; NOP; JMPF 1000:0148, then the run as before
		ProgramBuilder builder = routineRunProgram("90 90 ea 48 01 00 10 ", ROUTINE_C_REACHED);
		try {
			Program program = builder.getProgram();
			Instruction jump = program.getListing().getInstructionAt(builder.addr("0x1000:0x0102"));
			builder.withTransaction(() -> jump.setFlowOverride(FlowOverride.CALL_RETURN));
			assertTrue("setup: the jump is now terminal", jump.getFlowType().isTerminal());

			assertEquals("three routines", 3, fillGaps(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * VICEROY {@code 210d:05f0}: code below a far jump that jumps back into the middle of the
	 * routine above it ({@code JNZ 05e5}, {@code JMP 05e1}, into the INT 21h hook) is a
	 * detached block of that routine, not a routine of its own. Here C ends in
	 * {@code JMP 0103}, the {@code POP BP} of the routine above.
	 */
	@Test
	public void testBlockJumpingBackIntoTheRoutineAboveIsLeftAlone() throws Exception {
		ProgramBuilder builder = routineRunProgram(
			"a1 62 26 a3 62 26 a1 62 26 a3 62 26 a1 62 26 e9 bb ff ");
		try {
			assertEquals("a detached block is no routine", 0, fillGaps(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * VICEROY {@code 210d:1df1}: three entries into one body, each loading its own constant
	 * into DX first — the first two jump to the body, the last falls into it. Nothing calls
	 * any of them; each becomes a function, the last owning the body.
	 * <pre>
	 *   0100  55 8b ec 5d cb   the routine above, ends RETF       ; disassembled
	 *   0105  52 ba 00 08 eb 0a   PUSH DX ; MOV DX,0x0800 ; JMP 0115
	 *   010b  52 ba 00 20 eb 04   PUSH DX ; MOV DX,0x2000 ; JMP 0115
	 *   0111  52 ba 00 10         PUSH DX ; MOV DX,0x1000
	 *   0115  09 16 00 00 5a cb   OR [0],DX ; POP DX ; RETF
	 *   011b  55 8b ec 5d cb   the next function                  ; disassembled
	 * </pre>
	 */
	@Test
	public void testEntriesSharingABodyAreRecovered() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("ENTRIES", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "55 8b ec 5d cb " +
				"52 ba 00 08 eb 0a 52 ba 00 20 eb 04 52 ba 00 10 09 16 00 00 5a cb " +
				"55 8b ec 5d cb");
			builder.disassemble("0x1000:0x0100", 5, true);
			builder.createFunction("0x1000:0x0100");
			builder.disassemble("0x1000:0x011b", 5, true);
			builder.createFunction("0x1000:0x011b");

			assertEquals("three entries", 3, fillGaps(builder));

			var functions = builder.getProgram().getFunctionManager();
			assertEquals(6, functions.getFunctionAt(builder.addr("0x1000:0x0105"))
					.getBody().getNumAddresses());
			assertEquals(6, functions.getFunctionAt(builder.addr("0x1000:0x010b"))
					.getBody().getNumAddresses());
			assertEquals("the last entry owns the body", 10,
				functions.getFunctionAt(builder.addr("0x1000:0x0111")).getBody().getNumAddresses());
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * RTLink's rtcommon, {@code 275d:07cf}: a far jump, six zero bytes, then two routines
	 * nothing calls. The zeros are left alone and the routines claimed.
	 * <pre>
	 *   0100  ea 00 01 00 10      JMPF 1000:0100                  ; disassembled
	 *   0105  00 00 00 00 00 00   padding
	 *   010b  50 06 b0 04 07 58 cb   PUSH AX ; PUSH ES ; MOV AL,4 ; POP ES ; POP AX ; RETF
	 *   0112  33 c0 cb            XOR AX,AX ; RETF
	 *   0115  55 8b ec 5d cb      the next function               ; disassembled
	 * </pre>
	 */
	@Test
	public void testRoutinesBehindZeroPaddingAreRecovered() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("PAD", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "ea 00 01 00 10 00 00 00 00 00 00 " +
				"50 06 b0 04 07 58 cb 33 c0 cb 55 8b ec 5d cb");
			builder.disassemble("0x1000:0x0100", 5, true);
			builder.disassemble("0x1000:0x0115", 5, true);
			builder.createFunction("0x1000:0x0115");

			assertEquals("two routines", 2, fillGaps(builder));

			Program program = builder.getProgram();
			assertNotNull(program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x010b")));
			assertNotNull(program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0112")));
			assertNull("the padding stays undefined",
				program.getListing().getInstructionContaining(builder.addr("0x1000:0x0105")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * VICEROY {@code 210d:2016}: near jumps between routines are slots of a table only a
	 * computed jump reaches, not routines; they are not claimed.
	 * <pre>
	 *   0100  c3            RET                                   ; disassembled
	 *   0101  e9 0c 00      JMP 0110
	 *   0104  e9 09 00      JMP 0110
	 *   0107  e9 06 00      JMP 0110
	 *   010a  e9 03 00      JMP 0110
	 *   010d  e9 00 00      JMP 0110
	 *   0110  55 8b ec 5d c3   the next function                  ; disassembled
	 * </pre>
	 */
	@Test
	public void testJumpSlotsAreLeftAlone() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("SLOTS", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100",
				"c3 e9 0c 00 e9 09 00 e9 06 00 e9 03 00 e9 00 00 55 8b ec 5d c3");
			builder.disassemble("0x1000:0x0100", 1, true);
			builder.disassemble("0x1000:0x0110", 5, true);
			builder.createFunction("0x1000:0x0110");

			fillGaps(builder);

			assertNull("a jump slot is no routine", builder.getProgram()
					.getFunctionManager()
					.getFunctionAt(builder.addr("0x1000:0x0101")));
		}
		finally {
			builder.dispose();
		}
	}

	/** A short gap opening with {@code ENTER n,0} is a prologue like PUSH BP; MOV BP,SP. */
	@Test
	public void testEnterPrologueIsRecovered() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("ENTER", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			// 0100: RETF; 0101: ENTER 2,0; LEAVE; RETF (the gap); 0107: the next routine
			builder.setBytes("0x1000:0x0100", "cb c8 02 00 00 c9 cb 55 8b ec 5d cb");
			builder.disassemble("0x1000:0x0100", 1, true);
			builder.disassemble("0x1000:0x0107", 5, true);
			builder.createFunction("0x1000:0x0107");

			assertEquals(1, fillGaps(builder));
			assertNotNull("the ENTER routine becomes a function", builder.getProgram()
					.getFunctionManager()
					.getFunctionAt(builder.addr("0x1000:0x0101")));
		}
		finally {
			builder.dispose();
		}
	}

	private static int resolveVectors(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("resolve far vectors");
		try {
			return FarVectorFlows.resolve(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static int sealNonReturning(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("seal non-returning calls");
		try {
			return NonReturningCalls.seal(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/**
	 * The vendor driver's abort path, in miniature. Nothing reaches the fatal handler
	 * except an indirect far jump through a vector in the code segment, so no pass ever
	 * decodes it; and because the abort never returns, the disassembler runs the call's
	 * fall-through into the handler table behind it and decodes zeros until its
	 * repeated-byte limiter gives up.
	 * <pre>
	 *   0100  9a 20 01 00 10   CALLF abort (1000:0120)   ; registration table full
	 *   0105  00 00 ... 00     the handler table         ; zeros: data, not code
	 *   0120  2e ff 2e 40 01   JMPF CS:[0x140]           ; abort tail-jumps via vector
	 *   0130  b8 01 4c cd 21   MOV AX,0x4C01; INT 0x21   ; the handler: DOS terminate
	 *   0140  30 01 00 10      the vector: far ptr 1000:0130
	 * </pre>
	 */
	private ProgramBuilder abortProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("EXIT", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x50);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "9a 20 01 00 10");           // CALLF abort
			builder.setBytes("0x1000:0x0120", "2e ff 2e 40 01");           // JMPF CS:[0x140]
			builder.setBytes("0x1000:0x0130", "b8 01 4c cd 21");           // MOV AX,4C01; INT 21
			builder.setBytes("0x1000:0x0140", "30 01 00 10");              // vector -> 1000:0130
			builder.disassemble("0x1000:0x0100", 5, false);
			builder.disassemble("0x1000:0x0120", 5, false);
			builder.createFunction("0x1000:0x0120");
			// The junk the disassembler decoded from the table behind the call, and the
			// mark it left one byte past where it gave up.
			builder.disassemble("0x1000:0x0105", 4, false);
			Program program = builder.getProgram();
			builder.withTransaction(() -> program.getBookmarkManager()
					.setBookmark(builder.addr("0x1000:0x0109"), BookmarkType.ERROR,
						Disassembler.ERROR_BOOKMARK_CATEGORY,
						"Maximum run of repeated byte instructions exceeded " +
							"(flow from 1000:0107)"));
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	@Test
	public void testFarJumpThroughCodeVectorIsFollowed() throws Exception {
		ProgramBuilder builder = abortProgram();
		try {
			Program program = builder.getProgram();
			assertNull("setup: the handler must start out undecoded",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0130")));

			assertEquals(1, resolveVectors(builder));

			Instruction handler =
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0130"));
			assertNotNull("the handler behind the vector must be disassembled", handler);
			assertEquals("MOV", handler.getMnemonicString());
			assertNotNull("and promoted to a function",
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0130")));
			assertEquals("a second run must not re-resolve it", 0, resolveVectors(builder));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testCallToTerminatingRoutineLosesItsFallThrough() throws Exception {
		ProgramBuilder builder = abortProgram();
		try {
			Program program = builder.getProgram();
			resolveVectors(builder); // the handler must exist before it can be judged

			assertEquals(1, sealNonReturning(builder));

			Instruction call =
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0100"));
			assertEquals("a call that cannot return has no fall-through",
				FlowOverride.CALL_RETURN, call.getFlowOverride());
			assertNull(call.getFallThrough());
			assertTrue("the abort routine is marked non-returning", program
					.getFunctionManager()
					.getFunctionAt(builder.addr("0x1000:0x0120"))
					.hasNoReturn());
			assertNull("and the table behind it is not decoded as code",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0105")));
			assertNull("the mark the abandoned run left behind must go too",
				program.getBookmarkManager()
						.getBookmark(builder.addr("0x1000:0x0109"), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
			assertEquals("a second run must find nothing to seal", 0,
				sealNonReturning(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The junk behind the abort is cleared even though the routine's own loads
	 * reference it (those data references are what prove it is a table, not code) — but
	 * the clear must stop dead at the first instruction something really flows to.
	 */
	@Test
	public void testSealStopsAtCodeSomethingFlowsTo() throws Exception {
		ProgramBuilder builder = abortProgram();
		try {
			Program program = builder.getProgram();
			// A jump target immediately after the junk: real code, reached from
			// elsewhere, sitting right where a runaway clear would reach it.
			builder.setBytes("0x1000:0x0109", "cb");             // RETF at 0109
			builder.setBytes("0x1000:0x0118", "eb ef");          // JMP 0109
			builder.disassemble("0x1000:0x0118", 2, true);       // makes the flow ref
			builder.disassemble("0x1000:0x0109", 1, true);       // and the code it reaches
			resolveVectors(builder);

			assertEquals(1, sealNonReturning(builder));

			assertNull("the junk table is cleared",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0105")));
			assertNotNull("but the code the jump reaches is untouched",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0109")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * A name someone gave the bytes right behind the call is evidence the clear must respect,
	 * even on the very first instruction: the call is still sealed, nothing is cleared.
	 */
	@Test
	public void testSealSparesANamedFallThrough() throws Exception {
		ProgramBuilder builder = abortProgram();
		try {
			Program program = builder.getProgram();
			builder.createLabel("0x1000:0x0105", "handler_table");
			resolveVectors(builder);

			assertEquals(1, sealNonReturning(builder));

			assertEquals("the call is sealed all the same", FlowOverride.CALL_RETURN,
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0100")).getFlowOverride());
			assertNotNull("but the named code behind it is untouched",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0105")));
		}
		finally {
			builder.dispose();
		}
	}

	/** A default-named function nothing calls behind the call is analysis' orphan, not evidence. */
	@Test
	public void testSealClearsAnOrphanFunctionAtTheFallThrough() throws Exception {
		ProgramBuilder builder = abortProgram();
		try {
			Program program = builder.getProgram();
			builder.createFunction("0x1000:0x0105");
			resolveVectors(builder);

			assertEquals(1, sealNonReturning(builder));

			assertNull("the orphan's junk is cleared",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0105")));
		}
		finally {
			builder.dispose();
		}
	}

	/** A routine that plainly returns must never be taken for a terminating one. */
	@Test
	public void testOrdinaryCallKeepsItsFallThrough() throws Exception {
		// The callee: INT 21h (AH=9, print) then RETF.
		ProgramBuilder builder = callerAndCallee("b4 09 cd 21 cb");
		try {
			assertNotNull("setup: the callee must be decoded", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0122")));
			assertEquals("an INT 21h that is not 4Ch terminates nothing", 0,
				sealNonReturning(builder));
			Instruction call = builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0100"));
			assertEquals(FlowOverride.NONE, call.getFlowOverride());
			assertNotNull("its fall-through stands", call.getFallThrough());
		}
		finally {
			builder.dispose();
		}
	}

	/** {@code CALLF 1000:0120; RETF}, the callee given as bytes, both decoded and made functions. */
	private ProgramBuilder callerAndCallee(String callee) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("EXIT", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "9a 20 01 00 10 cb");
			builder.setBytes("0x1000:0x0120", callee);
			// Each disassemble stays inside the bytes it is given, so decode both.
			builder.disassemble("0x1000:0x0100", 6, false);
			builder.disassemble("0x1000:0x0120", callee.split(" ").length, false);
			builder.createFunction("0x1000:0x0120");
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	/** {@code MOV AH,4Ch; MOV AL,1; INT 21h}: loading the exit code into AL leaves AH alone. */
	@Test
	public void testExitWithCodeLoadedIntoAlIsRecognised() throws Exception {
		ProgramBuilder builder = callerAndCallee("b4 4c b0 01 cd 21");
		try {
			assertEquals(1, sealNonReturning(builder));
			Instruction call = builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0100"));
			assertEquals(FlowOverride.CALL_RETURN, call.getFlowOverride());
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * An exit directly above an ordinary DOS call: {@code MOV AX,4C01h; INT 21h} then the
	 * callee {@code MOV AH,[BX]; INT 21h; RETF}. The callee's {@code AH} comes from memory, so
	 * its {@code INT 21h} is no exit — the walk must neither skip the load nor run on into the
	 * routine above.
	 */
	@Test
	public void testExitOfRoutineAboveIsNotBorrowed() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("EXIT", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "9a 25 01 00 10 cb");   // CALLF 1000:0125; RETF
			builder.setBytes("0x1000:0x0120", "b8 01 4c cd 21");      // the routine above
			builder.setBytes("0x1000:0x0125", "8a 27 cd 21 cb");      // MOV AH,[BX]; INT 21; RETF
			builder.disassemble("0x1000:0x0100", 6, false);
			builder.disassemble("0x1000:0x0120", 10, false);
			// The callee first, so the routine above, which still falls into it, stops there.
			builder.createFunction("0x1000:0x0125");
			builder.createFunction("0x1000:0x0120");

			sealNonReturning(builder);

			Listing listing = builder.getProgram().getListing();
			assertEquals("the callee's INT 21h is not an exit", FlowOverride.NONE,
				listing.getInstructionAt(builder.addr("0x1000:0x0127")).getFlowOverride());
			Instruction call = listing.getInstructionAt(builder.addr("0x1000:0x0100"));
			assertEquals(FlowOverride.NONE, call.getFlowOverride());
			assertNotNull("the call to it keeps its fall-through", call.getFallThrough());
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * {@code JZ 0127; MOV AX,4C01h; INT 21h} with nothing decoded at {@code 0127}: one path
	 * exits, the other leaves the body for code the test cannot see. A body cut short like
	 * that — by a conflict, typically — must not make the routine look terminating.
	 */
	@Test
	public void testRoutineWithAnUnseenPathIsNotTerminating() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("EXIT", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "9a 20 01 00 10 cb");
			builder.setBytes("0x1000:0x0120", "74 05 b8 01 4c cd 21 cb");
			builder.disassemble("0x1000:0x0100", 6, false);
			builder.disassemble("0x1000:0x0120", 7, false); // 0127 stays undecoded
			builder.createFunction("0x1000:0x0120");

			assertEquals(0, sealNonReturning(builder));
			Instruction call = builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0100"));
			assertNotNull("the call keeps its fall-through", call.getFallThrough());
			assertFalse(builder.getProgram()
					.getFunctionManager()
					.getFunctionAt(builder.addr("0x1000:0x0120"))
					.hasNoReturn());
		}
		finally {
			builder.dispose();
		}
	}

	private static int clearStaleNoReturns(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("clear stale no-return flags");
		try {
			return StaleNoReturns.clear(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/** The category Ghidra's "Non-Returning Functions - Discovered" pass bookmarks with. */
	private static final String DISCOVERED = "Non-Returning Function";

	/**
	 * ROE2MAIN's {@code __ftol} and one of its callers, after Ghidra's discovery pass got the
	 * callee wrong: the callee flagged and bookmarked, the call cut off, the caller's body
	 * stopping at it, and the code after it a function nothing calls.
	 * <pre>
	 *   0100  55               PUSH BP
	 *   0101  9a 40 01 00 10   CALLF 1000:0140   ; CALL_RETURN override
	 *   0106  b8 01 00         MOV AX,1          ; FUN_1000_0106, 0 callers
	 *   0109  5d               POP BP
	 *   010a  cb               RETF
	 *   0140  callee
	 * </pre>
	 * With {@code discovered} false the flag is there without the discovery pass's bookmark,
	 * as one set by name or by hand is.
	 */
	private ProgramBuilder cutCallerProgram(String callee, boolean discovered) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("NORET", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x50);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "55 9a 40 01 00 10 b8 01 00 5d cb");
			builder.setBytes("0x1000:0x0140", callee);
			builder.disassemble("0x1000:0x0100", 11, false);
			builder.disassemble("0x1000:0x0140", callee.split(" ").length, false);
			builder.createFunction("0x1000:0x0140");
			builder.createFunction("0x1000:0x0100");
			Program program = builder.getProgram();
			int txId = program.startTransaction("discover a wrong no-return");
			try {
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0140"))
						.setNoReturn(true);
				if (discovered) {
					program.getBookmarkManager()
							.setBookmark(builder.addr("0x1000:0x0140"), BookmarkType.ANALYSIS,
								DISCOVERED, "Non-Returning Function Found");
				}
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0101"))
						.setFlowOverride(FlowOverride.CALL_RETURN);
				CreateFunctionCmd.fixupFunctionBody(program,
					program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0100")),
					TaskMonitor.DUMMY);
			}
			finally {
				program.endTransaction(txId, true);
			}
			builder.createFunction("0x1000:0x0106");
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	@Test
	public void testDiscoveredNoReturnOnReturningBodyIsCleared() throws Exception {
		ProgramBuilder builder = cutCallerProgram("33 c0 cb", true); // XOR AX,AX; RETF
		try {
			Program program = builder.getProgram();
			FunctionManager functions = program.getFunctionManager();
			assertFalse("setup: the caller must stop at the call",
				functions.getFunctionAt(builder.addr("0x1000:0x0100"))
						.getBody()
						.contains(builder.addr("0x1000:0x010a")));

			assertEquals(1, clearStaleNoReturns(builder));

			assertFalse("the callee returns",
				functions.getFunctionAt(builder.addr("0x1000:0x0140")).hasNoReturn());
			assertNull("and the discovery pass's verdict goes with the flag",
				program.getBookmarkManager()
						.getBookmark(builder.addr("0x1000:0x0140"), BookmarkType.ANALYSIS,
							DISCOVERED));
			Instruction call = program.getListing().getInstructionAt(builder.addr("0x1000:0x0101"));
			assertEquals(FlowOverride.NONE, call.getFlowOverride());
			assertNull("the orphan below the call is gone",
				functions.getFunctionAt(builder.addr("0x1000:0x0106")));
			assertTrue("and the caller owns its code again, down to its RETF",
				functions.getFunctionAt(builder.addr("0x1000:0x0100"))
						.getBody()
						.contains(builder.addr("0x1000:0x010a")));
			assertEquals("a second run must find nothing", 0, clearStaleNoReturns(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/** A discovered verdict on a body without a return is the discovery pass being right. */
	@Test
	public void testDiscoveredNoReturnWithoutReturnStands() throws Exception {
		ProgramBuilder builder = cutCallerProgram("eb fe", true); // JMP $
		try {
			assertEquals(0, clearStaleNoReturns(builder));
			Program program = builder.getProgram();
			assertTrue(program.getFunctionManager()
					.getFunctionAt(builder.addr("0x1000:0x0140"))
					.hasNoReturn());
			assertEquals(FlowOverride.CALL_RETURN, program.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0101"))
					.getFlowOverride());
			assertNotNull(program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0106")));
		}
		finally {
			builder.dispose();
		}
	}

	/** A flag the discovery pass did not set — by name, by hand — is never second-guessed. */
	@Test
	public void testUndiscoveredNoReturnStands() throws Exception {
		ProgramBuilder builder = cutCallerProgram("33 c0 cb", false);
		try {
			assertEquals(0, clearStaleNoReturns(builder));
			assertTrue(builder.getProgram()
					.getFunctionManager()
					.getFunctionAt(builder.addr("0x1000:0x0140"))
					.hasNoReturn());
		}
		finally {
			builder.dispose();
		}
	}

	/** A discovered verdict on a function whose signature someone has since committed stands. */
	@Test
	public void testDiscoveredNoReturnOnCommittedSignatureStands() throws Exception {
		ProgramBuilder builder = cutCallerProgram("33 c0 cb", true);
		try {
			Program program = builder.getProgram();
			Function callee = program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0140"));
			builder.withTransaction(() -> callee.setSignatureSource(SourceType.USER_DEFINED));

			assertEquals(0, clearStaleNoReturns(builder));
			assertTrue(callee.hasNoReturn());
		}
		finally {
			builder.dispose();
		}
	}

	/** A function behind the cut call that someone has commented is theirs, not an orphan. */
	@Test
	public void testCommentedFunctionBehindTheCallIsKept() throws Exception {
		ProgramBuilder builder = cutCallerProgram("33 c0 cb", true);
		try {
			Program program = builder.getProgram();
			Function split = program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0106"));
			builder.withTransaction(() -> split.setComment("split off by hand"));

			assertEquals(1, clearStaleNoReturns(builder));

			assertEquals("the call is restored", FlowOverride.NONE, program.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0101"))
					.getFlowOverride());
			assertNotNull("but the commented function stays",
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0106")));
		}
		finally {
			builder.dispose();
		}
	}

	private static int clearFiller(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("clear filler islands");
		try {
			return FillerIslands.clear(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/** A block of zero fill with a routine before it, and nothing pointing into it. */
	private ProgramBuilder fillerProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("FILL", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x60);
			builder.withTransaction(() -> code.setExecute(true));
			// 0100: a real routine, ending in RETF — the fill starts at 0104 and runs
			// to the end of the block, exactly as the DGROUP tail does in the corpus.
			builder.setBytes("0x1000:0x0100", "55 8b ec cb");
			builder.disassemble("0x1000:0x0100", 4, true);
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	/**
	 * NEBULAR's island in miniature: something disassembled the zero fill at an address
	 * it never checked, and did it twice, one byte out of phase — the phase break is
	 * the "conflicting instruction" the disassembler bookmarks. Both chains must go,
	 * and neither may be left behind as an orphan.
	 */
	@Test
	public void testZeroFillIslandsAreDeleted() throws Exception {
		ProgramBuilder builder = fillerProgram();
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			builder.disassemble("0x1000:0x0110", 20, false); // chain A, even phase
			builder.disassemble("0x1000:0x0125", 20, false); // chain B, odd phase
			builder.withTransaction(() -> {
				// The conflict mark sits in the one-byte HOLE between the chains —
				// chain A's last instruction ends at 0x0123, chain B starts at 0x0125 —
				// so it lies on no instruction at all. That is the real shape (NEBULAR
				// 2078:18eb), and a sweep that followed instruction extents would miss it.
				program.getBookmarkManager()
						.setBookmark(builder.addr("0x1000:0x0124"), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY,
							"Failed to disassemble at 1000:0124 due to conflicting " +
								"instruction (flow from 1000:0122)");
				program.getBookmarkManager()
						.setBookmark(builder.addr("0x1000:0x0137"), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY,
							"Maximum run of repeated byte instructions exceeded " +
								"(flow from 1000:0135)");
			});
			assertNotNull("setup: the fill must be decoded as instructions",
				listing.getInstructionAt(builder.addr("0x1000:0x0110")));

			assertTrue("every instruction in both chains is deleted",
				clearFiller(builder) >= 20);

			for (long offset = 0x0104; offset <= 0x015f; offset++) {
				assertNull("no instruction may survive in the fill at " + offset,
					listing.getInstructionAt(
						builder.addr(String.format("0x1000:0x%04x", offset))));
			}
			assertNull("the conflict mark in the hole goes with the junk it described",
				program.getBookmarkManager()
						.getBookmark(builder.addr("0x1000:0x0124"), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
			assertNull("and so does the abandoned-run mark",
				program.getBookmarkManager()
						.getBookmark(builder.addr("0x1000:0x0137"), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
			assertNotNull("the routine above the fill is untouched",
				listing.getInstructionAt(builder.addr("0x1000:0x0100")));
			assertEquals("a second run finds nothing", 0, clearFiller(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The control that decides the whole design. {@code 00 00} is a real instruction —
	 * SPHERE's {@code OVL023_03D4} stores a byte with it ({@code MOV SI,[BP-0x3e];
	 * ADD [BX+SI],AL; JMP ...}) — so the test can never be "this instruction decodes
	 * from zeros". It is "these bytes are a long run of zeros", and here they are not.
	 */
	@Test
	public void testGenuineZeroInstructionInRealCodeSurvives() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("REAL", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			// 8b 76 c4 | 00 00 | eb 02 | cb  — transcribed from SPHERE 02f5ff.
			builder.setBytes("0x1000:0x0100", "55 8b ec 8b 76 c4 00 00 eb 02 90 90 cb");
			builder.disassemble("0x1000:0x0100", 13, true);
			Instruction store =
				builder.getProgram().getListing().getInstructionAt(builder.addr("0x1000:0x0106"));
			assertNotNull("setup: the byte store must be decoded", store);
			assertEquals("ADD", store.getMnemonicString());

			assertEquals("a 00 00 instruction in real code is not fill", 0,
				clearFiller(builder));
			assertNotNull("and it must still be there", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0106")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * An instruction whose bytes only partly lie in the fill — {@code MOV AX,0} is
	 * {@code b8 00 00} — belongs to the code before it, not to the island.
	 */
	@Test
	public void testInstructionStraddlingTheFillEdgeSurvives() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("EDGE", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			// 0100: PUSH BP; MOV BP,SP; MOV AX,0 — the MOV's last two bytes are zeros
			// and run straight into the fill that follows.
			builder.setBytes("0x1000:0x0100", "55 8b ec b8 00 00");
			builder.disassemble("0x1000:0x0100", 6, true);
			builder.disassemble("0x1000:0x0110", 16, false); // junk decoded from the fill

			clearFiller(builder);

			Instruction mov = builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0103"));
			assertNotNull("MOV AX,0 is code, not fill", mov);
			assertEquals("MOV", mov.getMnemonicString());
			assertNull("the junk decoded from the fill is gone", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0110")));
		}
		finally {
			builder.dispose();
		}
	}

	/** Real code running into the fill claims it: that is Detector E's business. */
	@Test
	public void testFillFallenIntoFromRealCodeIsLeftAlone() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("FALL", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", "55 8b ec"); // falls straight into the fill
			builder.disassemble("0x1000:0x0100", 24, true);

			assertEquals("something runs into this fill: not ours to delete", 0,
				clearFiller(builder));
			assertNotNull(builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0103")));
		}
		finally {
			builder.dispose();
		}
	}

	/** A jump into the fill claims it too. */
	@Test
	public void testReferencedFillIsLeftAlone() throws Exception {
		ProgramBuilder builder = fillerProgram();
		try {
			builder.setBytes("0x1000:0x0104", "eb 0a"); // JMP 0110, inside the fill
			builder.disassemble("0x1000:0x0104", 2, true);
			builder.disassemble("0x1000:0x0110", 16, false);

			assertEquals("something jumps here: leave it", 0, clearFiller(builder));
			assertNotNull(builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0110")));
		}
		finally {
			builder.dispose();
		}
	}

	/** A NOP sled is real code, however long and however unreferenced. */
	@Test
	public void testNopSledIsNotFill() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("NOPS", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0110",
				"90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90");
			builder.disassemble("0x1000:0x0110", 20, false);

			assertEquals("0x90 is an instruction, not fill", 0, clearFiller(builder));
			assertNotNull(builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0110")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * A mark describing junk that is already gone is a fossil. The disassembler never
	 * takes its bookmarks back, so one outlives the instructions it complained about —
	 * and on a program repaired by an earlier run there is no longer any instruction
	 * there to sweep it alongside.
	 */
	@Test
	public void testFossilBookmarkInFillIsSwept() throws Exception {
		ProgramBuilder builder = fillerProgram();
		try {
			Program program = builder.getProgram();
			// The fill was already cleared; only the mark is left, on undefined bytes.
			builder.withTransaction(() -> program.getBookmarkManager()
					.setBookmark(builder.addr("0x1000:0x0123"), BookmarkType.ERROR,
						Disassembler.ERROR_BOOKMARK_CATEGORY,
						"Failed to disassemble at 1000:0123 due to conflicting " +
							"instruction (flow from 1000:0121)"));

			assertEquals("there is no junk left to clear", 0, clearFiller(builder));
			assertNull("but the mark it left behind must go", program.getBookmarkManager()
					.getBookmark(builder.addr("0x1000:0x0123"), BookmarkType.ERROR,
						Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	/** A cleared island must not come straight back through the gap filler. */
	@Test
	public void testClearedIslandIsNotRefilled() throws Exception {
		ProgramBuilder builder = fillerProgram();
		try {
			builder.disassemble("0x1000:0x0110", 20, false);
			assertTrue(clearFiller(builder) > 0);

			assertEquals("the gap filler refuses fill", 0, fillGaps(builder));
			assertNull("and the island stays undefined", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0110")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * An unresolved RTLink dispatch stub — {@code CALLF dispatcher; JMPF 0000:offset},
	 * whose segment stays unrelocated until the overlay manager patches it at runtime —
	 * decodes perfectly and lands exactly on the code after it. It is still not ours:
	 * {@code RTLinkOverlayAnalyzer} turns these into thunks, and decoding one here
	 * leaves a real instruction whose flow points into memory that does not exist.
	 */
	@Test
	public void testStubsFlowingIntoNonExistentMemoryAreNotClaimed() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("STUB", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			// 0100: PUSH BP; MOV BP,SP; RETF        — a routine, disassembled
			// 0104: CALLF 1000:0100; JMPF 0000:0341 — the stub, undefined (the gap)
			// 010e: PUSH BP; MOV BP,SP; RETF        — the next routine
			builder.setBytes("0x1000:0x0100",
				"55 8b ec cb " + "9a 00 01 00 10 ea 41 03 00 00 " + "55 8b ec cb");
			builder.disassemble("0x1000:0x0100", 4, true);
			builder.disassemble("0x1000:0x010e", 4, true);
			builder.createFunction("0x1000:0x010e");

			assertEquals("a stub whose jump goes nowhere is not ours to claim", 0,
				fillGaps(builder));
			assertNull("the stub must stay undefined for the overlay analyzer",
				builder.getProgram()
						.getListing()
						.getInstructionAt(builder.addr("0x1000:0x0104")));
		}
		finally {
			builder.dispose();
		}
	}
}
