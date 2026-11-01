package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.HexFormat;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Characterization tests for {@link RTLinkSwitchTableAnalyzer#recoverTable}: each switch form
 * the analyzer recognizes, on bytes transcribed from the corpus (VICEROY, NEBULAR, RETURN),
 * with the exact destinations it recovers today. They pin behaviour for the refactor, so a
 * change in what is accepted, or in how a table is counted or anchored, shows up here before
 * it shows up in a decompilation.
 * <p>
 * Overlay tables are resolved against the module base the overlay analyzer records for the
 * block; each test records the bases that put its table where the corpus has it.
 */
public class RTLinkSwitchTableRecognizerTest extends AbstractGenericTest {

	// ---------------------------------------------------------------- harness

	/** A resident code block at {@code start} holding {@code hex}. */
	private static ProgramBuilder resident(String start, int size, String hex) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("SWITCH", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock block = builder.createMemory("CODE", start, size);
			builder.withTransaction(() -> block.setExecute(true));
			builder.setBytes(start, hex);
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
	 * An overlay block {@code name} of {@code size} bytes, with {@code hex} at page offset
	 * {@code at} and {@code bases} recorded as its module base paragraphs (none if empty).
	 */
	private static ProgramBuilder overlay(String name, int size, int at, String hex,
			List<Integer> bases) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("SWITCH", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock block = builder.createOverlayMemory(name, "0x2d00:0x0000", size);
			Program program = builder.getProgram();
			int txId = program.startTransaction("overlay");
			try {
				block.setExecute(true);
				program.getMemory().setBytes(block.getStart().add(at), bytes(hex));
				if (!bases.isEmpty()) {
					RTLinkProgram.recordModuleBases(program, name, bases);
				}
			}
			finally {
				program.endTransaction(txId, true);
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

	private static byte[] bytes(String hex) {
		return HexFormat.of().parseHex(hex.replace(" ", ""));
	}

	/** Disassemble {@code length} bytes at {@code start} without following flow. */
	private static void decode(Program program, Address start, int length) {
		int txId = program.startTransaction("decode");
		try {
			new DisassembleCommand(new AddressSet(start, start.add(length - 1)), null, false)
					.applyTo(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static List<Address> recover(Program program, Address dispatch) {
		Instruction instruction = program.getListing().getInstructionAt(dispatch);
		assertNotNull("setup: no dispatch instruction at " + dispatch, instruction);
		return RTLinkSwitchTableAnalyzer.recoverTable(program, instruction);
	}

	private static List<Address> offsets(MemoryBlock block, int... offsets) {
		return java.util.Arrays.stream(offsets).mapToObj(o -> block.getStart().add(o)).toList();
	}

	// ---------------------------------------------------------------- resident CS: tables

	/**
	 * VICEROY {@code 1aea:000b}: {@code SUB AX,0x110; CMP AX,0x22; JA; SHL AX,1; XCHG AX,BX;
	 * JMP CS:[BX+0x22]} in a segment not on a 64KB page — 35 entries, 27 distinct targets.
	 */
	private static final String VICEROY_1AEA =
		"90 55 8b ec 50 8b d0 2d 10 01 3d 22 00 77 4e d1 " +
			"e0 93 2e ff a7 22 00 80 00 86 00 8c 00 92 00 9a " +
			"00 a0 00 a6 00 ac 00 b2 00 b8 00 68 00 68 00 68 " +
			"00 68 00 be 00 c4 00 ca 00 d0 00 d6 00 dc 00 e2 " +
			"00 e8 00 ee 00 68 00 68 00 68 00 68 00 68 00 f4 " +
			"00 fa 00 00 01 06 01 0c 01 12 01 18 01";

	private static final int[] VICEROY_1AEA_TARGETS = { 0x80, 0x86, 0x8c, 0x92, 0x9a, 0xa0,
		0xa6, 0xac, 0xb2, 0xb8, 0x68, 0xbe, 0xc4, 0xca, 0xd0, 0xd6, 0xdc, 0xe2, 0xe8, 0xee,
		0xf4, 0xfa, 0x100, 0x106, 0x10c, 0x112, 0x118 };

	@Test
	public void testResidentTableScaledByShl() throws Exception {
		assertResidentTable(VICEROY_1AEA);
	}

	/** The same switch with the doubling written {@code ADD AX,AX}, as ROE2MAIN writes all 60. */
	@Test
	public void testResidentTableScaledByAdd() throws Exception {
		assertResidentTable(VICEROY_1AEA.replace("d1 e0 93", "03 c0 93"));
	}

	private static void assertResidentTable(String hex) throws Exception {
		ProgramBuilder builder = resident("0x1aea:0x000b", 0x112, hex);
		try {
			Program program = builder.getProgram();
			decode(program, builder.addr("0x1aea:0x000c"), 0x16);
			List<Address> targets = recover(program, builder.addr("0x1aea:0x001d"));
			List<Address> expected = java.util.Arrays.stream(VICEROY_1AEA_TARGETS)
					.mapToObj(o -> builder.addr(String.format("0x1aea:0x%04x", o)))
					.toList();
			assertEquals(expected, targets);
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * A resident table is held to the same entry tests as the other forms: an entry that lands
	 * inside the table's own bytes, or in the middle of an instruction already decoded, means
	 * the guard or the anchor was misread, and the table is refused rather than half-planted.
	 */
	@Test
	public void testResidentTableRefusesImpossibleEntries() throws Exception {
		assertResidentTableRefused("an entry inside the table",
			VICEROY_1AEA.replace("a7 22 00 80 00", "a7 22 00 24 00"));
		assertResidentTableRefused("an entry inside MOV BP,SP at 000d",
			VICEROY_1AEA.replace("a7 22 00 80 00", "a7 22 00 0e 00"));
	}

	private static void assertResidentTableRefused(String why, String hex) throws Exception {
		ProgramBuilder builder = resident("0x1aea:0x000b", 0x112, hex);
		try {
			Program program = builder.getProgram();
			decode(program, builder.addr("0x1aea:0x000c"), 0x16);
			assertNull(why, recover(program, builder.addr("0x1aea:0x001d")));
		}
		finally {
			builder.dispose();
		}
	}

	/** The same bytes in a segment on a 64KB page: currentCS gets that right, so hands off. */
	@Test
	public void testPageAlignedSegmentIsLeftToStock() throws Exception {
		ProgramBuilder builder = resident("0x1000:0x000b", 0x112, VICEROY_1AEA);
		try {
			Program program = builder.getProgram();
			decode(program, builder.addr("0x1000:0x000c"), 0x16);
			assertNull(recover(program, builder.addr("0x1000:0x001d")));
		}
		finally {
			builder.dispose();
		}
	}

	// ---------------------------------------------------------------- recorded targets

	/**
	 * The targets kept for a pending override come back as the same addresses, in the
	 * dispatch's own space and segment form, both in a segment off the 64KB page and in an
	 * overlay; a consumed record comes back empty.
	 */
	@Test
	public void testRecordedTargetsRoundTrip() throws Exception {
		ProgramBuilder builder = resident("0x1aea:0x000b", 0x112, VICEROY_1AEA);
		try {
			assertRoundTrip(builder.getProgram(), builder.addr("0x1aea:0x001d"),
				List.of(builder.addr("0x1aea:0x0080"), builder.addr("0x1aea:0x0118")));
		}
		finally {
			builder.dispose();
		}
		builder = overlay("OVERLAY_25", 0xa20, 0x316, "90", List.of(0, 0xb));
		try {
			Program program = builder.getProgram();
			MemoryBlock block = program.getMemory().getBlock("OVERLAY_25");
			assertRoundTrip(program, block.getStart().add(0x321), offsets(block, 0xd2, 0x30e));
		}
		finally {
			builder.dispose();
		}
	}

	private static void assertRoundTrip(Program program, Address dispatch, List<Address> targets) {
		int txId = program.startTransaction("record");
		try {
			RTLinkProgram.recordSwitch(program, dispatch, targets);
			List<Address> read = RTLinkProgram.switchTargets(program, dispatch);
			assertEquals(targets, read);
			assertEquals(targets.toString(), read.toString());
			assertEquals(dispatch, RTLinkProgram.pendingSwitches(program,
				new AddressSet(dispatch, dispatch)).next());
			RTLinkProgram.consumeSwitch(program, dispatch);
			assertEquals(List.of(), RTLinkProgram.switchTargets(program, dispatch));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	// ---------------------------------------------------------------- overlay module tables

	/**
	 * NEBULAR {@code OVERLAY_25::0321}: {@code SUB AX,0x46; CMP AX,9; JA; SHL AX,1; XCHG AX,BX;
	 * JMP CS:[BX+0x276]} in the module based at paragraph {@code 0x0b}. The table
	 * ({@code 0x326}-{@code 0x339}) runs past the next anchor, {@code 0x33} = {@code 0x330};
	 * it starts right after the dispatch, which proves its anchor, so it is accepted.
	 */
	@Test
	public void testAdjacentTableMayRunPastTheNextAnchor() throws Exception {
		String hex = "2d 46 00 3d 09 00 77 1c d1 e0 93 2e ff a7 76 02 " +
			"22 00 b4 00 ea 00 62 01 8e 01 c0 01 f2 01 26 02 5e 02 4c 01";
		ProgramBuilder builder = overlay("OVERLAY_25", 0xa20, 0x316, hex, List.of(0, 0xb, 0x33));
		try {
			Program program = builder.getProgram();
			MemoryBlock block = program.getMemory().getBlock("OVERLAY_25");
			decode(program, block.getStart().add(0x316), 0x10);
			assertEquals(offsets(block, 0xd2, 0x164, 0x19a, 0x212, 0x23e, 0x270, 0x2a2, 0x2d6,
				0x30e, 0x1fc), recover(program, block.getStart().add(0x321)));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * NEBULAR {@code OVERLAY_27::00ff}: a Borland switch over strided cases
	 * ({@code SUB AX,0x14; CMP AX,0x78; JA; MOV BL,10; DIV BL; OR AH,AH; JNZ; SHL AX,1;
	 * XCHG AX,BX; JMP CS:[BX+0x104]}) — 0x78/10 + 1 = 13 entries, here all one target.
	 */
	@Test
	public void testStridedTableThroughAByteDivide() throws Exception {
		String hex = "2d 14 00 3d 78 00 77 2a b3 0a f6 f3 0a e4 75 22 " +
			"d1 e0 93 2e ff a7 04 01 32 00 32 00 32 00 32 00 " +
			"32 00 32 00 32 00 32 00 32 00 32 00 32 00 32 00 32 00 83 7e";
		ProgramBuilder builder = overlay("OVERLAY_27", 0xcd0, 0xec, hex, List.of(0));
		try {
			Program program = builder.getProgram();
			MemoryBlock block = program.getMemory().getBlock("OVERLAY_27");
			decode(program, block.getStart().add(0xec), 0x18);
			assertEquals(offsets(block, 0x32), recover(program, block.getStart().add(0xff)));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * RETURN {@code OVERLAY_43::0cf5}: the index is halved back to a byte offset
	 * ({@code SHR AX,1; CMP AX,0x12; JA; XCHG AX,BX; JMP CS:[BX+0x30a]}) — no doubling, so the
	 * bound counts bytes: 0x12/2 + 1 = 10 entries, 7 distinct, module base {@code 0x9f}.
	 */
	@Test
	public void testByteOffsetIndexHalved() throws Exception {
		String hex = "2d da ff a8 03 75 21 d1 e8 3d 12 00 77 1a 93 2e " +
			"ff a7 0a 03 60 02 f2 01 1e 03 1e 03 1e 03 9c 01 8e 01 1e 03 60 01 56 01";
		ProgramBuilder builder = overlay("OVERLAY_43", 0xd30, 0xce6, hex, List.of(0, 0x9f));
		try {
			Program program = builder.getProgram();
			MemoryBlock block = program.getMemory().getBlock("OVERLAY_43");
			decode(program, block.getStart().add(0xce6), 0x14);
			assertEquals(offsets(block, 0xc50, 0xbe2, 0xd0e, 0xb8c, 0xb7e, 0xb50, 0xb46),
				recover(program, block.getStart().add(0xcf5)));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * RETURN {@code OVERLAY_38::125b}: the index merely required even ({@code TEST AL,1; JNZ;
	 * CMP AX,0x16; JA; XCHG AX,BX; JMP CS:[BX+0x260]}) — 0x16/2 + 1 = 12 entries, 11 distinct,
	 * module base {@code 0x100}.
	 */
	@Test
	public void testByteOffsetIndexRequiredEven() throws Exception {
		String hex = "2d 43 00 a8 01 75 23 3d 16 00 77 1e 93 2e ff a7 " +
			"60 02 4c 01 d0 01 10 02 78 02 7a 01 5a 01 6a 01 36 01 0a 01 78 02 22 01 2c 01";
		ProgramBuilder builder = overlay("OVERLAY_38", 0x12d0, 0x124e, hex, List.of(0, 0x100));
		try {
			Program program = builder.getProgram();
			MemoryBlock block = program.getMemory().getBlock("OVERLAY_38");
			decode(program, block.getStart().add(0x124e), 0x12);
			assertEquals(offsets(block, 0x114c, 0x11d0, 0x1210, 0x1278, 0x117a, 0x115a, 0x116a,
				0x1136, 0x110a, 0x1122, 0x112c), recover(program, block.getStart().add(0x125b)));
		}
		finally {
			builder.dispose();
		}
	}

	/** Without a recorded module base the overlay table cannot be anchored: hands off. */
	@Test
	public void testOverlayWithoutModuleBasesIsLeftAlone() throws Exception {
		String hex = "2d 46 00 3d 09 00 77 1c d1 e0 93 2e ff a7 76 02 " +
			"22 00 b4 00 ea 00 62 01 8e 01 c0 01 f2 01 26 02 5e 02 4c 01";
		ProgramBuilder builder = overlay("OVERLAY_25", 0xa20, 0x316, hex, List.of());
		try {
			Program program = builder.getProgram();
			MemoryBlock block = program.getMemory().getBlock("OVERLAY_25");
			decode(program, block.getStart().add(0x316), 0x10);
			assertNull(recover(program, block.getStart().add(0x321)));
		}
		finally {
			builder.dispose();
		}
	}

	// ---------------------------------------------------------------- DGROUP data table

	/**
	 * ROE2MAIN {@code 122e:5280}: {@code MOV DI,0xb26a; XOR CX,CX; MOV CL,[BX+SI+5]; ADD DI,CX;
	 * JMP word ptr [DI]}, its table in DGROUP ({@code 35f5}) at {@code b26a}: four cases
	 * ({@code 52ae 5282 528a 52a3}) and then {@code 0x0078}, a valid instruction address in the
	 * same block but in another function. The dispatching function runs from the call target
	 * {@code 51d5} to the next one, {@code 530c}, which is what ends the table. The two calls at
	 * {@code 5300} stand in for the program's callers of those entries.
	 */
	@Test
	public void testDgroupTableBoundedByTheCallingFunction() throws Exception {
		ProgramBuilder builder = resident("0x122e:0x51d0", 0x140, "c3");
		try {
			Program program = builder.getProgram();
			builder.setBytes("0x122e:0x5276", "bf 6a b2 33 c9 8a 48 05 03 f9 ff 25");
			builder.setBytes("0x122e:0x5300", "e8 d2 fe e8 06 00 c3"); // CALL 51d5; CALL 530c
			builder.createMemory("DGROUP", "0x35f5:0xb26a", 0x10);
			builder.setBytes("0x35f5:0xb26a", "ae 52 82 52 8a 52 a3 52 78 00");
			builder.setRegisterValue("DS", "0x122e:0x51d0", "0x122e:0x530f", 0x35f5);
			decode(program, builder.addr("0x122e:0x5276"), 12);
			decode(program, builder.addr("0x122e:0x5300"), 7);
			assertEquals(List.of(builder.addr("0x122e:0x52ae"), builder.addr("0x122e:0x5282"),
				builder.addr("0x122e:0x528a"), builder.addr("0x122e:0x52a3")),
				recover(program, builder.addr("0x122e:0x5280")));
		}
		finally {
			builder.dispose();
		}
	}
}
