package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link FarCodePointers}: a routine nothing calls is recovered when the program
 * builds a {@code CS:imm} far pointer to it — stored into adjacent words, handed as
 * {@code DS:DX} to a routine that stores it so, or installed by DOS set-vector — and not
 * when the segment half is not provably CS.
 * <p>
 * Each program has its code at {@code 1000:0100} and the routine at {@code 1000:0130}
 * ({@code IRET}), which starts out undefined.
 */
public class FarCodePointersTest extends AbstractGenericTest {

	private static final String TARGET = "0x1000:0x0130";

	private static ProgramBuilder program(String code) throws Exception {
		return program(code, null);
	}

	/** With {@code callee} (bytes) at 1000:0150, decoded and made a function first. */
	private static ProgramBuilder program(String code, String callee) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("FARPTR", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock block = builder.createMemory("CODE", "0x1000:0x0100", 0x100);
			builder.withTransaction(() -> block.setExecute(true));
			builder.setBytes("0x1000:0x0100", code);
			builder.setBytes(TARGET, "cf");
			if (callee != null) {
				builder.setBytes("0x1000:0x0150", callee);
				builder.disassemble("0x1000:0x0150", callee.split(" ").length, true);
				builder.createFunction("0x1000:0x0150");
			}
			builder.disassemble("0x1000:0x0100", code.split(" ").length, true);
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	private static int recover(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("far code pointers");
		try {
			return FarCodePointers.recover(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static void assertRecovered(ProgramBuilder builder, String from) throws Exception {
		Program program = builder.getProgram();
		assertNull("setup: the routine starts out undefined",
			program.getListing().getInstructionAt(builder.addr(TARGET)));

		assertEquals(1, recover(builder));

		assertNotNull("the routine becomes a function",
			program.getFunctionManager().getFunctionAt(builder.addr(TARGET)));
		boolean referenced = false;
		for (Reference ref : program.getReferenceManager().getReferencesFrom(builder.addr(from))) {
			referenced |= ref.getToAddress().equals(builder.addr(TARGET));
		}
		assertTrue("the instruction completing the pointer references it", referenced);
		assertEquals("a re-run finds nothing new", 0, recover(builder));
	}

	/** {@code MOV ES:[0x84],0x130 ; MOV AX,CS ; MOV ES:[0x86],AX ; RET} — VICEROY 210d:1b20. */
	@Test
	public void testVectorStoredThroughRegister() throws Exception {
		ProgramBuilder builder = program("26 c7 06 84 00 30 01 8c c8 26 a3 86 00 c3");
		try {
			assertRecovered(builder, "0x1000:0x0109");
		}
		finally {
			builder.dispose();
		}
	}

	/** {@code MOV ES:[0xa],0x130 ; MOV ES:[0xc],CS ; RET} — the PSP terminate hook, 275d:0732. */
	@Test
	public void testVectorStoredDirectly() throws Exception {
		ProgramBuilder builder = program("26 c7 06 0a 00 30 01 26 8c 0e 0c 00 c3");
		try {
			assertRecovered(builder, "0x1000:0x0107");
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * {@code MOV AX,0x130 ; MOV DX,CS ; XCHG SS:[SI],AX ; XCHG SS:[SI+2],DX ; RET} — the VM's
	 * return vector, 210d:29cd.
	 */
	@Test
	public void testReturnVectorExchangedOntoTheStack() throws Exception {
		ProgramBuilder builder = program("b8 30 01 8c ca 36 87 04 36 87 54 02 c3");
		try {
			assertRecovered(builder, "0x1000:0x0108");
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * {@code MOV AX,CS ; MOV DS,AX ; MOV DX,0x130 ; CALLF 1000:0150 ; RET}, where 0150
	 * stores {@code DX} and {@code DS} as a pointer — RTLink's {@code $$RTL_REGISTER},
	 * 210d:0be3.
	 */
	@Test
	public void testPairHandedToAStorer() throws Exception {
		ProgramBuilder builder = program("8c c8 8e d8 ba 30 01 9a 50 01 00 10 c3",
			"2e 89 17 2e 8c 5f 02 cb");
		try {
			assertRecovered(builder, "0x1000:0x0107");
		}
		finally {
			builder.dispose();
		}
	}

	/** {@code MOV AX,CS ; MOV DS,AX ; MOV DX,0x130 ; MOV AX,0x2521 ; INT 21h ; RET}. */
	@Test
	public void testDosSetVector() throws Exception {
		ProgramBuilder builder = program("8c c8 8e d8 ba 30 01 b8 21 25 cd 21 c3");
		try {
			assertRecovered(builder, "0x1000:0x010a");
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * {@code MOV [DI],0x130 ; ADD DI,4 ; MOV [DI+2],CS ; RET}: the two stores share an
	 * addressing mode but not a word, because DI moved in between.
	 */
	@Test
	public void testMovedBaseRegisterBreaksThePair() throws Exception {
		ProgramBuilder builder = program("c7 05 30 01 83 c7 04 8c 4d 02 c3");
		try {
			assertEquals(0, recover(builder));
			assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(TARGET)));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * {@code MOV ES:[0x84],0x130 ; MOV ES:[0x85],AL ; MOV ES:[0x86],CS ; RET}: a store the scan
	 * does not model lands in the offset word, so the pair no longer holds {@code 0x130}.
	 */
	@Test
	public void testUnmodelledStoreBreaksThePair() throws Exception {
		ProgramBuilder builder = program("26 c7 06 84 00 30 01 26 a2 85 00 26 8c 0e 86 00 c3");
		try {
			assertEquals(0, recover(builder));
			assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(TARGET)));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The PSP-hook shape again, but the target is something the program also reads as data:
	 * a far pointer to a buffer or an EXEC block, not to a handler. It is not disassembled.
	 */
	@Test
	public void testPointerToDataIsNotCode() throws Exception {
		ProgramBuilder builder = program("26 c7 06 0a 00 30 01 26 8c 0e 0c 00 c3");
		try {
			Program program = builder.getProgram();
			builder.withTransaction(() -> program.getReferenceManager()
					.addMemoryReference(builder.addr("0x1000:0x01f0"), builder.addr(TARGET),
						RefType.READ, SourceType.ANALYSIS, 0));
			assertEquals(0, recover(builder));
			assertNull(program.getListing().getInstructionAt(builder.addr(TARGET)));
		}
		finally {
			builder.dispose();
		}
	}

	/** The same set-vector with DS never set: DX is an offset into an unknown segment. */
	@Test
	public void testUnknownSegmentIsNoPointer() throws Exception {
		ProgramBuilder builder = program("ba 30 01 b8 21 25 cd 21 c3");
		try {
			assertEquals(0, recover(builder));
			assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(TARGET)));
		}
		finally {
			builder.dispose();
		}
	}
}
