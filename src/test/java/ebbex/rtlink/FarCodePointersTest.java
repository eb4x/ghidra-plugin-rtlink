package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
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
public class FarCodePointersTest extends RealModeTest {

	private static final String TARGET = "0x1000:0x0130";

	private RealMode program(String code) throws Exception {
		return program(code, null);
	}

	/** With {@code callee} (bytes) at 1000:0150, decoded and made a function first. */
	private RealMode program(String code, String callee) throws Exception {
		RealMode builder = realMode("FARPTR");
		builder.code("0x1000:0x0100", 0x100);
		builder.setBytes("0x1000:0x0100", code);
		builder.setBytes(TARGET, "cf");
		if (callee != null) {
			builder.setBytes("0x1000:0x0150", callee);
			builder.disassemble("0x1000:0x0150", callee.split(" ").length, true);
			builder.createFunction("0x1000:0x0150");
		}
		builder.disassemble("0x1000:0x0100", code.split(" ").length, true);
		return builder;
	}

	private static int recover(RealMode builder) throws Exception {
		return builder.tx(() -> FarCodePointers.recover(builder.getProgram(), TaskMonitor.DUMMY));
	}

	private static void assertRecovered(RealMode builder, String from) throws Exception {
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
		assertRecovered(program("26 c7 06 84 00 30 01 8c c8 26 a3 86 00 c3"), "0x1000:0x0109");
	}

	/** {@code MOV ES:[0xa],0x130 ; MOV ES:[0xc],CS ; RET} — the PSP terminate hook, 275d:0732. */
	@Test
	public void testVectorStoredDirectly() throws Exception {
		assertRecovered(program("26 c7 06 0a 00 30 01 26 8c 0e 0c 00 c3"), "0x1000:0x0107");
	}

	/**
	 * {@code MOV AX,0x130 ; MOV DX,CS ; XCHG SS:[SI],AX ; XCHG SS:[SI+2],DX ; RET} — the VM's
	 * return vector, 210d:29cd.
	 */
	@Test
	public void testReturnVectorExchangedOntoTheStack() throws Exception {
		assertRecovered(program("b8 30 01 8c ca 36 87 04 36 87 54 02 c3"), "0x1000:0x0108");
	}

	/**
	 * {@code MOV AX,CS ; MOV DS,AX ; MOV DX,0x130 ; CALLF 1000:0150 ; RET}, where 0150
	 * stores {@code DX} and {@code DS} as a pointer — RTLink's {@code $$RTL_REGISTER},
	 * 210d:0be3.
	 */
	@Test
	public void testPairHandedToAStorer() throws Exception {
		assertRecovered(program("8c c8 8e d8 ba 30 01 9a 50 01 00 10 c3",
			"2e 89 17 2e 8c 5f 02 cb"), "0x1000:0x0107");
	}

	/** {@code MOV AX,CS ; MOV DS,AX ; MOV DX,0x130 ; MOV AX,0x2521 ; INT 21h ; RET}. */
	@Test
	public void testDosSetVector() throws Exception {
		assertRecovered(program("8c c8 8e d8 ba 30 01 b8 21 25 cd 21 c3"), "0x1000:0x010a");
	}

	/**
	 * {@code MOV [DI],0x130 ; ADD DI,4 ; MOV [DI+2],CS ; RET}: the two stores share an
	 * addressing mode but not a word, because DI moved in between.
	 */
	@Test
	public void testMovedBaseRegisterBreaksThePair() throws Exception {
		RealMode builder = program("c7 05 30 01 83 c7 04 8c 4d 02 c3");
		assertEquals(0, recover(builder));
		assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(TARGET)));
	}

	/**
	 * {@code MOV ES:[0x84],0x130 ; MOV ES:[0x85],AL ; MOV ES:[0x86],CS ; RET}: a store the scan
	 * does not model lands in the offset word, so the pair no longer holds {@code 0x130}.
	 */
	@Test
	public void testUnmodelledStoreBreaksThePair() throws Exception {
		RealMode builder = program("26 c7 06 84 00 30 01 26 a2 85 00 26 8c 0e 86 00 c3");
		assertEquals(0, recover(builder));
		assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(TARGET)));
	}

	/**
	 * The PSP-hook shape again, but the target is something the program also reads as data:
	 * a far pointer to a buffer or an EXEC block, not to a handler. It is not disassembled.
	 */
	@Test
	public void testPointerToDataIsNotCode() throws Exception {
		RealMode builder = program("26 c7 06 0a 00 30 01 26 8c 0e 0c 00 c3");
		Program program = builder.getProgram();
		builder.withTransaction(() -> program.getReferenceManager()
				.addMemoryReference(builder.addr("0x1000:0x01f0"), builder.addr(TARGET),
					RefType.READ, SourceType.ANALYSIS, 0));
		assertEquals(0, recover(builder));
		assertNull(program.getListing().getInstructionAt(builder.addr(TARGET)));
	}

	/**
	 * VICEROY {@code 210d:1526}: the routine behind the return vector loads a message address
	 * and jumps to the fatal path, and the string search, run long before, guessed a string
	 * one byte early, on the jump's last byte. Flow from the recovered routine wins: the guess
	 * is cleared and the jump decoded.
	 * <pre>
	 *   0130  bf 36 01   MOV DI,0x0136
	 *   0133  e9 0a 00   JMP 0x0140          ; the guess starts at 0135, its last byte
	 *   0136  "  &lt;x&gt;\r\n\0"
	 *   0140  cf         IRET
	 * </pre>
	 */
	@Test
	public void testFlowRunsThroughAGuessedString() throws Exception {
		RealMode builder = program("b8 30 01 8c ca 36 87 04 36 87 54 02 c3");
		builder.setBytes(TARGET, "bf 36 01 e9 0a 00 20 20 3c 78 3e 0d 0a 00 90 90 cf");
		Program program = builder.getProgram();
		builder.tx(() -> program.getListing()
				.createData(builder.addr("0x1000:0x0135"), new StringDataType(), 9));

		assertEquals(1, recover(builder));

		assertEquals("JMP", program.getListing()
				.getInstructionAt(builder.addr("0x1000:0x0133")).getMnemonicString());
		assertNotNull("and the flow runs on past it",
			program.getListing().getInstructionAt(builder.addr("0x1000:0x0140")));
		assertNull("the guess is gone",
			program.getListing().getDefinedDataContaining(builder.addr("0x1000:0x0135")));
		assertNull("and so is the conflict it caused", program.getBookmarkManager()
				.getBookmark(builder.addr("0x1000:0x0133"), BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY));
	}

	/** A string someone named is theirs: the flow stops at it, as it would at any data. */
	@Test
	public void testFlowStopsAtANamedString() throws Exception {
		RealMode builder = program("b8 30 01 8c ca 36 87 04 36 87 54 02 c3");
		builder.setBytes(TARGET, "bf 36 01 e9 0a 00 20 20 3c 78 3e 0d 0a 00 90 90 cf");
		Program program = builder.getProgram();
		builder.tx(() -> program.getListing()
				.createData(builder.addr("0x1000:0x0135"), new StringDataType(), 9));
		builder.createLabel("0x1000:0x0135", "s_fatal_message");

		assertEquals(1, recover(builder));

		assertNull("the jump stays undecoded",
			program.getListing().getInstructionAt(builder.addr("0x1000:0x0133")));
		assertNotNull("under the named string",
			program.getListing().getDefinedDataAt(builder.addr("0x1000:0x0135")));
	}

	/** The same set-vector with DS never set: DX is an offset into an unknown segment. */
	@Test
	public void testUnknownSegmentIsNoPointer() throws Exception {
		RealMode builder = program("ba 30 01 b8 21 25 cd 21 c3");
		assertEquals(0, recover(builder));
		assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(TARGET)));
	}
}
