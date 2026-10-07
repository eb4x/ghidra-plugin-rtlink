package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * {@link RTLinkOverlayAnalyzer#movDestination} and {@link RTLinkOverlayAnalyzer#movSourceRegister}
 * read a MOV from its p-code, so the answer cannot depend on operand display order. Stock
 * Ghidra 12.1.3 and 12.1.4 display {@code MOV Sreg,r/m16} ({@code 8E}) with the operands
 * swapped (GP-7018), and reading operand 0 there made the DGROUP detection and the
 * segment-flow guard of {@link RTLinkXrefAnalyzer} miss every segment load: on stock Ghidra
 * DS was never assumed. These assertions hold whichever way the SDK displays the operands.
 */
public class RTLinkSegmentMoveTest extends AbstractGenericTest {

	// @formatter:off
	private static final String CODE =
		"8e d8 " +      // 0000  MOV DS,AX
		"8e c7 " +      // 0002  MOV ES,DI
		"8c c0 " +      // 0004  MOV AX,ES
		"b8 34 12 " +   // 0006  MOV AX,0x1234
		"8b c3 " +      // 0009  MOV AX,BX
		"a1 02 00";     // 000b  MOV AX,[0x2]
	// @formatter:on

	@Test
	public void testSegmentMovesReadFromPcode() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("SREG", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0000", CODE, true);
			Program program = builder.getProgram();

			assertMove(program, "0x1000:0x0000", "DS", "AX");
			assertMove(program, "0x1000:0x0002", "ES", "DI");
			assertMove(program, "0x1000:0x0004", "AX", "ES");
			assertMove(program, "0x1000:0x0006", "AX", null);   // an immediate
			assertMove(program, "0x1000:0x0009", "AX", "BX");
			assertMove(program, "0x1000:0x000b", "AX", null);   // a memory source
		}
		finally {
			builder.dispose();
		}
	}

	private static void assertMove(Program program, String at, String destination,
			String source) {
		Instruction mov = program.getListing()
				.getInstructionAt(program.getAddressFactory().getAddress(at));
		assertNotNull("no instruction at " + at, mov);
		assertEquals(mov + ": destination", destination,
			RTLinkOverlayAnalyzer.movDestination(mov).getName());
		var src = RTLinkOverlayAnalyzer.movSourceRegister(mov);
		assertEquals(mov + ": source", source, src == null ? null : src.getName());
	}
}
