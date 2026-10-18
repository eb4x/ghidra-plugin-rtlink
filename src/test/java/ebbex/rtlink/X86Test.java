package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Tests for {@link X86}: the instruction facts the analyzers share. Each case is one
 * instruction at {@code 1000:0000}, read the way the analyzers read it.
 */
public class X86Test extends AbstractGenericTest {

	/** Decode {@code hex} as one instruction and run {@code check} on it. */
	private static void with(String hex, InstructionCheck check) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("X86", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock block = builder.createMemory("CODE", "0x1000:0x0000", 0x10);
			builder.withTransaction(() -> block.setExecute(true));
			builder.setBytes("0x1000:0x0000", hex);
			builder.disassemble("0x1000:0x0000", hex.split(" ").length, false);
			Program program = builder.getProgram();
			Instruction instruction =
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0000"));
			assertNotNull("setup: " + hex + " must decode", instruction);
			check.check(program, instruction);
		}
		finally {
			builder.dispose();
		}
	}

	@FunctionalInterface
	private interface InstructionCheck {
		void check(Program program, Instruction instruction) throws Exception;
	}

	private static Register reg(Program program, String name) {
		return program.getLanguage().getRegister(name);
	}

	@Test
	public void testWritesCountsOverlappingRegisters() throws Exception {
		with("b3 05", (program, insn) -> { // MOV BL,5
			assertTrue("MOV BL writes BX", X86.writes(insn, reg(program, "BX")));
			assertTrue(X86.writes(insn, reg(program, "BL")));
			assertFalse("but not BH", X86.writes(insn, reg(program, "BH")));
		});
	}

	@Test
	public void testChangesExemptsOrAndOfARegisterWithItself() throws Exception {
		with("0a e4", (program, insn) -> { // OR AH,AH
			assertTrue("OR AH,AH writes AX", X86.writes(insn, reg(program, "AX")));
			assertFalse("but leaves its value alone", X86.changes(insn, reg(program, "AX")));
		});
		with("0a e0", (program, insn) -> { // OR AH,AL
			assertTrue(X86.changes(insn, reg(program, "AX")));
		});
	}

	/** {@code 8E D8} is {@code MOV DS,AX}, whatever operand order Ghidra displays (GP-7018). */
	@Test
	public void testMovOperandsComeFromThePcode() throws Exception {
		with("8e d8", (program, insn) -> {
			assertEquals(reg(program, "DS"), X86.movDestination(insn));
			assertEquals(reg(program, "AX"), X86.movSourceRegister(insn));
		});
		with("b8 34 12", (program, insn) -> { // MOV AX,0x1234
			assertEquals(reg(program, "AX"), X86.movDestination(insn));
			assertNull("an immediate is no source register", X86.movSourceRegister(insn));
		});
	}

	@Test
	public void testPrefixesAndSegmentOverride() throws Exception {
		with("f3 26 a5", (program, insn) -> { // REP MOVSW ES:..
			byte[] bytes = X86.bytes(insn);
			assertEquals(2, X86.opcodeIndex(bytes));
			assertEquals(0x26, X86.segmentOverride(bytes));
		});
		with("90", (program, insn) -> {
			assertEquals(0, X86.opcodeIndex(X86.bytes(insn)));
			assertEquals(0, X86.segmentOverride(X86.bytes(insn)));
		});
		assertEquals(-1, X86.opcodeIndex(new byte[] { 0x26, 0x2e }));
		assertEquals(0x3412, X86.word(new byte[] { 0x12, 0x34 }, 0));
	}

	@Test
	public void testCodeSegmentPrefersTheContextValue() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("X86", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock block = builder.createMemory("CODE", "0x1000:0x0000", 0x10);
			builder.withTransaction(() -> block.setExecute(true));
			builder.setBytes("0x1000:0x0000", "90 90");
			builder.disassemble("0x1000:0x0000", 2, false);
			Program program = builder.getProgram();
			Instruction first = program.getListing().getInstructionAt(builder.addr("0x1000:0x0000"));
			Instruction second = program.getListing().getInstructionAt(builder.addr("0x1000:0x0001"));
			builder.setRegisterValue("CS", "0x1000:0x0001", "0x1000:0x0001", 0x0ff8);

			assertEquals("no context: the address' segment", 0x1000,
				X86.codeSegment(program, first, (SegmentedAddress) first.getMinAddress()));
			assertEquals("an asserted CS wins", 0x0ff8,
				X86.codeSegment(program, second, (SegmentedAddress) second.getMinAddress()));
		}
		finally {
			builder.dispose();
		}
	}
}
