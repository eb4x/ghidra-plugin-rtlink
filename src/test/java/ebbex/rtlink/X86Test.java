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

	/** The immediate of every {@code MOV reg,imm} form, and none for a load from memory. */
	@Test
	public void testMovImmediateComesFromTheBytes() throws Exception {
		with("b8 34 12", (_, insn) -> assertEquals(Long.valueOf(0x1234), X86.movImmediate(insn)));
		with("b1 03", (_, insn) -> assertEquals(Long.valueOf(3), X86.movImmediate(insn)));
		with("c7 c3 56 2a", (_, insn) -> assertEquals(Long.valueOf(0x2a56), X86.movImmediate(insn)));
		with("c6 c3 ff", (_, insn) -> assertEquals(Long.valueOf(0xff), X86.movImmediate(insn)));
		with("8b 1e 56 2a", (program, insn) -> { // MOV BX,[0x2a56]
			assertEquals(reg(program, "BX"), X86.movDestination(insn));
			assertNull("an address is no immediate", X86.movImmediate(insn));		});
		with("c7 06 56 2a 34 12", (_, insn) -> { // MOV word ptr [0x2a56],0x1234
			assertNull("a store to memory loads no register", X86.movImmediate(insn));
		});
		with("8b d8", (_, insn) -> assertNull(X86.movImmediate(insn))); // MOV BX,AX
	}

	/** Every encoding of an ALU op with an immediate on a register, and none on memory. */
	@Test
	public void testAluImmediateComesFromTheBytes() throws Exception {
		with("3d 22 00", (program, insn) -> assertEquals( // CMP AX,0x22
			new X86.RegisterImmediate(reg(program, "AX"), 0x22), X86.aluImmediate(program, insn, X86.CMP)));
		with("3c 58", (program, insn) -> assertEquals( // CMP AL,0x58
			new X86.RegisterImmediate(reg(program, "AL"), 0x58), X86.aluImmediate(program, insn, X86.CMP)));
		with("81 fb 10 01", (program, insn) -> assertEquals( // CMP BX,0x110
			new X86.RegisterImmediate(reg(program, "BX"), 0x110), X86.aluImmediate(program, insn, X86.CMP)));
		with("83 f9 09", (program, insn) -> assertEquals( // CMP CX,9
			new X86.RegisterImmediate(reg(program, "CX"), 9), X86.aluImmediate(program, insn, X86.CMP)));
		with("83 f9 ff", (program, insn) -> assertEquals("83 sign-extends", // CMP CX,-1
			new X86.RegisterImmediate(reg(program, "CX"), 0xffff), X86.aluImmediate(program, insn, X86.CMP)));
		with("80 e4 0f", (program, insn) -> assertEquals( // AND AH,0xf
			new X86.RegisterImmediate(reg(program, "AH"), 0xf), X86.aluImmediate(program, insn, X86.AND)));
		with("3d 22 00", (program, insn) -> assertNull("not an AND", X86.aluImmediate(program, insn, X86.AND)));
		with("83 3e 56 2a 09", (program, insn) -> assertNull("CMP word ptr [0x2a56],9: memory", //
			X86.aluImmediate(program, insn, X86.CMP)));
	}

	/** The direction bit decides which register is the destination. */
	@Test
	public void testRegisterPairFollowsTheDirectionBit() throws Exception {
		with("8b d8", (program, insn) -> assertEquals( // MOV BX,AX (8B: reg <- rm)
			new X86.RegisterPair(reg(program, "BX"), reg(program, "AX")), X86.registerPair(program, insn, X86.MOV)));
		with("89 c3", (program, insn) -> assertEquals( // MOV BX,AX (89: rm <- reg)
			new X86.RegisterPair(reg(program, "BX"), reg(program, "AX")), X86.registerPair(program, insn, X86.MOV)));
		with("03 c0", (program, insn) -> assertEquals( // ADD AX,AX
			new X86.RegisterPair(reg(program, "AX"), reg(program, "AX")), X86.registerPair(program, insn, X86.ADD * 8)));
		with("02 46 fe", (program, insn) -> assertNull("ADD AL,[BP-2]: memory", //
			X86.registerPair(program, insn, X86.ADD * 8)));
	}

	@Test
	public void testShiftsExchangesAndDivides() throws Exception {
		with("d1 e0", (program, insn) -> assertEquals( // SHL AX,1
			new X86.Shift(X86.SHL, reg(program, "AX"), 1, false), X86.shift(program, insn)));
		with("c1 e0 01", (program, insn) -> assertEquals( // SHL AX,1 (186 form)
			new X86.Shift(X86.SHL, reg(program, "AX"), 1, false), X86.shift(program, insn)));
		with("d2 e8", (program, insn) -> assertEquals( // SHR AL,CL
			new X86.Shift(X86.SHR, reg(program, "AL"), 0, true), X86.shift(program, insn)));
		with("93", (program, insn) -> assertEquals( // XCHG AX,BX
			new X86.RegisterPair(reg(program, "AX"), reg(program, "BX")), X86.exchange(program, insn)));
		with("87 d9", (program, insn) -> { // XCHG CX,BX
			X86.RegisterPair pair = X86.exchange(program, insn);
			assertEquals(java.util.Set.of(reg(program, "CX"), reg(program, "BX")),
				java.util.Set.of(pair.destination(), pair.source()));
		});
		with("90", (program, insn) -> assertNull("NOP is no exchange", X86.exchange(program, insn)));
		with("f6 f3", (program, insn) -> assertEquals(reg(program, "BL"), X86.byteDivisor(program, insn)));
		with("fe c1", (program, insn) -> assertEquals(reg(program, "CL"), X86.incremented(program, insn)));
		with("41", (program, insn) -> assertEquals(reg(program, "CX"), X86.incremented(program, insn)));
	}

	@Test
	public void testJumpsByEncoding() throws Exception {
		with("ff e2", (program, insn) -> { // JMP DX
			assertEquals(reg(program, "DX"), X86.jumpRegister(program, insn));
			assertTrue(X86.isUnconditionalJump(insn));
			assertFalse(X86.isFarJump(insn));
		});
		with("2e ff 2e 56 06", (program, insn) -> { // JMPF CS:[0x656]
			assertNull(X86.jumpRegister(program, insn));
			assertTrue(X86.isFarJump(insn));
			assertTrue(X86.isUnconditionalJump(insn));
		});
		with("ea 60 06 5d 27", (_, insn) -> assertTrue(X86.isFarJump(insn))); // JMPF 275d:0660
		with("eb fe", (_, insn) -> assertTrue(X86.isUnconditionalJump(insn)));
		with("74 fe", (_, insn) -> assertFalse("JZ is conditional", X86.isUnconditionalJump(insn)));
		with("ff d2", (program, insn) -> { // CALL DX
			assertNull(X86.jumpRegister(program, insn));
			assertFalse(X86.isUnconditionalJump(insn));
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
