package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Regression test for {@link RTLinkXrefAnalyzer#addDataXrefs}: the address-of
 * immediate pass ({@code PUSH imm16} / {@code MOV BX/SI/DI,imm16} /
 * {@code ADD AX/BX/CX/DX/SI/DI,imm16} whose value
 * lands in a mapped non-executable block gets a DATA reference) and its guards,
 * plus the pre-existing DS-relative dereference pass.  The memory map mirrors
 * VICEROY.EXE's DGROUP: an executable low block (its CODE_104) whose extent
 * rejects every small coincidental constant, and an uninitialized rw- block
 * (its BSS DATA) holding the globals.
 */
public class RTLinkAddressOfXrefTest extends AbstractGenericTest {

	@Test
	public void testAddressOfImmediateXrefs() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("AOF", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x40);
			// mirrors CODE_104: the executable low-DGROUP region — targets here rejected
			MemoryBlock dgLow = builder.createMemory("CODE_DG", "0x2000:0x0000", 0x100);
			builder.withTransaction(() -> {
				code.setExecute(true);
				dgLow.setExecute(true);
			});
			// mirrors the BSS DATA block: uninitialized rw- — valid target
			builder.createUninitializedMemory("DATA", "0x2000:0x1000", 0x100);
			// mapped rw- block covering the VGA segment and 0x8000 sentinel values,
			// so the value exclusions (not the block guard) are what those cases
			// exercise
			builder.createUninitializedMemory("DATA_HI", "0x2000:0x8000", 0x2010);

			builder.setBytes("0x1000:0x0000",
			// @formatter:off
				"68 10 10 " +    // 0x0000  PUSH 0x1010     -> BSS: DATA ref, opIndex 0
				"be 20 10 " +    // 0x0003  MOV SI,0x1020   -> BSS: DATA ref, opIndex 1
				"68 50 00 " +    // 0x0006  PUSH 0x50       -> executable block: no ref
				"68 00 30 " +    // 0x0009  PUSH 0x3000     -> unmapped: no ref
				"b9 10 10 " +    // 0x000c  MOV CX,0x1010   -> disallowed register: no ref
				"b8 10 10 " +    // 0x000f  MOV AX,0x1010   -> AX excluded (DOS selectors): no ref
				"05 10 10 " +    // 0x0012  ADD AX,0x1010   -> &g[i] idiom, AX allowed: DATA ref
				"81 c1 30 10 " + // 0x0015  ADD CX,0x1030   -> CX allowed for ADD: DATA ref
				"81 c5 10 10 " + // 0x0019  ADD BP,0x1010   -> BP excluded: no ref
				"a1 10 10 " +    // 0x001d  MOV AX,[0x1010] -> deref pass: READ ref
				"68 00 a0 " +    // 0x0020  PUSH 0xA000     -> video segment, mapped target: no ref
				"bf 40 10 " +    // 0x0023  MOV DI,0x1040   -> flows into ES below: no ref
				"8e c7 " +       // 0x0026  MOV ES,DI       -> the segment load
				"68 00 80",      // 0x0028  PUSH 0x8000     -> sentinel constant, mapped target: no ref
			// @formatter:on
				true);
			builder.setRegisterValue("DS", "0x1000:0x0000", "0x1000:0x003f", 0x2000);

			Program program = builder.getProgram();
			ProgramContext context = program.getProgramContext();
			Register ds = context.getRegister("DS");
			Memory memory = program.getMemory();
			ReferenceManager refManager = program.getReferenceManager();
			SegmentedAddressSpace space =
				(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();

			RTLinkXrefAnalyzer.Counts counts = new RTLinkXrefAnalyzer.Counts();
			builder.withTransaction(() -> {
				for (Instruction instr : program.getListing().getInstructions(true)) {
					RTLinkXrefAnalyzer.addDataXrefs(instr, context, ds, memory, refManager,
						space, counts);
				}
			});

			assertEquals("address-of refs", 4, counts.addressOf);
			assertEquals("deref refs", 1, counts.deref);

			Reference[] push = refManager.getReferencesFrom(builder.addr("0x1000:0x0000"));
			assertEquals(1, push.length);
			assertEquals(RefType.DATA, push[0].getReferenceType());
			assertEquals(builder.addr("0x2000:0x1010"), push[0].getToAddress());
			assertEquals(0, push[0].getOperandIndex());

			Reference[] movSi = refManager.getReferencesFrom(builder.addr("0x1000:0x0003"));
			assertEquals(1, movSi.length);
			assertEquals(RefType.DATA, movSi[0].getReferenceType());
			assertEquals(builder.addr("0x2000:0x1020"), movSi[0].getToAddress());
			assertEquals(1, movSi[0].getOperandIndex());

			assertEquals("imm into executable block must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0006")).length);
			assertEquals("imm into unmapped memory must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0009")).length);
			assertEquals("MOV CX,imm must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x000c")).length);
			assertEquals("MOV AX,imm must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x000f")).length);

			Reference[] addAx = refManager.getReferencesFrom(builder.addr("0x1000:0x0012"));
			assertEquals(1, addAx.length);
			assertEquals(RefType.DATA, addAx[0].getReferenceType());
			assertEquals(builder.addr("0x2000:0x1010"), addAx[0].getToAddress());
			assertEquals(1, addAx[0].getOperandIndex());

			Reference[] addCx = refManager.getReferencesFrom(builder.addr("0x1000:0x0015"));
			assertEquals(1, addCx.length);
			assertEquals(RefType.DATA, addCx[0].getReferenceType());
			assertEquals(builder.addr("0x2000:0x1030"), addCx[0].getToAddress());

			assertEquals("ADD BP,imm must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0019")).length);

			Reference[] deref = refManager.getReferencesFrom(builder.addr("0x1000:0x001d"));
			assertEquals(1, deref.length);
			assertTrue("deref pass must still make READ refs",
				deref[0].getReferenceType().isRead());
			assertEquals(builder.addr("0x2000:0x1010"), deref[0].getToAddress());

			assertEquals("PUSH of a video segment value must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0020")).length);
			assertEquals("immediate that flows into ES must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0023")).length);
			assertEquals("PUSH of the 0x8000 sentinel must not ref", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0028")).length);
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testXlatTableImmediates() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("XLT", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x40);
			builder.withTransaction(() -> code.setExecute(true));
			builder.createUninitializedMemory("DATA", "0x2000:0x1000", 0x100);

			builder.setBytes("0x1000:0x0000",
			// @formatter:off
				"bb 20 00 " + // 0x0000  MOV BX,0x20    -> XLAT CS: table: ref to 1000:0020
				"24 07 " +    // 0x0003  AND AL,0x7
				"2e d7 " +    // 0x0005  XLAT CS:BX
				"bb 10 10 " + // 0x0007  MOV BX,0x1010  -> XLAT SS: table: no ref at all
				"36 d7 " +    // 0x000a  XLAT SS:BX
				"bb 10 10 " + // 0x000c  MOV BX,0x1010  -> bare XLAT reads DS: DGROUP ref
				"d7 " +       // 0x000f  XLAT
				"c3",         // 0x0010  RET
			// @formatter:on
				true);
			builder.setRegisterValue("DS", "0x1000:0x0000", "0x1000:0x003f", 0x2000);

			Program program = builder.getProgram();
			ProgramContext context = program.getProgramContext();
			Register ds = context.getRegister("DS");
			Memory memory = program.getMemory();
			ReferenceManager refManager = program.getReferenceManager();
			SegmentedAddressSpace space =
				(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();

			RTLinkXrefAnalyzer.Counts counts = new RTLinkXrefAnalyzer.Counts();
			builder.withTransaction(() -> {
				for (Instruction instr : program.getListing().getInstructions(true)) {
					RTLinkXrefAnalyzer.addDataXrefs(instr, context, ds, memory, refManager,
						space, counts);
				}
			});

			Reference[] csTable = refManager.getReferencesFrom(builder.addr("0x1000:0x0000"));
			assertEquals("imm feeding XLAT CS: must ref the code-segment table", 1,
				csTable.length);
			assertEquals(RefType.DATA, csTable[0].getReferenceType());
			assertEquals(builder.addr("0x1000:0x0020"), csTable[0].getToAddress());

			assertEquals("imm feeding XLAT SS: must not ref anything", 0,
				refManager.getReferencesFrom(builder.addr("0x1000:0x0007")).length);

			Reference[] plain = refManager.getReferencesFrom(builder.addr("0x1000:0x000c"));
			assertEquals("imm feeding a bare XLAT keeps the DGROUP ref", 1, plain.length);
			assertEquals(builder.addr("0x2000:0x1010"), plain[0].getToAddress());
		}
		finally {
			builder.dispose();
		}
	}
}
