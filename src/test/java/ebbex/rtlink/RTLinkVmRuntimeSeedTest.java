package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link RTLinkOverlayAnalyzer#seedVmRuntimeEntryPoints}: the RTLink entry stub
 * ({@code $$VM_INITW}: {@code CALLF init ; JMPF __astart}) and the VM nucleus's
 * constant-pair dispatch ({@code MOV AX,imm ; MOV DX,imm ; TEST CS:[flag],0xFF ; JE ;
 * MOV AX,imm ; MOV DX,imm ; MOV [SI-4],AX ; JMP DX}) in miniature — plus the refusals:
 * a target outside the dispatcher's block, and a byte shape that is nearly but not
 * exactly the dispatch.
 */
public class RTLinkVmRuntimeSeedTest extends AbstractGenericTest {

	private static final String ENTRY = "0x1000:0x0100";
	// CALLF 1000:0110 ; JMPF 1000:0200 — the $$VM_INITW stub shape, segments relocated.
	private static final String ENTRY_STUB = "9a 10 01 00 10 ea 00 02 00 10";
	private static final String INIT_BODY = "0x1000:0x0110";
	private static final String STARTUP = "0x1000:0x0200";

	private static final String DISPATCH_SITE = "0x1000:0x0100";
	// MOV AX,0x300 ; MOV DX,0x320 ; TEST byte CS:[0x1234],0xFF ; JE +6 ;
	// MOV AX,0x340 ; MOV DX,0x360 ; MOV [SI-4],AX ; JMP DX
	private static final String DISPATCH =
		"b8 00 03 ba 20 03 2e f6 06 34 12 ff 74 06 b8 40 03 ba 60 03 89 44 fc ff e2";
	private static final String VENDOR_A = "0x1000:0x0300"; // AX arm 1 -> function
	private static final String INNER_A = "0x1000:0x0320"; // DX arm 1 -> flow only
	private static final String VENDOR_B = "0x1000:0x0340"; // AX arm 2 -> function
	private static final String INNER_B = "0x1000:0x0360"; // DX arm 2 -> flow only

	// A dispatcher entry inside the block, keyed the way discoverDispatchers keys it:
	// flat physical address -> stub-declared segment.
	private static final long DISPATCHER_PHYSICAL = 0x10090L;
	private static final int DISPATCHER_SEGMENT = 0x1000;

	private ProgramBuilder program(String bytesAddr, String bytes, String[] retTargets,
			boolean withEntryPoint) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("VMSEED", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x400);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes(bytesAddr, bytes);
			for (String target : retTargets) {
				builder.setBytes(target, "c3"); // RET: decodes, so validation passes
			}
			if (withEntryPoint) {
				builder.createLabel(ENTRY, "entry");
				builder.createEntryPoint(ENTRY, "entry");
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

	/** Run the seeding pass inside a transaction and hand back the seeded-function count. */
	private static int seed(ProgramBuilder builder, Map<Long, Integer> dispatchers)
			throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("seed VM runtime entry points");
		try {
			return RTLinkOverlayAnalyzer.seedVmRuntimeEntryPoints(program, dispatchers,
				new MessageLog(), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static boolean hasSymbol(Program program, Address addr, String name) {
		SymbolIterator it = program.getSymbolTable().getSymbolsAsIterator(addr);
		for (Symbol symbol : it) {
			if (name.equals(symbol.getName())) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void testEntryStubSeedsInitBodyAndStartup() throws Exception {
		ProgramBuilder builder =
			program(ENTRY, ENTRY_STUB, new String[] { INIT_BODY, STARTUP }, true);
		try {
			int seeded = seed(builder, Map.of());
			assertEquals("init body and startup must both be seeded", 2, seeded);

			Program program = builder.getProgram();
			assertNotNull("init body must be a function",
				program.getFunctionManager().getFunctionAt(builder.addr(INIT_BODY)));
			assertNotNull("startup must be a function",
				program.getFunctionManager().getFunctionAt(builder.addr(STARTUP)));
			assertTrue("startup must be labeled __astart",
				hasSymbol(program, builder.addr(STARTUP), "__astart"));
			assertTrue("the stub must carry the $$VM_INITW label",
				hasSymbol(program, builder.addr(ENTRY), "$$VM_INITW"));
			assertEquals("the loader's entry symbol must stay primary", "entry",
				program.getSymbolTable().getPrimarySymbol(builder.addr(ENTRY)).getName());
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testEntryWithoutStubShapeIsLeftAlone() throws Exception {
		// A plain JMPF at the entry (no leading CALLF) is not the stub.
		ProgramBuilder builder = program(ENTRY, "ea 00 02 00 10 90 90 90 90 90",
			new String[] { STARTUP }, true);
		try {
			assertEquals(0, seed(builder, Map.of()));
			assertFalse("no __astart may be invented",
				hasSymbol(builder.getProgram(), builder.addr(STARTUP), "__astart"));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testDispatchPairSeedsVendorEntriesAndInnerFlow() throws Exception {
		ProgramBuilder builder = program(DISPATCH_SITE, DISPATCH,
			new String[] { VENDOR_A, INNER_A, VENDOR_B, INNER_B }, false);
		try {
			int seeded =
				seed(builder, Map.of(DISPATCHER_PHYSICAL, DISPATCHER_SEGMENT));
			assertEquals("both AX (vendor) targets must become functions", 2, seeded);

			Program program = builder.getProgram();
			assertNotNull(program.getFunctionManager().getFunctionAt(builder.addr(VENDOR_A)));
			assertNotNull(program.getFunctionManager().getFunctionAt(builder.addr(VENDOR_B)));
			assertNull("inner DX target must not become a function",
				program.getFunctionManager().getFunctionAt(builder.addr(INNER_A)));
			assertNull("inner DX target must not become a function",
				program.getFunctionManager().getFunctionAt(builder.addr(INNER_B)));
			assertNotNull("inner DX target must still be disassembled",
				program.getListing().getInstructionAt(builder.addr(INNER_A)));
			assertNotNull("inner DX target must still be disassembled",
				program.getListing().getInstructionAt(builder.addr(INNER_B)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testDispatchWithoutDispatcherInBlockSeedsNothing() throws Exception {
		ProgramBuilder builder = program(DISPATCH_SITE, DISPATCH,
			new String[] { VENDOR_A, INNER_A, VENDOR_B, INNER_B }, false);
		try {
			assertEquals("no discovered dispatcher, no seeding", 0, seed(builder, Map.of()));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testNearMissShapeIsNotMatched() throws Exception {
		// Same site with the JE distance off by one (74 05): not the dispatch.
		String nearMiss = DISPATCH.replace("74 06", "74 05");
		ProgramBuilder builder = program(DISPATCH_SITE, nearMiss,
			new String[] { VENDOR_A, INNER_A, VENDOR_B, INNER_B }, false);
		try {
			assertEquals(0, seed(builder, Map.of(DISPATCHER_PHYSICAL, DISPATCHER_SEGMENT)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testTargetOutsideDispatcherBlockIsNotSeeded() throws Exception {
		// AX arm 1 immediate 0x0500 lies past the 0x400-byte block: must be skipped while
		// the in-block arm 2 still seeds.
		String outOfBlock = DISPATCH.replace("b8 00 03", "b8 00 05");
		ProgramBuilder builder = program(DISPATCH_SITE, outOfBlock,
			new String[] { INNER_A, VENDOR_B, INNER_B }, false);
		try {
			int seeded =
				seed(builder, Map.of(DISPATCHER_PHYSICAL, DISPATCHER_SEGMENT));
			assertEquals("only the in-block vendor target may seed", 1, seeded);
			assertNotNull(builder.getProgram().getFunctionManager()
					.getFunctionAt(builder.addr(VENDOR_B)));
		}
		finally {
			builder.dispose();
		}
	}
}
