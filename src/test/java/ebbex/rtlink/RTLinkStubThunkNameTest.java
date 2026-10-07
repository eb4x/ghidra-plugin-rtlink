package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Tests that a dispatch stub's thunk shows its target's name, so every call site through
 * the stub decompiles as a call to the overlay function, while the stub's
 * {@code OVLSTUB_NN_OOOO} gate name moves into its plate comment.
 */
public class RTLinkStubThunkNameTest extends AbstractGenericTest {

	private static final String STUB = "0x1000:0x0010";
	private static final String TARGET = "0x1000:0x0080";
	private static final String GATE = "OVLSTUB_00_0080";

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("STUBNAME", ProgramBuilder._X86_16_REAL_MODE);
		MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x100);
		builder.withTransaction(() -> code.setExecute(true));
		builder.setBytes(STUB, "90 90 90 90 90 90 90 90 90 90 90 90");
		builder.setBytes(TARGET, "cb", true); // RETF
		builder.createFunction(TARGET);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	private Address addr(String a) {
		return builder.addr(a);
	}

	private void inTx(ThrowingRunnable r) throws Exception {
		int tx = program.startTransaction("test");
		try {
			r.run();
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}

	private Function thunk() throws Exception {
		MessageLog log = new MessageLog();
		inTx(() -> assertTrue(log.toString(), RTLinkOverlayAnalyzer.createThunkAtStub(
			program.getFunctionManager(), addr(STUB), addr(TARGET), 12, log)));
		Function stub = program.getFunctionManager().getFunctionAt(addr(STUB));
		assertNotNull(stub);
		assertTrue(stub.isThunk());
		return stub;
	}

	/** The gate name lives on in the stub's plate comment, not as a symbol. */
	private void assertGateInPlate() {
		String plate = program.getListing().getComment(CommentType.PLATE, addr(STUB));
		assertEquals("RTLink dispatch stub " + GATE, plate);
		SymbolTable symbols = program.getSymbolTable();
		assertFalse("a symbol at the stub would rename it: " +
			Arrays.toString(symbols.getSymbols(addr(STUB))),
			Arrays.stream(symbols.getSymbols(addr(STUB)))
					.anyMatch(s -> s.getName().equals(GATE)));
	}

	private void nameTarget(String name, SourceType source) throws Exception {
		inTx(() -> program.getFunctionManager().getFunctionAt(addr(TARGET)).setName(name,
			source));
	}

	@Test
	public void testLabelledStubShowsTargetName() throws Exception {
		inTx(() -> program.getSymbolTable().createLabel(addr(STUB), GATE,
			SourceType.ANALYSIS));
		nameTarget("madspack_read", SourceType.USER_DEFINED);

		Function stub = thunk();

		assertEquals(SourceType.DEFAULT, stub.getSymbol().getSource());
		assertEquals("madspack_read", stub.getName());
		assertGateInPlate();
	}

	@Test
	public void testTargetRenameFollowsThroughStub() throws Exception {
		inTx(() -> program.getSymbolTable().createLabel(addr(STUB), GATE,
			SourceType.ANALYSIS));
		Function stub = thunk();

		nameTarget("sprite_series_load", SourceType.USER_DEFINED);

		assertEquals("sprite_series_load", stub.getName());
	}

	@Test
	public void testUserNamedStubIsLeftAlone() throws Exception {
		inTx(() -> {
			Symbol s = program.getSymbolTable().createLabel(addr(STUB), "my_gate",
				SourceType.USER_DEFINED);
			s.setPrimary();
		});
		nameTarget("madspack_read", SourceType.USER_DEFINED);

		Function stub = thunk();

		assertEquals("my_gate", stub.getName());
	}

	@Test
	public void testExistingAnalysisNamedThunkIsRenamedOnRerun() throws Exception {
		// What a program analyzed by rtlink <= 0.4.2 holds: the thunk named after the gate.
		inTx(() -> program.getSymbolTable().createLabel(addr(STUB), GATE,
			SourceType.ANALYSIS));
		Function first = thunk();
		inTx(() -> first.setName(GATE, SourceType.ANALYSIS));
		nameTarget("madspack_read", SourceType.USER_DEFINED);

		Function stub = thunk();

		assertEquals("madspack_read", stub.getName());
		assertGateInPlate();
	}
}
