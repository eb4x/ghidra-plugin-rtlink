package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Tests that a dispatch stub's thunk shows its target's name, so every call site through
 * the stub decompiles as a call to the overlay function, while the stub's
 * {@code OVLSTUB_NN_OOOO} gate name moves into its plate comment.
 */
public class RTLinkStubThunkNameTest extends RealModeTest {

	private static final String STUB = "0x1000:0x0010";
	private static final String TARGET = "0x1000:0x0080";
	private static final String GATE = "OVLSTUB_00_0080";

	private RealMode builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = realMode("STUBNAME");
		builder.code("0x1000:0x0000", 0x100);
		builder.setBytes(STUB, "90 90 90 90 90 90 90 90 90 90 90 90");
		builder.setBytes(TARGET, "cb", true); // RETF
		builder.createFunction(TARGET);
		program = builder.getProgram();
	}

	private Address addr(String a) {
		return builder.addr(a);
	}

	private Function thunk() throws Exception {
		MessageLog log = new MessageLog();
		assertTrue(log.toString(), builder.tx(() -> StubThunks.create(
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
		builder.tx(() -> {
			program.getFunctionManager().getFunctionAt(addr(TARGET)).setName(name, source);
			return null;
		});
	}

	private void labelStub(String name, SourceType source) throws Exception {
		builder.tx(() -> program.getSymbolTable().createLabel(addr(STUB), name, source));
	}

	@Test
	public void testLabelledStubShowsTargetName() throws Exception {
		labelStub(GATE, SourceType.ANALYSIS);
		nameTarget("madspack_read", SourceType.USER_DEFINED);

		Function stub = thunk();

		assertEquals(SourceType.DEFAULT, stub.getSymbol().getSource());
		assertEquals("madspack_read", stub.getName());
		assertGateInPlate();
	}

	@Test
	public void testTargetRenameFollowsThroughStub() throws Exception {
		labelStub(GATE, SourceType.ANALYSIS);
		Function stub = thunk();

		nameTarget("sprite_series_load", SourceType.USER_DEFINED);

		assertEquals("sprite_series_load", stub.getName());
	}

	@Test
	public void testUserNamedStubIsLeftAlone() throws Exception {
		builder.tx(() -> {
			Symbol s = program.getSymbolTable().createLabel(addr(STUB), "my_gate",
				SourceType.USER_DEFINED);
			s.setPrimary();
			return null;
		});
		nameTarget("madspack_read", SourceType.USER_DEFINED);

		Function stub = thunk();

		assertEquals("my_gate", stub.getName());
	}

	@Test
	public void testExistingAnalysisNamedThunkIsRenamedOnRerun() throws Exception {
		// What a program analyzed by rtlink <= 0.4.2 holds: the thunk named after the gate.
		labelStub(GATE, SourceType.ANALYSIS);
		Function first = thunk();
		builder.tx(() -> {
			first.setName(GATE, SourceType.ANALYSIS);
			return null;
		});
		nameTarget("madspack_read", SourceType.USER_DEFINED);

		Function stub = thunk();

		assertEquals("madspack_read", stub.getName());
		assertGateInPlate();
	}
}
