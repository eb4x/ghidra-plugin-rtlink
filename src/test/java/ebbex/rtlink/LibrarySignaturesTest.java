package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ebbex.rtlink.OmfTestLibrary.ModuleSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link OmfLibrary} and {@link LibrarySignatures}, on libraries
 * {@link OmfTestLibrary} writes: a module matched whole, a module matched public by public
 * past a byte the program inserts, a short body placed beside its neighbour, a body that
 * matches twice (refused), a fixed-up word that differs, and names a user gave (kept).
 */
public class LibrarySignaturesTest extends RealModeTest {

	/**
	 * Module A, matched whole: alpha (a fixed-up word at 4), beta = gamma (aliases), delta.
	 * <pre>
	 *   00  55 8b ec a1 34 12 5d cb   alpha: PUSH BP; MOV BP,SP; MOV AX,[1234]; POP BP; RETF
	 *   08  b8 ff ff cb               beta, gamma: MOV AX,-1; RETF
	 *   0c  33 c0 cb                  delta: XOR AX,AX; RETF
	 * </pre>
	 */
	private static ModuleSpec moduleA() {
		return new ModuleSpec("moda", "55 8b ec a1 34 12 5d cb b8 ff ff cb 33 c0 cb")
				.pub("alpha", 0).pub("beta", 8).pub("gamma", 8).pub("delta", 0x0c)
				.fixup(4);
	}

	/**
	 * Module B, matched public by public: the program has two NOPs after f1, so the segment
	 * no longer matches whole; f3 is four bytes, placed only beside f2.
	 */
	private static ModuleSpec moduleB() {
		return new ModuleSpec("modb",
			"55 8b ec 83 ec 04 8b 46 06 03 46 08 8b e5 5d cb " + // 00 f1
				"50 53 51 52 b8 01 00 5a 59 5b 58 cb " + //            10 f2
				"b9 ff ff cb " + //                                    1c f3
				"56 57 1e 06 8b f0 07 1f 5f 5e cb") //                 20 f4
						.pub("f1", 0).pub("f2", 0x10).pub("f3", 0x1c).pub("f4", 0x20);
	}

	private RealMode program(String at, String hex) throws Exception {
		RealMode builder = realMode("LIB");
		builder.code("0x1000:0x0000", 0x400);
		builder.setBytes(at, hex);
		return builder;
	}

	private static LibrarySignatures.Result apply(RealMode builder, ModuleSpec... modules)
			throws Exception {
		List<OmfLibrary.Module> parsed = OmfLibrary.parse(OmfTestLibrary.library(modules));
		return builder.tx(
			() -> LibrarySignatures.apply(builder.getProgram(), parsed, TaskMonitor.DUMMY));
	}

	private static boolean named(RealMode builder, String at, String name) {
		for (Symbol symbol : builder.getProgram().getSymbolTable().getSymbols(builder.addr(at))) {
			if (symbol.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	private static Function function(RealMode builder, String at) {
		return builder.getProgram().getFunctionManager().getFunctionAt(builder.addr(at));
	}

	@Test
	public void testLibraryParses() throws Exception {
		List<OmfLibrary.Module> modules =
			OmfLibrary.parse(OmfTestLibrary.library(moduleA(), moduleB()));

		assertEquals(2, modules.size());
		OmfLibrary.Module a = modules.get(0);
		assertEquals("moda", a.name());
		assertEquals(4, a.publics().size());
		OmfLibrary.Segment segment = a.segment(1);
		assertEquals("TEST_TEXT", segment.name());
		assertEquals("CODE", segment.className());
		assertEquals(15, segment.data().length);
		assertFalse(segment.masked(3));
		assertTrue("the fixed-up word is masked", segment.masked(4));
		assertTrue(segment.masked(5));
		assertFalse(segment.masked(6));
	}

	@Test
	public void testModuleMatchedWhole() throws Exception {
		// The fixed-up word reads 5678 here, not 1234.
		RealMode builder = program("0x1000:0x0140",
			"55 8b ec a1 78 56 5d cb b8 ff ff cb 33 c0 cb");
		LibrarySignatures.Result result = apply(builder, moduleA());

		assertEquals(3, result.placed());
		assertEquals(3, result.functions());
		assertEquals("alpha", function(builder, "0x1000:0x0140").getName());
		assertEquals("beta", function(builder, "0x1000:0x0148").getName());
		assertTrue("the alias is a label beside it", named(builder, "0x1000:0x0148", "gamma"));
		assertEquals("delta", function(builder, "0x1000:0x014c").getName());
		assertEquals(SourceType.IMPORTED,
			function(builder, "0x1000:0x0140").getSymbol().getSource());
	}

	@Test
	public void testModuleMatchedPublicByPublic() throws Exception {
		RealMode builder = program("0x1000:0x0200",
			"55 8b ec 83 ec 04 8b 46 06 03 46 08 8b e5 5d cb 90 90 " +
				"50 53 51 52 b8 01 00 5a 59 5b 58 cb b9 ff ff cb " +
				"56 57 1e 06 8b f0 07 1f 5f 5e cb");
		apply(builder, moduleB());

		assertEquals("f1", function(builder, "0x1000:0x0200").getName());
		assertEquals("f2", function(builder, "0x1000:0x0212").getName());
		assertEquals("the short body, beside f2", "f3",
			function(builder, "0x1000:0x021e").getName());
		assertEquals("f4", function(builder, "0x1000:0x0222").getName());
	}

	@Test
	public void testBodyMatchingTwiceIsRefused() throws Exception {
		ModuleSpec twice =
			new ModuleSpec("modc", "50 53 51 52 b8 02 00 5a 59 5b 58 cb").pub("twice", 0);
		RealMode builder = program("0x1000:0x0100",
			"50 53 51 52 b8 02 00 5a 59 5b 58 cb 90 90 90 90 50 53 51 52 b8 02 00 5a 59 5b 58 cb");
		LibrarySignatures.Result result = apply(builder, twice);

		assertEquals(0, result.placed());
		assertNull(function(builder, "0x1000:0x0100"));
		assertNull(function(builder, "0x1000:0x0110"));
	}

	@Test
	public void testUserNameIsKept() throws Exception {
		RealMode builder = program("0x1000:0x0140",
			"55 8b ec a1 78 56 5d cb b8 ff ff cb 33 c0 cb");
		builder.disassemble("0x1000:0x0140", 8, true);
		builder.createFunction("0x1000:0x0140");
		Address entry = builder.addr("0x1000:0x0140");
		builder.tx(() -> {
			builder.getProgram()
					.getFunctionManager()
					.getFunctionAt(entry)
					.setName("my_alpha", SourceType.USER_DEFINED);
			return null;
		});

		apply(builder, moduleA());

		assertEquals("the user's name stays the function's", "my_alpha",
			function(builder, "0x1000:0x0140").getName());
		assertTrue("the vendor name goes beside it", named(builder, "0x1000:0x0140", "alpha"));
	}

	@Test
	public void testNothingMatchesNothingChanges() throws Exception {
		RealMode builder = program("0x1000:0x0100", "90 90 90 90 c3");
		assertEquals(0, apply(builder, moduleA(), moduleB()).placed());
	}
}
