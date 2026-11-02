package ebbex.rtlink;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.math.BigInteger;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * {@link ModuleSegments#assign}: CS, and {@code cseg} where the
 * language has it, over each module of a page is the page's paragraph plus the module's
 * base. {@code cseg} exists only in the dailydriver fork; against stock Ghidra those
 * assertions are skipped.
 */
public class RTLinkCodeSegmentTest extends RealModeTest {

	private RealMode builder;
	private Program program;
	private Register cs;
	private Register cseg;

	@Before
	public void setUp() throws Exception {
		builder = realMode("CS");
		program = builder.getProgram();
		cs = program.getRegister("CS");
		cseg = program.getRegister("cseg");
	}

	@Test
	public void testEachModuleGetsFramePlusBase() throws Exception {
		MemoryBlock page = builder.createMemory("OVERLAY_24", "0x3a00:0x0000", 0x2000);
		int modules = assign(page, List.of(0xe7, 0x40));

		assertEquals("base 0 is added for the page start", 3, modules);
		assertSegment(cs, "0x3a00:0x0000", 0x3a00);
		assertSegment(cs, "0x3a00:0x03ff", 0x3a00);
		assertSegment(cs, "0x3a00:0x0400", 0x3a40);
		assertSegment(cs, "0x3a00:0x0e6f", 0x3a40);
		assertSegment(cs, "0x3a00:0x0e70", 0x3ae7);
		assertSegment(cs, "0x3a00:0x1fff", 0x3ae7);

		assumeTrue("cseg is a dailydriver context field", cseg != null);
		for (String at : List.of("0x3a00:0x0000", "0x3a00:0x0400", "0x3a00:0x0e70")) {
			assertEquals("cseg equals CS at " + at, value(cs, at), value(cseg, at));
		}
	}

	@Test
	public void testBaseBeyondThePageIsIgnored() throws Exception {
		MemoryBlock page = builder.createMemory("OVERLAY_01", "0x3a00:0x0000", 0x100);
		int modules = assign(page, List.of(0x8, 0x10));

		assertEquals("only bases inside the page", 2, modules);
		assertSegment(cs, "0x3a00:0x00ff", 0x3a08);
	}

	/**
	 * A module first named after its code was decoded (the stub scan's extra bases, or a
	 * One Shot) still gets CS; Ghidra refuses the {@code cseg} write there, which must not
	 * abort the pass. On the 12.1.4 c14a82bda8 SDK it did, and the smoke sample's second
	 * module kept the page's CS.
	 */
	@Test
	public void testDecodedCodeStillGetsCs() throws Exception {
		MemoryBlock page = builder.createMemory("OVERLAY_01", "0x1100:0x0000", 0x40);
		builder.setBytes("0x1100:0x0020", "90 cb");
		assign(page, List.of());
		builder.decode("0x1100:0x0020", 2, true);

		int modules = assign(page, List.of(0x2, 0x3));

		assertEquals(3, modules);
		assertSegment(cs, "0x1100:0x0000", 0x1100);
		assertSegment(cs, "0x1100:0x0020", 0x1102);
		assertSegment(cs, "0x1100:0x0030", 0x1103);
		assumeTrue("cseg is a dailydriver context field", cseg != null);
		assertSegment(cseg, "0x1100:0x0030", 0x1103);
	}

	/**
	 * With {@code cseg} set before decoding, a near JMP wraps inside its 64KB segment: at
	 * {@code 1000:fff0}, {@code E9 1D 00} goes to {@code 1000:0010}, not to linear 0x20010.
	 */
	@Test
	public void testNearJumpWrapsInsideTheSegment() throws Exception {
		assumeTrue("cseg is a dailydriver context field", cseg != null);
		MemoryBlock block = builder.createMemory("CODE_0", "0x1000:0x0000", 0x10010);
		builder.setBytes("0x1000:0xfff0", "e9 1d 00");
		assign(block, List.of());

		builder.decode("0x1000:0xfff0", 3, true);

		Address target = program.getListing()
				.getInstructionAt(builder.addr("0x1000:0xfff0"))
				.getFlows()[0];
		assertEquals(0x10010, target.getOffset());
	}

	private int assign(MemoryBlock block, List<Integer> bases) throws Exception {
		return builder.tx(
			() -> ModuleSegments.assign(program.getProgramContext(), cs, cseg, block, bases));
	}

	private void assertSegment(Register register, String at, int expected) {
		assertEquals(register.getName() + " at " + at, BigInteger.valueOf(expected),
			value(register, at));
	}

	private BigInteger value(Register register, String at) {
		return program.getProgramContext().getValue(register, builder.addr(at), false);
	}
}
