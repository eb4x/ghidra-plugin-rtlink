package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link DispatchStubs#discoverDispatchers}: the dispatcher is the {@code CALLF}
 * target that enough {@code CALLF; JMPF} stub candidates share, keyed by its flat address and
 * mapped to the segment the stubs call it under.
 */
public class DispatchStubsTest extends RealModeTest {

	/** {@code CALLF 1000:0180; JMPF 0000:0341}: a dispatch stub of the jump table. */
	private static final String STUB = "9a 80 01 00 10 ea 41 03 00 00";
	/** The same dispatcher through another segment: {@code CALLF 1008:0100} is flat 10180h. */
	private static final String ALIAS_STUB = "9a 00 01 08 10 ea 41 03 00 00";
	/** A far call followed by something other than a far jump: no stub. */
	private static final String PLAIN_CALL = "9a 80 01 00 10 c3";
	private static final long DISPATCHER = 0x10180;

	private RealMode stubs(String... entries) throws Exception {
		RealMode builder = realMode("STUBS");
		builder.code("0x1000:0x0000", 0x200);
		int at = 0x100;
		for (String entry : entries) {
			builder.bytes(String.format("0x1000:0x%04x", at), entry);
			at += 10;
		}
		return builder;
	}

	private static DispatchStubs.Dispatchers discover(RealMode builder) throws Exception {
		return DispatchStubs.discoverDispatchers(builder.getProgram(), TaskMonitor.DUMMY);
	}

	@Test
	public void testTargetSharedByFourStubsIsTheDispatcher() throws Exception {
		RealMode builder = stubs(STUB, STUB, STUB, STUB);
		assertEquals(Map.of(DISPATCHER, 0x1000), discover(builder).segments());
	}

	@Test
	public void testThreeStubsAreNotEnough() throws Exception {
		RealMode builder = stubs(STUB, STUB, STUB, PLAIN_CALL);
		assertTrue("a far call without its far jump is no stub", discover(builder).isEmpty());
	}

	/** Aliases of one dispatcher count together; it keeps the segment the first stub used. */
	@Test
	public void testAliasesOfOneDispatcherAreCountedTogether() throws Exception {
		RealMode builder = stubs(STUB, ALIAS_STUB, ALIAS_STUB, STUB);
		assertEquals(Map.of(DISPATCHER, 0x1000), discover(builder).segments());
	}

	@Test
	public void testCalledAtIsTrueOnlyOnAFarCallToTheDispatcher() throws Exception {
		RealMode builder = stubs(STUB, STUB, STUB, STUB, PLAIN_CALL);
		var dispatchers = discover(builder);
		var memory = builder.getProgram().getMemory();
		var space = X86.space(builder.getProgram());

		assertTrue(dispatchers.calledAt(memory, space, builder.addr("0x1000:0x0100")));
		assertTrue("a plain call to the dispatcher counts too",
			dispatchers.calledAt(memory, space, builder.addr("0x1000:0x0128")));
		assertFalse("the stub's JMPF is no call",
			dispatchers.calledAt(memory, space, builder.addr("0x1000:0x0105")));
		assertFalse("nor is the byte after the CALLF opcode",
			dispatchers.calledAt(memory, space, builder.addr("0x1000:0x0101")));
	}
}
