package ebbex.rtlink;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.DefaultErrorLogger;
import ghidra.util.ErrorLogger;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link HuskRepair}: a function whose entry holds no instruction is disassembled,
 * its body recomputed and the call targets its code exposes promoted; one that still cannot
 * be disassembled is reported, and at analysis end that report reaches the application log.
 */
public class HuskRepairTest extends RealModeTest {

	/**
	 * <pre>
	 *   0100  e8 0d 00   CALL 0x0110      ; a husk: a function here, no code
	 *   0103  c3         RET
	 *   0110  33 c0      XOR AX,AX        ; reached only through the husk
	 *   0112  c3         RET
	 *   0120  fe f8                       ; FE /7: no instruction at all
	 * </pre>
	 */
	private static final String HUSK = "0x1000:0x0100";
	private static final String CALLEE = "0x1000:0x0110";
	private static final String UNDECODABLE = "0x1000:0x0120";

	private RealMode huskProgram(String... husks) throws Exception {
		RealMode builder = realMode("HUSK");
		builder.code("0x1000:0x0100", 0x40);
		builder.bytes(HUSK, "e8 0d 00 c3");
		builder.bytes(CALLEE, "33 c0 c3");
		builder.bytes(UNDECODABLE, "fe f8");
		Program program = builder.getProgram();
		for (String husk : husks) {
			builder.withTransaction(
				() -> new CreateFunctionCmd(builder.addr(husk)).applyTo(program, TaskMonitor.DUMMY));
			assertNotNull("setup: a function at " + husk, function(builder, husk));
			assertNull("setup: with no code at its entry",
				program.getListing().getInstructionAt(builder.addr(husk)));
		}
		return builder;
	}

	private static Function function(RealMode builder, String at) {
		return builder.getProgram().getFunctionManager().getFunctionAt(builder.addr(at));
	}

	private static MessageLog repair(RealMode builder) throws Exception {
		MessageLog log = new MessageLog();
		builder.tx(() -> {
			HuskRepair.repair(builder.getProgram(), log, TaskMonitor.DUMMY);
			return null;
		});
		return log;
	}

	@Test
	public void testHuskIsDisassembledAndItsCalleePromoted() throws Exception {
		RealMode builder = huskProgram(HUSK);

		MessageLog log = repair(builder);

		assertFalse("nothing to report: " + log, log.hasMessages());
		assertEquals("CALL", builder.getProgram().getListing()
				.getInstructionAt(builder.addr(HUSK)).getMnemonicString());
		assertTrue("the body runs to the RET",
			function(builder, HUSK).getBody().contains(builder.addr("0x1000:0x0103")));
		assertNotNull("the callee the husk exposed becomes a function", function(builder, CALLEE));
	}

	@Test
	public void testUnrepairableHuskIsReported() throws Exception {
		RealMode builder = huskProgram(UNDECODABLE);

		MessageLog log = repair(builder);

		assertTrue(log.toString(), log.toString().contains(
			"husk function at " + builder.addr(UNDECODABLE) + " could not be repaired"));
		assertNull(builder.getProgram().getListing().getInstructionAt(builder.addr(UNDECODABLE)));
	}

	/** {@code analysisEnded} cannot raise the analysis dialog, so it forwards to {@link Msg#warn}. */
	@Test
	public void testUnrepairableHuskIsWarnedAtAnalysisEnd() throws Exception {
		RealMode builder = huskProgram(UNDECODABLE);
		Program program = builder.getProgram();
		builder.withTransaction(() -> RTLinkProgram.markOverlayAnalyzed(program));

		List<String> warnings = new ArrayList<>();
		Msg.setErrorLogger(new CapturingLogger(warnings));
		try {
			builder.withTransaction(() -> new RTLinkOverlayAnalyzer().analysisEnded(program));
		}
		finally {
			Msg.setErrorLogger(new DefaultErrorLogger());
		}

		assertEquals(warnings.toString(), 1, warnings.stream()
				.filter(w -> w.contains("could not be repaired"))
				.count());
	}

	/** Keeps the warnings and drops everything else. */
	private record CapturingLogger(List<String> warnings) implements ErrorLogger {

		@Override
		public void warn(Object originator, Object message) {
			warnings.add(String.valueOf(message));
		}

		@Override
		public void warn(Object originator, Object message, Throwable throwable) {
			warnings.add(String.valueOf(message));
		}

		@Override
		public void trace(Object originator, Object message) {
		}

		@Override
		public void trace(Object originator, Object message, Throwable throwable) {
		}

		@Override
		public void debug(Object originator, Object message) {
		}

		@Override
		public void debug(Object originator, Object message, Throwable throwable) {
		}

		@Override
		public void info(Object originator, Object message) {
		}

		@Override
		public void info(Object originator, Object message, Throwable throwable) {
		}

		@Override
		public void error(Object originator, Object message) {
		}

		@Override
		public void error(Object originator, Object message, Throwable throwable) {
		}
	}
}
