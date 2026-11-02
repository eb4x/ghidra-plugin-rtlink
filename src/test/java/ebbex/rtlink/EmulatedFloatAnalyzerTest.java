package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link EmulatedFloatAnalyzer}'s pass over the patcher: which calls it patches
 * and which bookmarks its end-of-analysis sweep removes.
 */
public class EmulatedFloatAnalyzerTest extends RealModeTest {

	/**
	 * {@code CD 35 5E CD} is one emulator call, {@code INT 35h} with modrm {@code 5E} and
	 * displacement {@code CD}, followed by {@code CMP AX,AX; RET}. Decoded by flow before the
	 * rewrite it reads as {@code INT 35h; POP SI; INT 3Bh}: the second "call" is the first's
	 * displacement byte and the next instruction's opcode.
	 */
	private static final String OUT_OF_PHASE = "cd 35 5e cd 3b c0 c3";

	private RealMode program(String code) throws Exception {
		RealMode builder = realMode("FP");
		builder.code("0x1000:0x0000", 0x200);
		builder.setBytes("0x1000:0x0000", code);
		builder.disassemble("0x1000:0x0000", 7, false);
		return builder;
	}

	private static void analyze(RealMode builder, EmulatedFloatAnalyzer analyzer)
			throws Exception {
		Program program = builder.getProgram();
		builder.tx(() -> {
			analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog());
			analyzer.analysisEnded(program);
			return null;
		});
	}

	@Test
	public void testCallDecodedFromAnotherCallsOperandsIsNotPatched() throws Exception {
		RealMode builder = program(OUT_OF_PHASE);
		Program program = builder.getProgram();
		assertNotNull("setup: the out-of-phase INT 3Bh must be decoded",
			program.getListing().getInstructionAt(builder.addr("0x1000:0x0003")));

		analyze(builder, new EmulatedFloatAnalyzer());

		byte[] bytes = new byte[5];
		program.getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
		assertArrayEquals("only the real call is rewritten; its displacement and the CMP " +
			"after it are untouched",
			new byte[] { (byte) 0x9b, (byte) 0xd9, 0x5e, (byte) 0xcd, 0x3b }, bytes);
		assertNotNull("the CMP decodes in phase",
			program.getListing().getInstructionAt(builder.addr("0x1000:0x0004")));

		analyze(builder, new EmulatedFloatAnalyzer());
		program.getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
		assertArrayEquals("a second pass rewrites nothing",
			new byte[] { (byte) 0x9b, (byte) 0xd9, 0x5e, (byte) 0xcd, 0x3b }, bytes);
	}

	/**
	 * The rewrite is re-decoded: {@code 9B D9 5E CD} is {@code FWAIT} and then
	 * {@code FSTP float ptr [BP-0x33]} ({@code D9 /3}, modrm {@code 5E} = {@code [BP+disp8]}),
	 * read from the patched bytes, not left as the INT it replaced.
	 */
	@Test
	public void testRewriteIsReDecodedAsX87() throws Exception {
		RealMode builder = program(OUT_OF_PHASE);
		analyze(builder, new EmulatedFloatAnalyzer());

		Instruction store =
			builder.getProgram().getListing().getInstructionAt(builder.addr("0x1000:0x0001"));
		assertNotNull("the ESC instruction is decoded after the FWAIT", store);
		assertEquals("FSTP", store.getMnemonicString());
		assertEquals("float ptr [BP + -0x33]", store.getDefaultOperandRepresentation(0));
	}

	/**
	 * {@code INT 3Ch} under each segment: bits 7-6 of the byte after it pick the prefix, and
	 * the ESC is that byte with both set again. {@code FLD qword ptr <seg>:[BX]} = {@code DD 07}.
	 */
	@Test
	public void testSegmentOverrideForms() throws Exception {
		int[][] forms = { // byte after INT 3Ch, expected prefix
			{ 0xdd, 0x26 }, { 0x5d, 0x36 }, { 0x9d, 0x2e }, { 0x1d, 0x3e } };
		for (int[] form : forms) {
			RealMode builder = program(String.format("cd 3c %02x 07 c3", form[0]));
			analyze(builder, new EmulatedFloatAnalyzer());
			byte[] bytes = new byte[4];
			builder.getProgram().getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
			assertArrayEquals(String.format("INT 3Ch form %02x", form[0]),
				new byte[] { (byte) 0x9b, (byte) form[1], (byte) 0xdd, 0x07 }, bytes);
		}
	}

	/** A byte after INT 3Ch that is no ESC under any segment leaves the INT alone. */
	@Test
	public void testUnknownSegmentOverrideFormIsLeftAlone() throws Exception {
		RealMode builder = program("cd 3c 00 07 c3");
		analyze(builder, new EmulatedFloatAnalyzer());
		byte[] bytes = new byte[2];
		builder.getProgram().getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
		assertArrayEquals(new byte[] { (byte) 0xcd, 0x3c }, bytes);
	}

	@Test
	public void testSweepKeepsMarksOutsideTheRewrite() throws Exception {
		RealMode builder = program(OUT_OF_PHASE);
		builder.setBytes("0x1000:0x0100", "b8 00 00 c3 b8 00 00 c3");
		builder.disassemble("0x1000:0x0100", 8, false);
		// Stale: the mis-decode's mark, inside what the rewrite re-decodes.
		builder.errorMark("0x1000:0x0004", "conflicting instruction");
		// Elsewhere: a mark inside an instruction the rewrite never touched.
		builder.errorMark("0x1000:0x0101",
			"Failed to disassemble at 1000:0101 due to conflicting instruction at " +
				"1000:0100 (flow from 1000:0101)");
		// Elsewhere too, but caused by the wreckage: its flow came from 1000:0003, the
		// out-of-phase INT 3Bh, which the rewrite turned into a displacement byte.
		builder.errorMark("0x1000:0x0105",
			"Failed to disassemble at 1000:0105 due to conflicting instruction at " +
				"1000:0104 (flow from 1000:0003)");

		analyze(builder, new EmulatedFloatAnalyzer());

		BookmarkManager bookmarks = builder.getProgram().getBookmarkManager();
		assertNull("the rewrite's stale mark is swept",
			bookmarks.getBookmark(builder.addr("0x1000:0x0004"), BookmarkType.ERROR,
				Disassembler.ERROR_BOOKMARK_CATEGORY));
		assertNotNull("a mark outside the rewrite stays",
			bookmarks.getBookmark(builder.addr("0x1000:0x0101"), BookmarkType.ERROR,
				Disassembler.ERROR_BOOKMARK_CATEGORY));
		assertNull("a mark whose cause the rewrite removed is swept",
			bookmarks.getBookmark(builder.addr("0x1000:0x0105"), BookmarkType.ERROR,
				Disassembler.ERROR_BOOKMARK_CATEGORY));
	}
}
