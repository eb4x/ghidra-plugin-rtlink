package ebbex.rtlink;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link EmulatedFloatAnalyzer}'s pass over the patcher: which calls it patches
 * and which bookmarks its end-of-analysis sweep removes.
 */
public class EmulatedFloatAnalyzerTest extends AbstractGenericTest {

	/**
	 * {@code CD 35 5E CD} is one emulator call, {@code INT 35h} with modrm {@code 5E} and
	 * displacement {@code CD}, followed by {@code CMP AX,AX; RET}. Decoded by flow before the
	 * rewrite it reads as {@code INT 35h; POP SI; INT 3Bh}: the second "call" is the first's
	 * displacement byte and the next instruction's opcode.
	 */
	private static final String OUT_OF_PHASE = "cd 35 5e cd 3b c0 c3";

	private ProgramBuilder program(String code) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("FP", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock block = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> block.setExecute(true));
			builder.setBytes("0x1000:0x0000", code);
			builder.disassemble("0x1000:0x0000", 7, false);
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	private static void analyze(Program program, EmulatedFloatAnalyzer analyzer)
			throws Exception {
		int txId = program.startTransaction("emulated float");
		try {
			analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog());
			analyzer.analysisEnded(program);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testCallDecodedFromAnotherCallsOperandsIsNotPatched() throws Exception {
		ProgramBuilder builder = program(OUT_OF_PHASE);
		try {
			Program program = builder.getProgram();
			assertNotNull("setup: the out-of-phase INT 3Bh must be decoded",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0003")));

			analyze(program, new EmulatedFloatAnalyzer());

			byte[] bytes = new byte[5];
			program.getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
			assertArrayEquals("only the real call is rewritten; its displacement and the CMP " +
				"after it are untouched",
				new byte[] { (byte) 0x9b, (byte) 0xd9, 0x5e, (byte) 0xcd, 0x3b }, bytes);
			assertNotNull("the CMP decodes in phase",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x0004")));

			analyze(program, new EmulatedFloatAnalyzer());
			program.getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
			assertArrayEquals("a second pass rewrites nothing",
				new byte[] { (byte) 0x9b, (byte) 0xd9, 0x5e, (byte) 0xcd, 0x3b }, bytes);
		}
		finally {
			builder.dispose();
		}
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
			ProgramBuilder builder = program(String.format("cd 3c %02x 07 c3", form[0]));
			try {
				Program program = builder.getProgram();
				analyze(program, new EmulatedFloatAnalyzer());
				byte[] bytes = new byte[4];
				program.getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
				assertArrayEquals(String.format("INT 3Ch form %02x", form[0]),
					new byte[] { (byte) 0x9b, (byte) form[1], (byte) 0xdd, 0x07 }, bytes);
			}
			finally {
				builder.dispose();
			}
		}
	}

	/** A byte after INT 3Ch that is no ESC under any segment leaves the INT alone. */
	@Test
	public void testUnknownSegmentOverrideFormIsLeftAlone() throws Exception {
		ProgramBuilder builder = program("cd 3c 00 07 c3");
		try {
			Program program = builder.getProgram();
			analyze(program, new EmulatedFloatAnalyzer());
			byte[] bytes = new byte[2];
			program.getMemory().getBytes(builder.addr("0x1000:0x0000"), bytes);
			assertArrayEquals(new byte[] { (byte) 0xcd, 0x3c }, bytes);
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testSweepKeepsMarksOutsideTheRewrite() throws Exception {
		ProgramBuilder builder = program(OUT_OF_PHASE);
		try {
			Program program = builder.getProgram();
			builder.setBytes("0x1000:0x0100", "b8 00 00 c3");
			builder.disassemble("0x1000:0x0100", 4, false);
			BookmarkManager bookmarks = program.getBookmarkManager();
			builder.withTransaction(() -> {
				// Stale: the mis-decode's mark, inside what the rewrite re-decodes.
				bookmarks.setBookmark(builder.addr("0x1000:0x0004"), BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY, "conflicting instruction");
				// Elsewhere: a mark inside an instruction the rewrite never touched.
				bookmarks.setBookmark(builder.addr("0x1000:0x0101"), BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY, "conflicting instruction");
			});

			analyze(program, new EmulatedFloatAnalyzer());

			assertNull("the rewrite's stale mark is swept",
				bookmarks.getBookmark(builder.addr("0x1000:0x0004"), BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY));
			assertNotNull("a mark outside the rewrite stays",
				bookmarks.getBookmark(builder.addr("0x1000:0x0101"), BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}
}
