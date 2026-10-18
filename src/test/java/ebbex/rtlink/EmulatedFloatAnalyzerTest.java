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
