package ebbex.rtlink;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;

/**
 * Regression test for {@link RTLinkOverlayAnalyzer#applyOverlayRelocations}: a page's two
 * relocation lists take <b>two different deltas</b>.
 * <ul>
 * <li>List 1: the site holds a segment in the resident image, so it takes the MZ image
 *     load delta (0x1000, {@code MzLoader}'s {@code INITIAL_SEGMENT_VAL}).</li>
 * <li>List 2: the site holds a page-relative paragraph, so it takes the page's frame —
 *     statically, the overlay block's own base paragraph.</li>
 * </ul>
 * On every binary in the corpus both deltas happen to be 0x1000, because the first overlay
 * block is placed straight after the image base — precisely the kind of coincidence that
 * has already produced three bugs in the RTLink code. This test therefore places the block
 * at segment <b>0x2000</b>, where the two deltas differ: an implementation that swaps them,
 * or applies one delta to both lists, fails both site assertions.
 * <p>
 * The page bytes are transcribed from the single overlay page of a purpose-built
 * executable, so the test is hermetic and no binary lives in the repository. The program —
 * a resident main plus two modules in one VM page, where {@code funcA} far-calls
 * {@code funcB} — was compiled with Microsoft C 6.00 ({@code -AL -Gs}) and linked with
 * RTLink/Plus 6.10 using {@code LOCSYM}/{@code LOCALON}, which makes the linker emit the
 * intra-page far call as a direct reference carrying a list-2 relocation instead of the
 * usual {@code _@@@_RTLVMFAR_VECTOR} thunk. That is the only known way to obtain a list-2
 * entry on demand; the shipped games that carry them (NEBULAR, ROE2MAIN, SPHERE) cannot be
 * checked into the repo.
 */
public class RTLinkOverlayRelocationTest extends AbstractGenericTest {

	/**
	 * The on-disk bytes of the test program's overlay page. The header declares 7 total
	 * paragraphs but the file ends 11 bytes short — the usual truncated final page, which
	 * is fine here: everything through the last relocation site is present.
	 */
	private static final byte[] PAGE = bytes(
	// header: total=7 paras, overhead=3 paras, frame=0x262, start_index=0,
	// reloc counts 1/1/0, codeview=0
		"07 00 03 00 62 02 00 00 01 00 01 00 00 00 00 00 " +
	// list 1: one entry, offset=0x0013 seg_index=0x0002 -> site at code+0x33.
	// The list-2 entry does NOT follow it directly: the entry index is rounded up to a
	// multiple of 4 between the lists, hence the padding.
		"13 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
	// list 2 (at the rounded entry index 4): one entry, offset=0x0003 seg_index=0x0000
	// -> site at code+0x03
		"03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
	// code+0x00: funcA begins with CALLF 0000:000a to funcB; the call's segment word at
	// code+0x03 is the list-2 site, holding funcB's paragraph within the page (0)
		"9a 0a 00 00 00 05 e8 03 cb 90 8e 06 c0 03 26 a1 " +
		"02 00 cb 90 00 00 00 00 00 00 00 00 00 00 00 00 " +
		"0b 00 16 00 21 00 2c 00 37 00 42 00 4d 00 58 00 " +
	// code+0x30: JMPF 07d6:000a back into the resident image; its segment word at
	// code+0x33 is the list-1 site, holding the unrelocated resident segment 0x07d6
		"ea 0a 00 d6 07");

	private static byte[] bytes(String hex) {
		String[] parts = hex.trim().split("\\s+");
		byte[] result = new byte[parts.length];
		for (int i = 0; i < parts.length; i++) {
			result[i] = (byte) Integer.parseInt(parts[i], 16);
		}
		return result;
	}

	private static RTLinkOverlayPage parsePage() throws IOException {
		return new RTLinkOverlayPage(new BinaryReader(new ByteArrayProvider(PAGE), true), 0, 1);
	}

	/** The page parses into one entry per list, with list 2 at the rounded entry index. */
	@Test
	public void testPageParsesWithBothLists() throws IOException {
		RTLinkOverlayPage page = parsePage();

		assertTrue(page.getHeader().isValid());
		assertEquals(1, page.getRelocations().size());
		assertEquals(1, page.getSecondRelocations().size());
		assertEquals(0, page.getThirdRelocations().size());

		// entry index 1 rounds up to 4, so list 2 sits at byte 16 + 4*4 = 0x20 — this is
		// the rounding rule on a real page, not a synthetic header
		assertEquals(0x20, page.getHeader().getSecondRelocOffset());

		assertEquals(0x33, page.getRelocations().get(0).getSiteOffset());
		assertEquals(0x03, page.getSecondRelocations().get(0).getSiteOffset());
	}

	/**
	 * The assertion that matters: list 1 gets the image-base delta, list 2 the block's own
	 * base paragraph. The block is placed at 0x2000 so the two deltas differ; swapping them
	 * yields 0x27d6/0x1000 instead of 0x17d6/0x2000 and both checks fail.
	 */
	@Test
	public void testListOneTakesImageDeltaAndListTwoTakesFrameDelta() throws Exception {
		RTLinkOverlayPage page = parsePage();
		byte[] code = Arrays.copyOfRange(PAGE, page.getHeader().getOverheadSizeBytes(),
			PAGE.length);

		ProgramBuilder builder = new ProgramBuilder("L2TEST", ProgramBuilder._X86_16_REAL_MODE);
		try {
			// In production this is an overlay block; the delta derivation only uses the
			// block start's linear offset, which a plain block at 2000:0000 shares.
			MemoryBlock block = builder.createMemory("OVERLAY_00", "0x2000:0x0000", code.length);
			builder.setBytes("0x2000:0x0000", code);
			Program program = builder.getProgram();

			MessageLog log = new MessageLog();
			builder.withTransaction(() -> RTLinkOverlayAnalyzer.applyOverlayRelocations(program,
				block, page, log));
			assertFalse(log.toString(), log.hasMessages());

			Memory memory = program.getMemory();
			assertEquals("list-1 site must take the image load delta (0x07d6 + 0x1000)",
				0x17d6, Short.toUnsignedInt(memory.getShort(builder.addr("0x2000:0x0033"))));
			assertEquals("list-2 site must take the block's base paragraph (0x0000 + 0x2000)",
				0x2000, Short.toUnsignedInt(memory.getShort(builder.addr("0x2000:0x0003"))));

			// the instructions around the sites are untouched
			assertEquals(0x9a, Byte.toUnsignedInt(memory.getByte(builder.addr("0x2000:0x0000"))));
			assertEquals(0xea, Byte.toUnsignedInt(memory.getByte(builder.addr("0x2000:0x0030"))));

			List<Relocation> recorded = new ArrayList<>();
			program.getRelocationTable().getRelocations().forEachRemaining(recorded::add);
			assertEquals(2, recorded.size());
			for (Relocation reloc : recorded) {
				assertEquals(Status.APPLIED, reloc.getStatus());
			}
			assertEquals(builder.addr("0x2000:0x0003"), recorded.get(0).getAddress());
			assertEquals(builder.addr("0x2000:0x0033"), recorded.get(1).getAddress());
		}
		finally {
			builder.dispose();
		}
	}
}
