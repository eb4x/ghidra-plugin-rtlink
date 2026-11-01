package ebbex.rtlink;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

/**
 * Regression tests for {@link RTLinkPageHeader}, built from real page headers taken out of
 * RTLink/Plus executables.
 * <p>
 * Every field of this header is a word, and three separate bugs came from declaring one of
 * them wider than it is, or assuming it was always zero, because it <i>is</i> always zero in
 * VICEROY.EXE — the single binary the analyzer was first written against. Each case below is
 * a header that the buggy version got wrong, so the tests fail if the struct ever regresses
 * to a 32-bit field or to validating a word as reserved.
 * <p>
 * The bytes are transcribed from the binaries rather than loaded from them, so the tests are
 * hermetic and no third-party executable has to live in the repository.
 */
public class RTLinkPageHeaderTest {

	private static RTLinkPageHeader parse(int... words) throws IOException {
		byte[] bytes = new byte[words.length * 2];
		for (int i = 0; i < words.length; i++) {
			bytes[i * 2] = (byte) (words[i] & 0xFF);
			bytes[i * 2 + 1] = (byte) ((words[i] >> 8) & 0xFF);
		}
		return RTLinkPageHeader.read(new BinaryReader(new ByteArrayProvider(bytes), true));
	}

	/** VICEROY.EXE page 0: the easy case, and the only one the original code got right. */
	@Test
	public void testViceroyPage0() throws IOException {
		RTLinkPageHeader h = parse(0x07f1, 0x00d1, 0x02bc, 0x0000, 0x033a, 0, 0, 0);

		assertTrue(h.isValid());
		assertEquals(2033, h.totalParagraphs());
		assertEquals(209, h.overheadParagraphs());
		assertEquals(700, h.frameSize());
		assertEquals(826, h.relocCount());
		assertEquals(0, h.secondRelocCount());
		assertEquals(29184, h.codeSizeBytes());
	}

	/**
	 * NEBULAR.EXE page 1. reloc_count is 94 and the very next word — reloc_count_2 — is 2.
	 * Read as one dword that is 131166, which fails validation and stopped the page walk
	 * dead: the binary used to import with no overlay blocks at all.
	 */
	@Test
	public void testSecondRelocListIsNotTheHighHalfOfTheCount() throws IOException {
		RTLinkPageHeader h = parse(0x024a, 0x001b, 0x01fe, 0x0000, 0x005e, 0x0002, 0, 0);

		assertTrue("a page with a second reloc list must validate", h.isValid());
		assertEquals(94, h.relocCount());
		assertEquals(2, h.secondRelocCount());
		assertEquals(510, h.frameSize());
	}

	/**
	 * VMEX2.EXE, Pocket Soft's own example: identical to VMEX1.EXE but for one extra linker
	 * directive, CODEVIEW, which stamps 0x091C into the last word of every page header. That
	 * word was declared "reserved" and validated as zero, which rejected the whole program.
	 */
	@Test
	public void testCodeviewWordIsNotReserved() throws IOException {
		RTLinkPageHeader h = parse(0x0025, 0x000b, 0x0262, 0x0000, 0x0022, 0, 0, 0x091c);

		assertTrue("a CODEVIEW-linked page must validate", h.isValid());
		assertEquals(0x091c, h.codeviewWord());
		assertEquals(34, h.relocCount());

		// The same page without CODEVIEW (VMEX1.EXE) is otherwise identical.
		RTLinkPageHeader plain = parse(0x0025, 0x000b, 0x0262, 0x0000, 0x0022, 0, 0, 0);
		assertTrue(plain.isValid());
		assertEquals(0, plain.codeviewWord());
		assertEquals(h.relocCount(), plain.relocCount());
		assertEquals(h.totalParagraphs(), plain.totalParagraphs());
	}

	/**
	 * Relocation lists are addressed by entry index, and the runtime rounds the index up to a
	 * multiple of 4 between list 1 and list 2 — which is why list 2 lands on a paragraph
	 * boundary. List 3 follows list 2 with no rounding.
	 */
	@Test
	public void testRelocListOffsets() throws IOException {
		// reloc_count 94 -> list 2 starts at entry index 96 (94 rounded up to a multiple
		// of 4), i.e. byte offset 16 + 96*4 = 400, a paragraph boundary.
		RTLinkPageHeader h = parse(0x024a, 0x001b, 0x01fe, 0x0000, 94, 2, 0, 0);

		assertEquals(16, h.relocOffset());
		assertEquals(400, h.secondRelocOffset());
		assertEquals(0, h.secondRelocOffset() % 16);
		assertEquals(408, h.thirdRelocOffset());   // straight after list 2, no rounding
	}

	/** A nonzero reloc_start_index shifts the first list, and everything after it. */
	@Test
	public void testRelocStartIndexIsHonoured() throws IOException {
		RTLinkPageHeader h = parse(0x024a, 0x001b, 0x01fe, 4, 8, 0, 0, 0);

		assertEquals(4, h.relocStartIndex());
		assertEquals(16 + 4 * 4, h.relocOffset());
		// list 2 begins at entry index round_up_4(4 + 8) = 12
		assertEquals(16 + 12 * 4, h.secondRelocOffset());
	}

	/**
	 * The chain walk stops at a record whose frame size differs from the first page's: a
	 * valid-looking header with another frame is not part of this overlay area.
	 */
	@Test
	public void testChainStopsAtAForeignFrameSize() throws IOException {
		// Three one-paragraph-overhead records of two paragraphs each; the third has another
		// frame size.
		int[] words = {
			2, 1, 0x02bc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			2, 1, 0x02bc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			2, 1, 0x01fe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		byte[] bytes = new byte[words.length * 2];
		for (int i = 0; i < words.length; i++) {
			bytes[i * 2] = (byte) words[i];
			bytes[i * 2 + 1] = (byte) (words[i] >> 8);
		}
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		assertEquals(2, RTLinkOverlayPage.parseAllPages(reader, 0, bytes.length).size());
	}

	/** Structural rejections that must survive: the lists have to fit ahead of the code. */
	@Test
	public void testRejectsStructurallyImpossibleHeaders() throws IOException {
		assertFalse("overhead may not exceed the total",
			parse(10, 20, 0x02bc, 0, 0, 0, 0, 0).isValid());
		assertFalse("zero total is not a page",
			parse(0, 1, 0x02bc, 0, 0, 0, 0, 0).isValid());
		assertFalse("zero frame size is not a page",
			parse(100, 10, 0, 0, 0, 0, 0, 0).isValid());
		assertFalse("relocation list must fit within the overhead area",
			parse(100, 2, 0x02bc, 0, 1000, 0, 0, 0).isValid());
		assertFalse("the third list must fit too",
			parse(100, 2, 0x02bc, 0, 0, 0, 1000, 0).isValid());
	}
}
