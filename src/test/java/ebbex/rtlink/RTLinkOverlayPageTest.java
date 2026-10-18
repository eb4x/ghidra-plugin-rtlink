package ebbex.rtlink;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

/**
 * Characterization tests for {@link RTLinkOverlayPage}: the record-chain walk, where each
 * part of a record is found, and where the walk stops. The records are synthetic, built to
 * the layout {@code docs/rtlink-format.md} gives; {@link RTLinkPageHeaderTest} covers the
 * header shapes taken from real binaries.
 */
public class RTLinkOverlayPageTest {

	private static final int FRAME = 0x2bc;

	/** A relocation entry: site offset and paragraph index. */
	private record Reloc(int offset, int segIndex) {
	}

	/**
	 * One record of {@code total} paragraphs, {@code overhead} of them header and lists, with
	 * the given lists (list 2 at the rounded entry index, list 3 straight after it) and its
	 * code paragraphs filled with {@code fill}.
	 */
	private static byte[] record(int total, int overhead, int frame, List<Reloc> list1,
			List<Reloc> list2, int fill) {
		byte[] bytes = new byte[total * 16];
		int[] header = { total, overhead, frame, 0, list1.size(), list2.size(), 0, 0 };
		for (int i = 0; i < header.length; i++) {
			word(bytes, i * 2, header[i]);
		}
		int at = 16;
		for (Reloc reloc : list1) {
			word(bytes, at, reloc.offset());
			word(bytes, at + 2, reloc.segIndex());
			at += 4;
		}
		at = 16 + ((list1.size() + 3) & ~3) * 4;
		for (Reloc reloc : list2) {
			word(bytes, at, reloc.offset());
			word(bytes, at + 2, reloc.segIndex());
			at += 4;
		}
		Arrays.fill(bytes, overhead * 16, bytes.length, (byte) fill);
		return bytes;
	}

	private static byte[] record(int total, int overhead, int fill) {
		return record(total, overhead, FRAME, List.of(), List.of(), fill);
	}

	private static void word(byte[] bytes, int at, int value) {
		bytes[at] = (byte) value;
		bytes[at + 1] = (byte) (value >> 8);
	}

	private static byte[] concat(byte[]... parts) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (byte[] part : parts) {
			out.writeBytes(part);
		}
		return out.toByteArray();
	}

	private static List<RTLinkOverlayPage> parse(byte[] file, int overlayStart, int length) {
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(file), true);
		return RTLinkOverlayPage.parseAllPages(reader, overlayStart, length);
	}

	@Test
	public void testChainWalkFindsEveryRecordAndItsParts() throws IOException {
		byte[] first = record(4, 2, FRAME, List.of(new Reloc(0x10, 1), new Reloc(0x4, 0)),
			List.of(), 0x90);
		byte[] second = record(3, 1, 0xc3);
		byte[] third = record(5, 2, 0xcc);
		byte[] junk = new byte[0x20]; // the MZ image before the overlay area
		byte[] file = concat(junk, first, second, third);

		List<RTLinkOverlayPage> pages = parse(file, 0x20, file.length);

		assertEquals(3, pages.size());
		assertEquals(List.of(0, 1, 2), pages.stream().map(RTLinkOverlayPage::getPageIndex).toList());
		assertEquals(List.of(0x20L, 0x60L, 0x90L),
			pages.stream().map(RTLinkOverlayPage::getFileOffset).toList());
		assertEquals(List.of(0x40L, 0x70L, 0xb0L),
			pages.stream().map(RTLinkOverlayPage::getCodeFileOffset).toList());
		assertEquals(List.of(0x20, 0x20, 0x30),
			pages.stream().map(RTLinkOverlayPage::getCodeSize).toList());

		RTLinkOverlayPage page = pages.get(0);
		assertEquals(2, page.getRelocations().size());
		assertEquals(0x10, page.getRelocations().get(0).getOffset());
		assertEquals(1, page.getRelocations().get(0).getSegmentIndex());
		assertEquals(Set.of(0, 1), page.getModuleBases());
		assertEquals(Set.of(0), pages.get(1).getModuleBases());
	}

	/** List 2 starts at the entry index after list 1 rounded up to 4: a paragraph boundary. */
	@Test
	public void testSecondListIsReadAtTheRoundedIndex() throws IOException {
		byte[] file = concat(
			record(4, 3, FRAME, List.of(new Reloc(0x2, 0)), List.of(new Reloc(0x8, 2),
				new Reloc(0xa, 3)), 0x90),
			record(2, 1, 0x90));

		RTLinkOverlayPage page = parse(file, 0, file.length).get(0);

		assertEquals(32, page.getHeader().getSecondRelocOffset());
		assertEquals(1, page.getRelocations().size());
		assertEquals(2, page.getSecondRelocations().size());
		assertEquals(0x8, page.getSecondRelocations().get(0).getOffset());
		assertEquals(3, page.getSecondRelocations().get(1).getSegmentIndex());
		assertTrue(page.getThirdRelocations().isEmpty());
		assertEquals("list 2 is not a module-base witness (yet)", Set.of(0),
			page.getModuleBases());
	}

	/** The last record's paragraph-rounded size may run a few bytes past the end of the file. */
	@Test
	public void testFinalRecordMayRunPastTheEndOfTheFile() throws IOException {
		byte[] file = concat(record(2, 1, 0x90), record(4, 1, 0x90));
		int truncated = file.length - 8;

		List<RTLinkOverlayPage> pages = parse(file, 0, truncated);

		assertEquals(2, pages.size());
		assertEquals("the declared size is kept; the block clamps it", 0x30,
			pages.get(1).getCodeSize());
	}

	/** A last record whose header and lists do not even fit in the file is not a page. */
	@Test
	public void testFinalRecordWhoseOverheadDoesNotFitIsDropped() throws IOException {
		byte[] file = concat(record(2, 1, 0x90), record(4, 3, 0x90));
		int truncated = 0x20 + 0x28; // ends inside the second record's 0x30-byte overhead

		assertEquals(1, parse(file, 0, truncated).size());
	}

	/** An invalid header ends the chain, whatever follows it. */
	@Test
	public void testInvalidHeaderEndsTheChain() throws IOException {
		byte[] invalid = record(2, 1, 0x90);
		word(invalid, 2, 3); // overhead 3 > total 2
		byte[] file = concat(record(2, 1, 0x90), invalid, record(2, 1, 0x90));

		assertEquals(1, parse(file, 0, file.length).size());
	}
}
