package ebbex.rtlink.extract;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import ebbex.rtlink.RTLinkOverlayPage;
import ebbex.rtlink.RTLinkRelocation;
import ebbex.rtlink.extract.RTLinkExtract.Entry;
import ebbex.rtlink.extract.RTLinkExtract.Image;
import ebbex.rtlink.extract.RTLinkExtract.Page;
import ebbex.rtlink.sample.RTLinkSampleGenerator;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

/**
 * The Ghidra-independent extractor against the analyzer's own page parser, on the committed
 * smoke sample. The two are written separately (the extractor from the format doc alone), so
 * agreement here is what lets the extractor serve as an oracle on targets that cannot be
 * committed.
 */
public class RTLinkExtractTest {

	@Rule
	public TemporaryFolder temp = new TemporaryFolder();

	private static byte[] sample() throws IOException {
		return Files.readAllBytes(Path.of(RTLinkSampleGenerator.SAMPLE_PATH));
	}

	private static List<RTLinkOverlayPage> analyzerPages(byte[] file, long overlayStart) {
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(file), true);
		return RTLinkOverlayPage.parseAllPages(reader, overlayStart, file.length);
	}

	@Test
	public void testRecordsAgreeWithTheAnalyzer() throws IOException {
		byte[] file = sample();
		Image image = RTLinkExtract.parse(file);
		List<RTLinkOverlayPage> expected = analyzerPages(file, image.overlayStart());

		assertEquals(3, image.pages().size());
		assertEquals(expected.size(), image.pages().size());
		assertEquals("end of file", image.stopReason());
		assertEquals(file.length, image.chainEnd());
		for (int i = 0; i < expected.size(); i++) {
			RTLinkOverlayPage want = expected.get(i);
			Page got = image.pages().get(i);
			String which = "record " + i;
			assertEquals(which, want.getFileOffset(), got.headerOffset());
			assertEquals(which, want.getCodeFileOffset(), got.codeOffset());
			assertEquals(which, want.getCodeSize(), got.codeSize());
			assertEquals(which, want.getFrameSize(), got.frameSize());
			assertEquals(which, sites(want.getRelocations()), sites(got.list(1)));
			assertEquals(which, sites(want.getSecondRelocations()), sites(got.list(2)));
			assertEquals(which, sites(want.getThirdRelocations()), sites(got.list(3)));
		}
	}

	@Test
	public void testExtractedPagesAreTheFileBytes() throws IOException {
		byte[] file = sample();
		Image image = RTLinkExtract.parse(file);
		Path out = temp.newFolder().toPath();
		RTLinkExtract.write(file, image, out, null, null);

		for (Page page : image.pages()) {
			byte[] bin = Files.readAllBytes(out.resolve(String.format("ovl_%02d.bin",
				page.index())));
			int start = (int) page.codeOffset();
			assertArrayEquals(Arrays.copyOfRange(file, start, start + page.codeSize()), bin);
		}
		assertFalse(Files.exists(out.resolve("ovl_00.rel.bin")));
		assertTrue(Files.readString(out.resolve("index.txt"))
				.contains("chain ends at file 0x" + Integer.toHexString(file.length)));
	}

	@Test
	public void testRelocationTouchesOnlyListedSites() throws IOException {
		byte[] file = sample();
		Image image = RTLinkExtract.parse(file);
		Path out = temp.newFolder().toPath();
		RTLinkExtract.write(file, image, out, 0x1000, 0x2000);

		for (Page page : image.pages()) {
			String name = String.format("ovl_%02d", page.index());
			byte[] raw = Files.readAllBytes(out.resolve(name + ".bin"));
			byte[] rel = Files.readAllBytes(out.resolve(name + ".rel.bin"));
			boolean[] site = new boolean[raw.length];
			for (Entry e : page.entries()) {
				int delta = switch (e.list()) {
					case 1 -> 0x1000;
					case 2 -> 0x2000;
					default -> 0; // list 3 is applied unrelocated
				};
				assertEquals(name + " site 0x" + Integer.toHexString(e.site()),
					(RTLinkExtract.word(raw, e.site()) + delta) & 0xffff,
					RTLinkExtract.word(rel, e.site()));
				site[e.site()] = site[e.site() + 1] = true;
			}
			for (int i = 0; i < raw.length; i++) {
				if (!site[i]) {
					assertEquals(name + " byte 0x" + Integer.toHexString(i), raw[i], rel[i]);
				}
			}
		}
	}

	private static List<Integer> sites(List<?> entries) {
		return entries.stream()
				.map(e -> switch (e) {
					case RTLinkRelocation r -> r.getSiteOffset();
					case Entry x -> x.site();
					default -> throw new IllegalArgumentException(e.toString());
				})
				.toList();
	}
}
