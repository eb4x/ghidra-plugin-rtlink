package ebbex.rtlink.sample;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.Test;

import ebbex.rtlink.RTLinkOverlayPage;
import ebbex.rtlink.RTLinkRelocation;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

/**
 * The committed smoke sample against its generator, and its overlay records against the page
 * parser. The smoke test asserts what Ghidra makes of the sample; this pins the sample itself.
 */
public class RTLinkSampleTest {

	/** File offset of the overlay area: the paragraph-aligned MZ image end. */
	private static final int OVERLAY_START = 0x240;

	private static byte[] committed() throws IOException {
		return Files.readAllBytes(Path.of(RTLinkSampleGenerator.SAMPLE_PATH));
	}

	@Test
	public void testCommittedSampleMatchesGenerator() throws IOException {
		assertArrayEquals("src/test/smoke/rtlink-sample.exe is stale: run " +
			"./gradlew generateSmokeSample", RTLinkSampleGenerator.generate(), committed());
	}

	@Test
	public void testGeneratorIsDeterministic() {
		assertArrayEquals(RTLinkSampleGenerator.generate(), RTLinkSampleGenerator.generate());
	}

	@Test
	public void testOverlayRecordsParse() throws IOException {
		byte[] sample = committed();
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(sample), true);
		List<RTLinkOverlayPage> pages =
			RTLinkOverlayPage.parseAllPages(reader, OVERLAY_START, sample.length);
		assertEquals(3, pages.size());

		RTLinkOverlayPage record0 = pages.get(0);
		assertEquals(RTLinkSampleGenerator.FRAME_SIZE, record0.getFrameSize());
		assertEquals("a far call into the resident image and one through a trampoline",
			List.of(0x0a, 0x12), siteOffsets(record0.getRelocations()));
		assertTrue(record0.getSecondRelocations().isEmpty());

		RTLinkOverlayPage record1 = pages.get(1);
		assertTrue(record1.getRelocations().isEmpty());
		assertEquals("the intra-page far call from module 0 to module 1",
			List.of(0x0a), siteOffsets(record1.getSecondRelocations()));
		assertEquals("module 1 appears in no relocation: only its 14-byte stub names it",
			List.of(0), List.copyOf(record1.getModuleBases()));

		RTLinkOverlayPage record2 = pages.get(2);
		assertEquals(List.of(0x06), siteOffsets(record2.getRelocations()));
		assertEquals("the chain runs exactly to the end of the file", sample.length,
			record2.getFileOffset() + record2.getHeader().getTotalSizeBytes());
	}

	private static List<Integer> siteOffsets(List<RTLinkRelocation> relocations) {
		return relocations.stream().map(RTLinkRelocation::getSiteOffset).toList();
	}
}
