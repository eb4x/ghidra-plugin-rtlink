package ebbex.rtlink;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import ebbex.rtlink.OmfTestLibrary.ModuleSpec;

/**
 * Malformed input to {@link OmfLibrary}: each must surface as an {@link IOException}, which
 * the analyzer reports as an unreadable library, never as an unchecked exception that ends
 * analysis or as a hang.
 */
public class OmfLibraryTest {

	/** A four-byte code segment, so any data offset past 4 lies outside it. */
	private static ModuleSpec module() {
		return new ModuleSpec("M", "c3 c3 c3 c3").pub("_m", 0);
	}

	@Test
	public void testDataPastItsSegmentIsRefused() {
		// LEDATA: segment 1, offset 0x1000, one byte.
		ModuleSpec spec = module().record(0xa0, "01 00 10 90");
		IOException e = assertThrows(IOException.class,
			() -> OmfLibrary.parse(OmfTestLibrary.library(spec)));
		assertTrue(e.getMessage(), e.getMessage().contains("past the end of segment"));
	}

	@Test
	public void testIteratedDataNestedTooDeepIsRefused() {
		// LIDATA: segment 1, offset 0, then twenty levels of {repeat 1, one block} around a
		// one-byte leaf.
		String nest = "01 00 01 00 ".repeat(20) + "01 00 00 00 01 90";
		ModuleSpec spec = module().record(0xa2, "01 00 00 " + nest);
		IOException e = assertThrows(IOException.class,
			() -> OmfLibrary.parse(OmfTestLibrary.library(spec)));
		assertTrue(e.getMessage(), e.getMessage().contains("nested deeper"));
	}

	/** An object cut short by its final checksum byte is truncated, not a complete module. */
	@Test
	public void testRecordMissingItsChecksumIsRefused() {
		byte[] object = OmfTestLibrary.module(module());
		byte[] truncated = Arrays.copyOf(object, object.length - 1);
		IOException e = assertThrows(IOException.class, () -> OmfLibrary.parse(truncated));
		assertTrue(e.getMessage(), e.getMessage().contains("bad record"));
	}

	/** An empty unit repeated 2^32-1 times adds nothing, at once. */
	@Test(timeout = 10_000)
	public void testEmptyIteratedUnitDoesNotSpin() throws Exception {
		// LIDATA32: segment 1, offset 0, repeat 0xffffffff, no blocks, zero bytes.
		ModuleSpec spec = module().record(0xa3, "01 00 00 00 00 ff ff ff ff 00 00 00");
		List<OmfLibrary.Module> modules = OmfLibrary.parse(OmfTestLibrary.library(spec));
		assertEquals(1, modules.size());
	}
}
