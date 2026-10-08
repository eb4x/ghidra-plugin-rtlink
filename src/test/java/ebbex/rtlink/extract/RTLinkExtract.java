package ebbex.rtlink.extract;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Extracts every RTLink/Plus overlay page of an MZ executable as a flat binary that a stock
 * disassembler can read ({@code objdump -D -b binary -m i8086 -M intel ovl_NN.bin}), with its
 * relocation lists and the resident image beside it.
 * <p>
 * <b>This class is an oracle, so it must stay independent of what it checks.</b> It uses the
 * JDK only: no Ghidra, and nothing from {@code ebbex.rtlink}. It is written from
 * {@code docs/rtlink-format.md}, not from {@code RTLinkPageHeader} or
 * {@code RTLinkOverlayPage}, so a parsing bug shared with the analyzer cannot hide behind
 * agreement. {@code RTLinkExtractTest} compares the two parsers on the committed sample.
 * <p>
 * Usage: {@code RTLinkExtract <exe> <outdir> [--image-base SEG --frame SEG]}. Runs without
 * Gradle as {@code java src/test/java/ebbex/rtlink/extract/RTLinkExtract.java …}, or through
 * {@code ./gradlew extractOverlays}. Output:
 * <ul>
 * <li>{@code index.txt}: the MZ header, the overlay area, one line per record, and why the
 *     record chain stopped;</li>
 * <li>{@code ovl_NN.bin}: record NN's code exactly as on disk, offset 0 = page offset 0;</li>
 * <li>{@code ovl_NN.relocs.txt}: every relocation entry of the record, with its site;</li>
 * <li>{@code resident.bin} and {@code mz-relocs.txt}: the MZ load module and its
 *     relocations;</li>
 * <li>with both {@code --image-base} and {@code --frame}: {@code ovl_NN.rel.bin} (list 1
 *     sites plus the image base, list 2 sites plus the frame; list 3 is never applied, as
 *     the format doc explains) and {@code resident.rel.bin} (MZ sites plus the image
 *     base).</li>
 * </ul>
 */
public final class RTLinkExtract {

	static final int PAGE_HEADER_SIZE = 16;

	private RTLinkExtract() {
	}

	/** The MZ header fields the extraction needs; every one is a 16-bit word. */
	public record MzHeader(int lastPageBytes, int pages, int relocCount, int headerParagraphs,
			int relocTableOffset) {

		/** File offset just past the load module, from {@code e_cp}/{@code e_cblp}. */
		public long imageEnd() {
			if (pages == 0) {
				return 0;
			}
			return lastPageBytes == 0 ? pages * 512L : (pages - 1) * 512L + lastPageBytes;
		}

		public long loadModuleOffset() {
			return headerParagraphs * 16L;
		}
	}

	/** One MZ relocation: the word at {@code segment:offset} of the load module. */
	public record MzRelocation(int offset, int segment) {

		public int imageOffset() {
			return segment * 16 + offset;
		}
	}

	/**
	 * One relocation entry of a page. {@code list} is 1, 2 or 3; the patched word is at
	 * page-linear {@code seg_index * 16 + offset}.
	 */
	public record Entry(int list, int index, int offset, int segIndex) {

		public int site() {
			return segIndex * 16 + offset;
		}
	}

	/** One overlay record: its eight header words and its relocation entries. */
	public record Page(int index, long headerOffset, int totalParagraphs,
			int overheadParagraphs, int frameSize, int relocStartIndex, int count1, int count2,
			int count3, int codeviewWord, List<Entry> entries) {

		public long codeOffset() {
			return headerOffset + overheadParagraphs * 16L;
		}

		public int codeSize() {
			return (totalParagraphs - overheadParagraphs) * 16;
		}

		public int list1Offset() {
			return PAGE_HEADER_SIZE + relocStartIndex * 4;
		}

		/** The runtime rounds the entry index up to a group of four before list 2. */
		public int list2Offset() {
			return PAGE_HEADER_SIZE + ((relocStartIndex + count1 + 3) & ~3) * 4;
		}

		public int list3Offset() {
			return list2Offset() + count2 * 4;
		}

		public int listsEnd() {
			return list3Offset() + count3 * 4;
		}

		public List<Entry> list(int n) {
			return entries.stream().filter(e -> e.list() == n).toList();
		}
	}

	/** Everything parsed from one executable. */
	public record Image(MzHeader mz, List<MzRelocation> mzRelocations, long overlayStart,
			List<Page> pages, long chainEnd, String stopReason) {
	}

	public static void main(String[] args) throws IOException {
		if (args.length != 2 && args.length != 6) {
			usage();
			return;
		}
		Integer imageBase = null;
		Integer frame = null;
		for (int i = 2; i < args.length; i += 2) {
			int value = Integer.decode(args[i + 1]);
			switch (args[i]) {
				case "--image-base" -> imageBase = value;
				case "--frame" -> frame = value;
				default -> {
					usage();
					return;
				}
			}
		}
		if ((imageBase == null) != (frame == null)) {
			usage();
			return;
		}
		byte[] file = Files.readAllBytes(Path.of(args[0]));
		Path out = Path.of(args[1]);
		Files.createDirectories(out);
		Image image = parse(file);
		write(file, image, out, imageBase, frame);
		System.out.printf("%d overlay records from %s into %s%n", image.pages().size(), args[0],
			out);
	}

	private static void usage() {
		System.err.println(
			"usage: RTLinkExtract <exe> <outdir> [--image-base SEG --frame SEG]");
		System.exit(2);
	}

	static int word(byte[] b, long offset) {
		return (b[(int) offset] & 0xff) | (b[(int) offset + 1] & 0xff) << 8;
	}

	/** Parses the MZ header, its relocations and the overlay record chain. */
	public static Image parse(byte[] file) {
		if (file.length < 0x1c || word(file, 0) != 0x5a4d) {
			throw new IllegalArgumentException("not an MZ executable");
		}
		MzHeader mz = new MzHeader(word(file, 2), word(file, 4), word(file, 6), word(file, 8),
			word(file, 0x18));
		List<MzRelocation> mzRelocations = new ArrayList<>();
		for (int i = 0; i < mz.relocCount(); i++) {
			long at = mz.relocTableOffset() + i * 4L;
			mzRelocations.add(new MzRelocation(word(file, at), word(file, at + 2)));
		}

		long overlayStart = (mz.imageEnd() + 15) & ~15L;
		List<Page> pages = new ArrayList<>();
		long cursor = overlayStart;
		String stop = null;
		while (stop == null) {
			if (cursor == file.length) {
				stop = "end of file";
				break;
			}
			if (cursor + PAGE_HEADER_SIZE > file.length) {
				stop = (file.length - cursor) + " trailing bytes, too few for a header";
				break;
			}
			Page page = readPage(file, cursor, pages.size());
			stop = invalidReason(page, file.length);
			if (stop != null) {
				break;
			}
			pages.add(page);
			cursor += page.totalParagraphs() * 16L;
			if (cursor >= file.length) {
				stop = cursor == file.length ? "end of file"
						: "end of file, last record " + (cursor - file.length) +
							" bytes short of its paragraph";
			}
		}
		return new Image(mz, mzRelocations, overlayStart, pages, cursor, stop);
	}

	private static Page readPage(byte[] file, long at, int index) {
		int[] w = new int[8];
		for (int i = 0; i < 8; i++) {
			w[i] = word(file, at + i * 2L);
		}
		Page header = new Page(index, at, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
			List.of());
		List<Entry> entries = new ArrayList<>();
		long overheadEnd = at + header.overheadParagraphs() * 16L;
		readList(file, at + header.list1Offset(), 1, header.count1(), overheadEnd, entries);
		readList(file, at + header.list2Offset(), 2, header.count2(), overheadEnd, entries);
		readList(file, at + header.list3Offset(), 3, header.count3(), overheadEnd, entries);
		return new Page(index, at, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
			List.copyOf(entries));
	}

	private static void readList(byte[] file, long at, int list, int count, long limit,
			List<Entry> into) {
		for (int i = 0; i < count && at + i * 4L + 4 <= Math.min(limit, file.length); i++) {
			long e = at + i * 4L;
			into.add(new Entry(list, i, word(file, e), word(file, e + 2)));
		}
	}

	/** Why {@code page} is not a record, or null when it is one. */
	private static String invalidReason(Page page, long fileLength) {
		String where = String.format("record %d at file 0x%x: ", page.index(),
			page.headerOffset());
		if (page.totalParagraphs() == 0) {
			return where + "total_paragraphs is 0";
		}
		if (page.overheadParagraphs() == 0 ||
			page.overheadParagraphs() > page.totalParagraphs()) {
			return where + "overhead_paragraphs out of range";
		}
		if (page.frameSize() == 0) {
			return where + "frame_size is 0";
		}
		if (page.listsEnd() > page.overheadParagraphs() * 16) {
			return where + "relocation lists overrun the overhead area";
		}
		if (page.codeOffset() >= fileLength) {
			return where + "code starts past end of file";
		}
		return null;
	}

	/** Writes the extraction of {@code image} into {@code out}. */
	public static void write(byte[] file, Image image, Path out, Integer imageBase,
			Integer frame) throws IOException {
		int width = Math.max(2, String.valueOf(Math.max(0, image.pages().size() - 1)).length());
		List<String> index = new ArrayList<>(header(file, image));
		for (Page page : image.pages()) {
			String name = String.format("ovl_%0" + width + "d", page.index());
			byte[] code = code(file, page);
			Files.write(out.resolve(name + ".bin"), code);
			Files.write(out.resolve(name + ".relocs.txt"), relocLines(file, page, code));
			if (imageBase != null) {
				Files.write(out.resolve(name + ".rel.bin"),
					relocate(code, page, imageBase, frame));
			}
			index.add(indexLine(file, page, code.length));
		}
		index.add(String.format("chain ends at file 0x%x of 0x%x: %s", image.chainEnd(),
			file.length, image.stopReason()));
		Files.write(out.resolve("index.txt"), index);

		byte[] resident = Arrays.copyOfRange(file, (int) image.mz().loadModuleOffset(),
			(int) Math.min(image.mz().imageEnd(), file.length));
		Files.write(out.resolve("resident.bin"), resident);
		Files.write(out.resolve("mz-relocs.txt"), mzRelocLines(image, resident, imageBase));
		if (imageBase != null) {
			Files.write(out.resolve("resident.rel.bin"),
				relocateResident(resident, image.mzRelocations(), imageBase));
		}
	}

	private static List<String> header(byte[] file, Image image) {
		MzHeader mz = image.mz();
		return List.of(
			String.format("file length            0x%x", file.length),
			String.format("e_cblp e_cp            0x%04x 0x%04x -> image end 0x%x", mz.lastPageBytes(),
				mz.pages(), mz.imageEnd()),
			String.format("e_cparhdr              0x%04x -> load module at 0x%x",
				mz.headerParagraphs(), mz.loadModuleOffset()),
			String.format("e_crlc e_lfarlc        %d at 0x%x", mz.relocCount(),
				mz.relocTableOffset()),
			String.format("overlay area           0x%x (image end rounded to a paragraph)",
				image.overlayStart()),
			"",
			"rec  header    code      code_size  total overhd frame  start  n1   n2   n3   cv     " +
				"overhead_tail_nonzero");
	}

	private static String indexLine(byte[] file, Page page, int present) {
		String size = present == page.codeSize() ? String.format("0x%05x", page.codeSize())
				: String.format("0x%05x (0x%x on disk)", page.codeSize(), present);
		return String.format(
			"%3d  0x%06x  0x%06x  %-9s  0x%03x 0x%03x  0x%03x  %-5d  %-4d %-4d %-4d 0x%04x %d",
			page.index(), page.headerOffset(), page.codeOffset(), size, page.totalParagraphs(),
			page.overheadParagraphs(), page.frameSize(), page.relocStartIndex(), page.count1(),
			page.count2(), page.count3(), page.codeviewWord(), overheadTailNonzero(file, page));
	}

	/**
	 * Nonzero bytes in the overhead area past the last relocation list: a relocation the
	 * header does not count would show up here.
	 */
	private static int overheadTailNonzero(byte[] file, Page page) {
		int count = 0;
		for (long at = page.headerOffset() + page.listsEnd(); at < page.codeOffset(); at++) {
			if (file[(int) at] != 0) {
				count++;
			}
		}
		return count;
	}

	private static byte[] code(byte[] file, Page page) {
		long end = Math.min(page.codeOffset() + page.codeSize(), file.length);
		return Arrays.copyOfRange(file, (int) page.codeOffset(), (int) end);
	}

	private static List<String> relocLines(byte[] file, Page page, byte[] code) {
		List<String> lines = new ArrayList<>();
		lines.add(String.format("record %d: list 1 at +0x%x (%d), list 2 at +0x%x (%d), " +
			"list 3 at +0x%x (%d)", page.index(), page.list1Offset(), page.count1(),
			page.list2Offset(), page.count2(), page.list3Offset(), page.count3()));
		lines.add("list entry  offset seg_index  site    file_offset  word");
		for (Entry e : page.entries()) {
			int site = e.site();
			String word = site + 2 <= code.length ? String.format("0x%04x", word(code, site))
					: "OUTSIDE THE PAGE";
			lines.add(String.format("%-4d %-5d  0x%04x 0x%04x     0x%04x  0x%06x     %s",
				e.list(), e.index(), e.offset(), e.segIndex(), site, page.codeOffset() + site,
				word));
		}
		return lines;
	}

	private static byte[] relocate(byte[] code, Page page, int imageBase, int frame) {
		byte[] out = code.clone();
		for (Entry e : page.entries()) {
			int delta = switch (e.list()) {
				case 1 -> imageBase;
				case 2 -> frame;
				default -> 0;
			};
			if (delta != 0 && e.site() + 2 <= out.length) {
				addWord(out, e.site(), delta);
			}
		}
		return out;
	}

	private static byte[] relocateResident(byte[] resident, List<MzRelocation> relocations,
			int imageBase) {
		byte[] out = resident.clone();
		for (MzRelocation r : relocations) {
			if (r.imageOffset() + 2 <= out.length) {
				addWord(out, r.imageOffset(), imageBase);
			}
		}
		return out;
	}

	private static void addWord(byte[] b, int at, int delta) {
		int value = (word(b, at) + delta) & 0xffff;
		b[at] = (byte) value;
		b[at + 1] = (byte) (value >> 8);
	}

	private static List<String> mzRelocLines(Image image, byte[] resident, Integer imageBase) {
		List<String> lines = new ArrayList<>();
		lines.add(imageBase == null ? "seg:off    image_offset  file_offset  word"
				: "seg:off    loaded     image_offset  file_offset  word");
		for (MzRelocation r : image.mzRelocations()) {
			int at = r.imageOffset();
			String word = at + 2 <= resident.length ? String.format("0x%04x", word(resident, at))
					: "OUTSIDE THE IMAGE";
			long fileOffset = image.mz().loadModuleOffset() + at;
			lines.add(imageBase == null
					? String.format("%04x:%04x  0x%06x      0x%06x     %s", r.segment(),
						r.offset(), at, fileOffset, word)
					: String.format("%04x:%04x  %04x:%04x  0x%06x      0x%06x     %s",
						r.segment(), r.offset(), (r.segment() + imageBase) & 0xffff,
						r.offset(), at, fileOffset, word));
		}
		return lines;
	}
}
