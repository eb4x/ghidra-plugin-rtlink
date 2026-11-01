package ebbex.rtlink;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.util.bin.BinaryReader;

/**
 * A single RTLink/Plus overlay page: its header, relocation entries, and the file region
 * where code bytes reside. Code bytes are not stored here; they are read directly from
 * {@link ghidra.program.database.mem.FileBytes} when creating memory blocks.
 *
 * @param pageIndex         0-based page number
 * @param fileOffset        absolute file offset where this page starts
 * @param relocations       the first relocation list, applied with the image-base delta
 * @param secondRelocations the page's second relocation list, empty when it has none (as it
 *                          always is in VICEROY.EXE; NEBULAR.EXE has 90 sites, SPHERE.EXE
 *                          67). Each site is the segment word of a statically encoded
 *                          <b>intra-page far call</b> between two of the page's modules
 *                          ({@code CALLF module:offset}); the stored word is a page-relative
 *                          paragraph. The runtime fixup (byte-identical in all three
 *                          binaries; the list-2 call reads the count from header +0xA, rounds
 *                          the start index up to a 4-entry group exactly as
 *                          {@link RTLinkPageHeader#secondRelocOffset()} models, and adds
 *                          {@code currentFrame - previousFrame} on every page move) maintains
 *                          the invariant <i>word = file word + current frame</i> — so
 *                          {@code OverlayRelocations.apply} applies them statically with the
 *                          overlay block's base segment as the frame. They are excluded from
 *                          {@link #moduleBases()} only because nothing has needed their
 *                          seg_index anchors yet; the runtime addresses their sites
 *                          (frame + seg_index):offset identically to the first list's.
 * @param thirdRelocations  the page's third relocation list. Empty on every page of every
 *                          binary seen so far; the RTLink runtime reads its count, but the
 *                          RTLink/Plus 6.10 linker has been shown unable to emit one (see
 *                          {@link RTLinkPageHeader}), so a nonzero count would signal a
 *                          different linker version. Parsed but not applied.
 */
public record RTLinkOverlayPage(int pageIndex, long fileOffset, RTLinkPageHeader header,
		List<RTLinkRelocation> relocations, List<RTLinkRelocation> secondRelocations,
		List<RTLinkRelocation> thirdRelocations) {

	public RTLinkOverlayPage {
		relocations = List.copyOf(relocations);
		secondRelocations = List.copyOf(secondRelocations);
		thirdRelocations = List.copyOf(thirdRelocations);
	}

	/** The page whose header starts at {@code fileOffset}, with its relocation lists. */
	public static RTLinkOverlayPage read(BinaryReader reader, long fileOffset, int pageIndex)
			throws IOException {
		reader.setPointerIndex(fileOffset);
		RTLinkPageHeader header = RTLinkPageHeader.read(reader);
		return new RTLinkOverlayPage(pageIndex, fileOffset, header,
			readList(reader, fileOffset + header.relocOffset(), header.relocCount()),
			readList(reader, fileOffset + header.secondRelocOffset(), header.secondRelocCount()),
			readList(reader, fileOffset + header.thirdRelocOffset(), header.thirdRelocCount()));
	}

	private static List<RTLinkRelocation> readList(BinaryReader reader, long at, int count)
			throws IOException {
		List<RTLinkRelocation> list = new ArrayList<>(count);
		if (count > 0) {
			reader.setPointerIndex(at);
			for (int i = 0; i < count; i++) {
				list.add(RTLinkRelocation.read(reader));
			}
		}
		return list;
	}

	/**
	 * The module base paragraphs of this page, derived from the distinct relocation
	 * seg_index values. RTLink packs multiple link-time modules into one overlay page; each
	 * module executes with CS = page frame segment + its base paragraph, so CS-relative
	 * absolute offsets in module code (switch jump tables, the module_word of 14-byte
	 * dispatch stubs) are module-relative, not page-relative. Module 0 (the page start) is
	 * always included.
	 * <p>
	 * Note this set is not exhaustive: a module referenced only by dispatch stubs (never by
	 * an intra-page relocation) does not appear in the relocation table.
	 */
	public SortedSet<Integer> moduleBases() {
		SortedSet<Integer> bases = new TreeSet<>();
		bases.add(0);
		for (RTLinkRelocation reloc : relocations) {
			bases.add(reloc.segmentIndex());
		}
		return bases;
	}

	/** The file offset where the code bytes begin (past the overhead area). */
	public long codeFileOffset() {
		return fileOffset + header.overheadSizeBytes();
	}

	/** The number of code bytes in this page. */
	public int codeSize() {
		return header.codeSizeBytes();
	}

	/** The overlay frame size from the page header, in paragraphs. */
	public int frameSize() {
		return header.frameSize();
	}

	/**
	 * Parses all contiguous RTLink/Plus overlay pages starting at the given file
	 * offset. Stops when a header fails validation, when its frame size differs from the
	 * first page's (it is constant along the chain in every binary checked), or at the end
	 * of the file.
	 *
	 * @param reader       A {@link BinaryReader} for the file
	 * @param overlayStart File offset where overlay data begins
	 * @param fileLength   Total file length
	 * @return list of parsed overlay pages (may be empty)
	 */
	public static List<RTLinkOverlayPage> parseAllPages(BinaryReader reader, long overlayStart,
			long fileLength) {
		List<RTLinkOverlayPage> pages = new ArrayList<>();
		long cursor = overlayStart;
		int pageIndex = 0;

		while (cursor + RTLinkPageHeader.HEADER_SIZE <= fileLength) {
			try {
				RTLinkOverlayPage page = read(reader, cursor, pageIndex);
				if (!page.header().isValid()) {
					break;
				}
				if (!pages.isEmpty() && page.frameSize() != pages.get(0).frameSize()) {
					break; // not this chain's record: appended data that happens to validate
				}
				int totalSize = page.header().totalSizeBytes(); // positive: isValid
				// The final page's paragraph-rounded total size can extend a few bytes
				// past the physical end of file, because the image is not padded to a
				// full paragraph. Accept such a final page as long as its overhead
				// (header + relocations) fits and at least one code byte is present; the
				// code size is clamped when the memory block is created. Only bail out
				// if even the overhead does not fit within the file.
				if (cursor + totalSize > fileLength &&
					cursor + page.header().overheadSizeBytes() >= fileLength) {
					break;
				}
				pages.add(page);
				cursor += totalSize;
				pageIndex++;
			}
			catch (IOException _) {
				break;
			}
		}
		return pages;
	}

	@Override
	public String toString() {
		return String.format("RTLinkOverlayPage[page=%d fileOff=0x%X codeOff=0x%X codeSize=0x%X]",
			pageIndex, fileOffset, codeFileOffset(), codeSize());
	}
}
