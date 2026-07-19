/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ebbex.rtlink;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.util.bin.BinaryReader;

/**
 * Represents a single RTLink/Plus overlay page: its header, relocation entries, and
 * the file region where code bytes reside.  Code bytes are not stored here; they are
 * read directly from {@link ghidra.program.database.mem.FileBytes} when creating
 * memory blocks.
 */
public class RTLinkOverlayPage {

	private final int pageIndex;
	private final long fileOffset;
	private final RTLinkPageHeader header;
	private final List<RTLinkRelocation> relocations;
	private final List<RTLinkRelocation> secondRelocations;
	private final List<RTLinkRelocation> thirdRelocations;

	/**
	 * Constructs an overlay page by reading the header and relocations at the given
	 * file offset.
	 *
	 * @param reader    A {@link BinaryReader} for the file
	 * @param fileOffset Absolute file offset where this page starts
	 * @param pageIndex  0-based page number
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkOverlayPage(BinaryReader reader, long fileOffset, int pageIndex)
			throws IOException {
		this.pageIndex = pageIndex;
		this.fileOffset = fileOffset;

		reader.setPointerIndex(fileOffset);
		header = new RTLinkPageHeader(reader);

		relocations = readList(reader, header.getRelocOffset(), header.getRelocCount());

		// The second and third lists are parsed for visibility but never applied — they
		// do not take the image-base delta. See RTLinkPageHeader's class comment.
		secondRelocations =
			readList(reader, header.getSecondRelocOffset(), header.getSecondRelocCount());
		thirdRelocations =
			readList(reader, header.getThirdRelocOffset(), header.getThirdRelocCount());
	}

	private List<RTLinkRelocation> readList(BinaryReader reader, int offset, int count)
			throws IOException {
		List<RTLinkRelocation> list = new ArrayList<>(count);
		if (count > 0) {
			reader.setPointerIndex(fileOffset + offset);
			for (int i = 0; i < count; i++) {
				list.add(new RTLinkRelocation(reader));
			}
		}
		return list;
	}

	public int getPageIndex() {
		return pageIndex;
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public RTLinkPageHeader getHeader() {
		return header;
	}

	public List<RTLinkRelocation> getRelocations() {
		return relocations;
	}

	/**
	 * The page's second relocation list, empty when it has none (as it always is in
	 * VICEROY.EXE; NEBULAR.EXE has 90 sites, SPHERE.EXE 67). Each site is the segment
	 * word of a statically encoded <b>intra-page far call</b> between two of the page's
	 * modules ({@code CALLF module:offset}); the stored word is a page-relative
	 * paragraph. The runtime fixup (byte-identical in all three binaries; the list-2
	 * call reads the count from header +0xA, rounds the start index up to a 4-entry
	 * group exactly as {@link RTLinkPageHeader#getSecondRelocOffset()} models, and adds
	 * {@code currentFrame - previousFrame} on every page move) maintains the invariant
	 * <i>word = file word + current frame</i> — so
	 * {@code RTLinkOverlayAnalyzer.applyOverlayRelocations} applies them statically with
	 * the overlay block's base segment as the frame. They are excluded from
	 * {@link #getModuleBases()} only because nothing has needed their seg_index anchors
	 * yet; the runtime addresses their sites (frame + seg_index):offset identically to
	 * the first list's.
	 */
	public List<RTLinkRelocation> getSecondRelocations() {
		return secondRelocations;
	}

	/**
	 * The page's third relocation list. Empty on every page of every binary seen so far;
	 * the RTLink runtime reads its count, but the RTLink/Plus 6.10 linker has been shown
	 * unable to emit one (see {@link RTLinkPageHeader}), so a nonzero count would signal a
	 * different linker version. Parsed but not applied, exactly like
	 * {@link #getSecondRelocations()}.
	 */
	public List<RTLinkRelocation> getThirdRelocations() {
		return thirdRelocations;
	}

	/**
	 * Returns the module base paragraphs of this page, derived from the distinct
	 * relocation seg_index values.  RTLink packs multiple link-time modules into one
	 * overlay page; each module executes with CS = page frame segment + its base
	 * paragraph, so CS-relative absolute offsets in module code (switch jump tables,
	 * the module_word of 14-byte dispatch stubs) are module-relative, not
	 * page-relative.  Module 0 (the page start) is always included.
	 * <p>
	 * Note this set is not exhaustive: a module referenced only by dispatch stubs
	 * (never by an intra-page relocation) does not appear in the relocation table.
	 *
	 * @return the sorted set of module base paragraph indices
	 */
	public SortedSet<Integer> getModuleBases() {
		SortedSet<Integer> bases = new TreeSet<>();
		bases.add(0);
		for (RTLinkRelocation reloc : relocations) {
			bases.add(reloc.getSegmentIndex());
		}
		return bases;
	}

	/**
	 * Returns the file offset where the code bytes begin (past the overhead area).
	 *
	 * @return code region file offset
	 */
	public long getCodeFileOffset() {
		return fileOffset + header.getOverheadSizeBytes();
	}

	/**
	 * Returns the number of code bytes in this page.
	 *
	 * @return code size in bytes
	 */
	public int getCodeSize() {
		return header.getCodeSizeBytes();
	}

	/**
	 * Returns the overlay frame size from the page header.
	 *
	 * @return frame size in bytes
	 */
	public long getFrameSize() {
		return header.getFrameSize();
	}

	/**
	 * Parses all contiguous RTLink/Plus overlay pages starting at the given file
	 * offset.  Stops when a header fails validation or the end of the file is reached.
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
				RTLinkOverlayPage page = new RTLinkOverlayPage(reader, cursor, pageIndex);
				if (!page.getHeader().isValid()) {
					break;
				}
				int totalSize = page.getHeader().getTotalSizeBytes();
				if (totalSize <= 0) {
					break;
				}
				// The final page's paragraph-rounded total size can extend a few bytes
				// past the physical end of file, because the image is not padded to a
				// full paragraph. Accept such a final page as long as its overhead
				// (header + relocations) fits and at least one code byte is present; the
				// code size is clamped when the memory block is created. Only bail out
				// if even the overhead does not fit within the file.
				if (cursor + totalSize > fileLength &&
					cursor + page.getHeader().getOverheadSizeBytes() >= fileLength) {
					break;
				}
				pages.add(page);
				cursor += totalSize;
				pageIndex++;
			}
			catch (IOException e) {
				break;
			}
		}
		return pages;
	}

	@Override
	public String toString() {
		return String.format("RTLinkOverlayPage[page=%d fileOff=0x%X codeOff=0x%X codeSize=0x%X]",
			pageIndex, fileOffset, getCodeFileOffset(), getCodeSize());
	}
}
