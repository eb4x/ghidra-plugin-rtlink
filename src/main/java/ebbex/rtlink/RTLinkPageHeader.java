package ebbex.rtlink;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;

/**
 * A 16-byte RTLink/Plus overlay page header.
 *
 * <pre>
 * struct rtlink_page_header {
 *     uint16 total_paragraphs;     // total record size in 16-byte paragraphs
 *     uint16 overhead_paragraphs;  // header+relocs+padding; code starts after
 *     uint16 frame_size;           // overlay frame size in paragraphs (700 / 510)
 *     uint16 reloc_start_index;    // entry index the first relocation list starts at
 *     uint16 reloc_count;          // entries in the first relocation list
 *     uint16 reloc_count_2;        // entries in the second list, if any
 *     uint16 reloc_count_3;        // entries in the third list, if any
 *     uint16 codeview_word;        // 0 unless the program was linked with CODEVIEW
 * };
 * </pre>
 * <p>
 * Every field here is a word, and <b>none of them may be assumed zero</b>. Three separate
 * bugs in this class came from treating a field that VICEROY.EXE happens to zero as if the
 * format guaranteed it:
 * <ol>
 * <li>{@code reloc_count} read as a dword swallows {@code reloc_count_2}. NEBULAR.EXE
 *     (Rex Nebular) carries a second list on 15 of its 79 pages; page 1's count of 94
 *     became 131166, {@link #isValid()} rejected it, and the page walk stopped before it
 *     started — the binary imported with no overlay blocks at all. SPHERE.EXE
 *     (Dragonsphere) failed identically. ROE2MAIN.EXE failed more quietly: 27 of its 171
 *     pages parsed and the rest were silently dropped.</li>
 * <li>{@code frame_size} read as a dword swallows {@code reloc_start_index}.</li>
 * <li>The last word was declared {@code reserved} and <i>validated as zero</i>. It is not
 *     reserved. Pocket Soft's own VMEX2.EXE example — the same program as VMEX1.EXE, built
 *     with one extra linker directive, {@code CODEVIEW} — carries 0x091C there on every one
 *     of its five pages, and the zero check rejected the whole executable.</li>
 * </ol>
 * The moral, learned three times: check a constant against a second executable before
 * believing it is part of the format.
 * <p>
 * The layout above is confirmed against the RTLink runtime's own relocation code (traced
 * in VICEROY at 210d:2318, which drives the fixup subroutine at 210d:2e59). That routine
 * reads {@code reloc_start_index} and {@code reloc_count} as separate words, and reaches
 * the later lists through {@code reloc_count_2} and {@code reloc_count_3}. Relocation
 * lists are addressed by <i>entry index</i>, not byte offset: the runtime rounds the index
 * up to a multiple of 4 between the first and second list, which is why the second list
 * lands on a paragraph boundary (4 entries × 4 bytes = 16). See {@link #relocOffset()}
 * and friends.
 * <p>
 * <b>The first two lists are applied, with different addends; the third never is.</b> The
 * runtime applies the first list at initial load, adding the image-base delta. The second
 * is driven from the page-move path and keeps <i>word = file word + current frame</i>, so
 * it is applied statically with the overlay block's base segment as the frame (see
 * {@link RTLinkOverlayPage#secondRelocations()}). {@code reloc_count_3} is zero on all
 * 281 pages across VICEROY, NEBULAR and
 * ROE2MAIN — and it has since been established <b>by construction</b> (RTLink/Plus 6.10 +
 * a purpose-built probe; see {@code ~/dosbox/RTLTEST/HANDOFF.md}) that the 6.10 linker
 * cannot emit a list-3 entry at all: for a resident site holding a paged symbol's segment
 * it announces "page-base relocation will be performed when the page comes in" and then
 * writes nothing, leaving the site permanently unpatched. The runtime's list-3 support is
 * vestigial for 6.10-linked programs, so parsing without applying is the complete
 * treatment, not a stopgap.
 *
 * @param relocStartIndex  the entry index the first relocation list starts at; 0 in every
 *                         page seen
 * @param secondRelocCount entries in the second relocation list; 0 when the page has none
 * @param thirdRelocCount  entries in the third relocation list; 0 in every page seen
 * @param codeviewWord     the last word of the header. Zero unless the program was linked
 *                         with the {@code CODEVIEW} directive, in which case the linker
 *                         stamps the same nonzero value into every page (0x091C throughout
 *                         Pocket Soft's VMEX2.EXE). Its meaning is unknown; what matters is
 *                         that it is <b>not</b> reserved, so {@link #isValid()} must not
 *                         require it to be zero — doing so rejected VMEX2.EXE outright.
 */
public record RTLinkPageHeader(int totalParagraphs, int overheadParagraphs, int frameSize,
		int relocStartIndex, int relocCount, int secondRelocCount, int thirdRelocCount,
		int codeviewWord) implements StructConverter {

	public static final String NAME = "RTLink_Page_Header";
	public static final int HEADER_SIZE = 16;

	/** The header at the reader's position. */
	public static RTLinkPageHeader read(BinaryReader reader) throws IOException {
		int[] words = new int[8];
		for (int i = 0; i < words.length; i++) {
			words[i] = Short.toUnsignedInt(reader.readNextShort());
		}
		return new RTLinkPageHeader(words[0], words[1], words[2], words[3], words[4], words[5],
			words[6], words[7]);
	}

	/** Byte offset, from the start of the header, of the first relocation list. */
	public int relocOffset() {
		return HEADER_SIZE + relocStartIndex * 4;
	}

	/**
	 * Byte offset, from the start of the header, of the second relocation list. The
	 * runtime rounds the <i>entry index</i> past the first list up to a multiple of 4,
	 * which puts the second list on a paragraph boundary.
	 */
	public int secondRelocOffset() {
		return HEADER_SIZE + roundUpToEntryGroup(relocStartIndex + relocCount) * 4;
	}

	/**
	 * Byte offset, from the start of the header, of the third relocation list. Unlike the
	 * second, it follows the previous list immediately — the runtime advances the entry
	 * index by the second list's count without rounding.
	 */
	public int thirdRelocOffset() {
		return secondRelocOffset() + secondRelocCount * 4;
	}

	private static int roundUpToEntryGroup(int entryIndex) {
		return (entryIndex + 3) & ~3;
	}

	public int totalSizeBytes() {
		return totalParagraphs * 16;
	}

	public int overheadSizeBytes() {
		return overheadParagraphs * 16;
	}

	public int codeSizeBytes() {
		return totalSizeBytes() - overheadSizeBytes();
	}

	/** True if the header fields are structurally consistent. */
	public boolean isValid() {
		if (totalParagraphs <= 0) {
			return false;
		}
		if (overheadParagraphs <= 0 || overheadParagraphs > totalParagraphs) {
			return false;
		}
		if (frameSize <= 0) {
			return false;
		}
		// Deliberately no check on codeviewWord: it is not reserved, and requiring it to be
		// zero rejected every page of a CODEVIEW-linked program (see the class comment).
		// The remaining checks plus the page-chain walk in RTLinkOverlayPage.parseAllPages
		// carry the validation; nothing in the corpus is newly accepted without this one.
		//
		// All three relocation lists live in the overhead area, ahead of the code. The
		// lists run in order, so the end of the last one bounds them all.
		long overheadBytes = (long) overheadParagraphs * 16;
		long lastListEnd = (long) thirdRelocOffset() + (long) thirdRelocCount * 4;
		return lastListEnd <= overheadBytes;
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "total_paragraphs", "Total record size in 16-byte paragraphs");
		struct.add(WORD, "overhead_paragraphs", "Header+relocs+padding paragraphs");
		struct.add(WORD, "frame_size", "Overlay frame size in paragraphs");
		struct.add(WORD, "reloc_start_index", "Entry index the first relocation list starts at");
		struct.add(WORD, "reloc_count", "Entries in the first relocation list");
		struct.add(WORD, "reloc_count_2", "Entries in the second relocation list (0 if none)");
		struct.add(WORD, "reloc_count_3", "Entries in the third relocation list (0 if none)");
		struct.add(WORD, "codeview_word", "Nonzero only in CODEVIEW-linked programs");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format(
			"RTLinkPageHeader[total=%d overhead=%d frame=0x%X relocs=%d/%d/%d]",
			totalParagraphs, overheadParagraphs, frameSize, relocCount, secondRelocCount,
			thirdRelocCount);
	}
}
