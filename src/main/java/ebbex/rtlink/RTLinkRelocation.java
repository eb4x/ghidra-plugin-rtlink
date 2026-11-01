package ebbex.rtlink;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;

/**
 * A single 4-byte RTLink/Plus overlay relocation entry.
 *
 * <pre>
 * uint16 offset;    // site offset, relative to paragraph seg_index of the page code
 * uint16 seg_index; // paragraph (16-byte unit) index within the page code
 * </pre>
 *
 * The patched word lives at page-linear byte offset {@code seg_index * 16 + offset}
 * (see {@link #siteOffset()}). Within one list, the runtime fixup loop adds the same
 * value to the unrelocated segment word at every site, regardless of seg_index — seg_index
 * only relocates the site address, it never selects a different fixup value. Which value
 * depends on the list: the load delta for the first, the page frame for the second.
 *
 * @param offset       the site offset, relative to paragraph {@code segmentIndex}
 * @param segmentIndex the paragraph index within the page code the offset is relative to
 */
public record RTLinkRelocation(int offset, int segmentIndex) implements StructConverter {

	public static final String NAME = "RTLink_Relocation";

	/** The entry at the reader's position. */
	public static RTLinkRelocation read(BinaryReader reader) throws IOException {
		int offset = Short.toUnsignedInt(reader.readNextShort());
		int segmentIndex = Short.toUnsignedInt(reader.readNextShort());
		return new RTLinkRelocation(offset, segmentIndex);
	}

	/** The page-linear byte offset of the patched word: {@code seg_index * 16 + offset}. */
	public int siteOffset() {
		return segmentIndex * 16 + offset;
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "offset", "Site offset, relative to paragraph seg_index of the page code");
		struct.add(WORD, "seg_index", "Paragraph index within the page code (site = seg_index*16 + offset)");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format("off=%04x segidx=%04x", offset, segmentIndex);
	}
}
