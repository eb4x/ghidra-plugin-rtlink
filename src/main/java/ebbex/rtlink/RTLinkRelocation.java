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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A single 4-byte RTLink/Plus overlay relocation entry.
 *
 * <pre>
 * uint16 offset;    // site offset, relative to paragraph seg_index of the page code
 * uint16 seg_index; // paragraph (16-byte unit) index within the page code
 * </pre>
 *
 * The patched word lives at page-linear byte offset {@code seg_index * 16 + offset}
 * (see {@link #getSiteOffset()}). The runtime fixup loop adds the same load delta to
 * the unrelocated segment word at every site, regardless of seg_index — seg_index
 * only relocates the site address, it never selects a different fixup value.
 */
public class RTLinkRelocation implements StructConverter {

	public static final String NAME = "RTLink_Relocation";

	private int offset;
	private int segIndex;

	/**
	 * Constructs a new RTLink/Plus relocation entry
	 *
	 * @param reader A {@link BinaryReader} positioned at the start of the entry
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkRelocation(BinaryReader reader) throws IOException {
		offset = Short.toUnsignedInt(reader.readNextShort());
		segIndex = Short.toUnsignedInt(reader.readNextShort());
	}

	/**
	 * Gets the site offset, relative to paragraph {@code seg_index} of the page code
	 *
	 * @return The offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Gets the paragraph (16-byte unit) index within the page code that the offset
	 * is relative to
	 *
	 * @return The segment index
	 */
	public int getSegmentIndex() {
		return segIndex;
	}

	/**
	 * Gets the page-linear byte offset of the patched word:
	 * {@code seg_index * 16 + offset}
	 *
	 * @return The fixup site offset within the page code
	 */
	public int getSiteOffset() {
		return segIndex * 16 + offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "offset", "Site offset, relative to paragraph seg_index of the page code");
		struct.add(WORD, "seg_index", "Paragraph index within the page code (site = seg_index*16 + offset)");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format("off=%04x segidx=%04x", offset, segIndex);
	}
}
