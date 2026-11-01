package ebbex.rtlink;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The parts of an Intel OMF-86 object library (or a single object module) that signature
 * matching needs: each module's segments, the bytes its data records give them, the bytes
 * its fixups patch, and its public symbols.
 * <p>
 * Read with the JDK only, from the record layout in the OMF-86 specification: a library is a
 * {@code LIBHDR} (F0h) record that sets the page size, then one module per page-aligned run
 * of records ending in {@code MODEND} (8Ah/8Bh), then {@code LIBEND} (F1h). Of a module's
 * records only {@code LNAMES}, {@code SEGDEF}, {@code PUBDEF}, {@code LEDATA},
 * {@code LIDATA} and {@code FIXUPP} are read; the rest are skipped by their length.
 */
final class OmfLibrary {

	/** A public symbol: its name, the segment (1-based SEGDEF index) and offset it names. */
	record Public(String name, int segment, long offset) {
	}

	/**
	 * A segment: its names, and per byte whether a data record gave it ({@code known}) and
	 * whether a fixup patches it ({@code fixed}: the linker rewrites those bytes).
	 */
	record Segment(int index, String name, String className, byte[] data, boolean[] known,
			boolean[] fixed) {

		/** True for a byte matching must not compare: never given, or rewritten by the linker. */
		boolean masked(int offset) {
			return !known[offset] || fixed[offset];
		}
	}

	record Module(String name, List<Segment> segments, List<Public> publics) {
		Segment segment(int index) {
			for (Segment segment : segments) {
				if (segment.index() == index) {
					return segment;
				}
			}
			return null;
		}
	}

	private static final int THEADR = 0x80;
	private static final int LHEADR = 0x82;
	private static final int PUBDEF = 0x90;
	private static final int PUBDEF32 = 0x91;
	private static final int LNAMES = 0x96;
	private static final int SEGDEF = 0x98;
	private static final int SEGDEF32 = 0x99;
	private static final int FIXUPP = 0x9c;
	private static final int FIXUPP32 = 0x9d;
	private static final int LEDATA = 0xa0;
	private static final int LEDATA32 = 0xa1;
	private static final int LIDATA = 0xa2;
	private static final int LIDATA32 = 0xa3;
	private static final int MODEND = 0x8a;
	private static final int MODEND32 = 0x8b;
	private static final int LIBHDR = 0xf0;
	private static final int LIBEND = 0xf1;

	/** Deepest nesting of iterated data blocks accepted in an LIDATA record. */
	private static final int MAX_LIDATA_DEPTH = 16;

	/** Bytes a fixup patches, by its location type (OMF-86 LOCAT field). */
	private static final int[] FIXUP_SIZE = { 1, 2, 2, 4, 1, 2, 0, 0, 0, 4, 0, 6, 0, 4, 0, 0 };

	private OmfLibrary() {
	}

	static List<Module> read(Path path) throws IOException {
		return parse(Files.readAllBytes(path));
	}

	/** The modules of a library, or the one module of an object file. */
	static List<Module> parse(byte[] bytes) throws IOException {
		List<Module> modules = new ArrayList<>();
		int at = 0;
		int pageSize = 0;
		if (bytes.length > 3 && (bytes[0] & 0xff) == LIBHDR) {
			pageSize = u16(bytes, 1) + 3;
			at = pageSize;
		}
		while (at + 3 <= bytes.length) {
			int type = bytes[at] & 0xff;
			if (type == LIBEND) {
				break;
			}
			if (type != THEADR && type != LHEADR) {
				throw new IOException(String.format("no module header at 0x%x", at));
			}
			ModuleReader reader = new ModuleReader(bytes, at);
			modules.add(reader.read());
			at = reader.end;
			if (pageSize > 0) {
				at = (at + pageSize - 1) / pageSize * pageSize;
			}
		}
		return modules;
	}

	/** One module's records, from its header to its MODEND. */
	private static final class ModuleReader {
		private final byte[] bytes;
		private final int start;
		private int end;
		private final List<String> names = new ArrayList<>(List.of("")); // 1-based
		private final List<Segment> segments = new ArrayList<>();
		private final List<Public> publics = new ArrayList<>();
		private String moduleName = "";
		private Segment lastSegment;
		private int lastOffset;
		private int lastLength;
		private boolean lastIterated;

		ModuleReader(byte[] bytes, int start) {
			this.bytes = bytes;
			this.start = start;
		}

		Module read() throws IOException {
			int at = start;
			while (true) {
				if (at + 3 > bytes.length) {
					throw new IOException("module runs past the end of the file");
				}
				int type = bytes[at] & 0xff;
				int length = u16(bytes, at + 1);
				int content = at + 3;
				int contentEnd = content + length - 1; // the checksum byte closes the record
				if (contentEnd >= bytes.length || length < 1) {
					throw new IOException(String.format("bad record at 0x%x", at));
				}
				Cursor cursor = new Cursor(bytes, content, contentEnd);
				switch (type) {
					case THEADR, LHEADR -> moduleName = cursor.name();
					case LNAMES -> {
						while (cursor.more()) {
							names.add(cursor.name());
						}
					}
					case SEGDEF, SEGDEF32 -> segdef(cursor, type == SEGDEF32);
					case PUBDEF, PUBDEF32 -> pubdef(cursor, type == PUBDEF32);
					case LEDATA, LEDATA32 -> ledata(cursor, type == LEDATA32);
					case LIDATA, LIDATA32 -> lidata(cursor, type == LIDATA32);
					case FIXUPP, FIXUPP32 -> fixupp(cursor, type == FIXUPP32);
					default -> {
						// not needed for matching
					}
				}
				at = contentEnd + 1;
				if (type == MODEND || type == MODEND32) {
					end = at;
					return new Module(moduleName, List.copyOf(segments), List.copyOf(publics));
				}
			}
		}

		private void segdef(Cursor c, boolean wide) {
			int acbp = c.u8();
			if ((acbp >> 5) == 0) {
				c.skip(3); // absolute segment: frame number and offset
			}
			long length = wide ? c.u32() : c.u16();
			if (!wide && (acbp & 0x02) != 0) {
				length = 0x10000; // the B bit: exactly 64K
			}
			String name = name(c.index());
			String className = name(c.index());
			c.index(); // overlay name
			int size = (int) Math.min(length, 0x100000);
			segments.add(new Segment(segments.size() + 1, name, className, new byte[size],
				new boolean[size], new boolean[size]));
		}

		private void pubdef(Cursor c, boolean wide) {
			c.index(); // group
			int segment = c.index();
			if (segment == 0) {
				c.skip(2); // frame number of an absolute base
			}
			while (c.more()) {
				String name = c.name();
				long offset = wide ? c.u32() : c.u16();
				c.index(); // type
				if (segment != 0) {
					publics.add(new Public(name, segment, offset));
				}
			}
		}

		private void ledata(Cursor c, boolean wide) throws IOException {
			Segment segment = segment(c.index());
			int offset = dataOffset(segment, wide ? c.u32() : c.u16());
			byte[] data = c.rest();
			put(segment, offset, data);
			remember(segment, offset, data.length, false);
		}

		private void lidata(Cursor c, boolean wide) throws IOException {
			Segment segment = segment(c.index());
			int offset = dataOffset(segment, wide ? c.u32() : c.u16());
			ByteSink sink = new ByteSink();
			while (c.more()) {
				iterate(c, wide, sink, 0);
			}
			byte[] data = sink.toArray();
			put(segment, offset, data);
			remember(segment, offset, data.length, true);
		}

		/**
		 * One iterated data block. Real translators nest a few levels at most; the depth bound
		 * keeps a malformed record from recursing a 64K record's worth of levels deep.
		 */
		private void iterate(Cursor c, boolean wide, ByteSink sink, int depth)
				throws IOException {
			if (depth > MAX_LIDATA_DEPTH) {
				throw new IOException("iterated data nested deeper than " + MAX_LIDATA_DEPTH);
			}
			long repeat = wide ? c.u32() : c.u16();
			int blocks = c.u16();
			ByteSink one = new ByteSink();
			if (blocks == 0) {
				int count = c.u8();
				for (int i = 0; i < count; i++) {
					one.add(c.u8());
				}
			}
			else {
				for (int i = 0; i < blocks; i++) {
					iterate(c, wide, one, depth + 1);
				}
			}
			byte[] unit = one.toArray();
			if (unit.length == 0) {
				return; // repeating nothing, however often, adds nothing
			}
			for (long i = 0; i < repeat && sink.size() < 0x100000; i++) {
				sink.addAll(unit);
			}
		}

		/** A data record's offset, checked against the segment it fills. */
		private static int dataOffset(Segment segment, long offset) throws IOException {
			if (segment != null && offset > segment.data().length) {
				throw new IOException(String.format(
					"data at 0x%x lies past the end of segment %s", offset, segment.name()));
			}
			return (int) offset;
		}

		private void fixupp(Cursor c, boolean wide) {
			while (c.more()) {
				int first = c.u8();
				if ((first & 0x80) == 0) {
					thread(c, first);
					continue;
				}
				int locat = (first << 8) | c.u8();
				int location = (locat >> 10) & 0x0f;
				int recordOffset = locat & 0x3ff;
				int fixdat = c.u8();
				if ((fixdat & 0x80) == 0) {
					datum(c, (fixdat >> 4) & 0x07);
				}
				if ((fixdat & 0x08) == 0) {
					datum(c, fixdat & 0x03);
				}
				if ((fixdat & 0x04) == 0) {
					c.skip(wide ? 4 : 2); // target displacement
				}
				mask(recordOffset, FIXUP_SIZE[location]);
			}
		}

		private void thread(Cursor c, int data) {
			boolean frame = (data & 0x40) != 0;
			int method = (data >> 2) & 0x07;
			datum(c, frame ? method : method & 0x03);
		}

		/** A frame or target datum: an index for methods 0-2, a frame number for 3, none above. */
		private static void datum(Cursor c, int method) {
			if (method < 3) {
				c.index();
			}
			else if (method == 3) {
				c.skip(2);
			}
		}

		private void mask(int recordOffset, int size) {
			if (lastSegment == null) {
				return;
			}
			if (lastIterated) {
				// Where a fixup lands in expanded iterated data is not worth modelling: none
				// of it is compared.
				for (int i = 0; i < lastLength; i++) {
					fix(lastOffset + i);
				}
				return;
			}
			for (int i = 0; i < Math.max(size, 1); i++) {
				fix(lastOffset + recordOffset + i);
			}
		}

		private void fix(int offset) {
			if (offset >= 0 && offset < lastSegment.fixed().length) {
				lastSegment.fixed()[offset] = true;
			}
		}

		private void put(Segment segment, int offset, byte[] data) {
			if (segment == null) {
				return;
			}
			int n = Math.max(0, Math.min(data.length, segment.data().length - offset));
			System.arraycopy(data, 0, segment.data(), offset, n);
			Arrays.fill(segment.known(), offset, offset + n, true);
		}

		private void remember(Segment segment, int offset, int length, boolean iterated) {
			lastSegment = segment;
			lastOffset = offset;
			lastLength = length;
			lastIterated = iterated;
		}

		private Segment segment(int index) {
			return index >= 1 && index <= segments.size() ? segments.get(index - 1) : null;
		}

		private String name(int index) {
			return index >= 0 && index < names.size() ? names.get(index) : "";
		}
	}

	/** Reads one record's content. */
	private static final class Cursor {
		private final byte[] bytes;
		private int at;
		private final int end;

		Cursor(byte[] bytes, int at, int end) {
			this.bytes = bytes;
			this.at = at;
			this.end = end;
		}

		boolean more() {
			return at < end;
		}

		int u8() {
			return at < end ? bytes[at++] & 0xff : 0;
		}

		int u16() {
			return u8() | (u8() << 8);
		}

		long u32() {
			return u16() | ((long) u16() << 16);
		}

		void skip(int n) {
			at = Math.min(end, at + n);
		}

		int index() {
			int b = u8();
			return (b & 0x80) == 0 ? b : ((b & 0x7f) << 8) | u8();
		}

		String name() {
			int length = u8();
			int n = Math.min(length, end - at);
			String name = new String(bytes, at, n, StandardCharsets.ISO_8859_1);
			at += n;
			return name;
		}

		byte[] rest() {
			byte[] rest = Arrays.copyOfRange(bytes, at, end);
			at = end;
			return rest;
		}
	}

	private static final class ByteSink {
		private byte[] buffer = new byte[64];
		private int size;

		void add(int b) {
			if (size == buffer.length) {
				buffer = Arrays.copyOf(buffer, size * 2);
			}
			buffer[size++] = (byte) b;
		}

		void addAll(byte[] bytes) {
			for (byte b : bytes) {
				add(b);
			}
		}

		int size() {
			return size;
		}

		byte[] toArray() {
			return Arrays.copyOf(buffer, size);
		}
	}

	private static int u16(byte[] b, int at) {
		return (b[at] & 0xff) | ((b[at + 1] & 0xff) << 8);
	}
}
