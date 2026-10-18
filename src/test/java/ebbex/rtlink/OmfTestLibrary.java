package ebbex.rtlink;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Writes small OMF-86 object modules and libraries for the tests: one code segment per
 * module, its bytes in one LEDATA, public symbols, and 16-bit offset fixups. Every byte is
 * ours; nothing comes from a vendor library.
 */
final class OmfTestLibrary {

	/** One module: a segment's bytes, its publics (name, offset) and fixed-up word offsets. */
	static final class ModuleSpec {
		final String name;
		final byte[] code;
		final List<String> publicNames = new ArrayList<>();
		final List<Integer> publicOffsets = new ArrayList<>();
		final List<Integer> fixups = new ArrayList<>();
		final List<Integer> extraTypes = new ArrayList<>();
		final List<byte[]> extraContents = new ArrayList<>();

		ModuleSpec(String name, String hex) {
			this.name = name;
			this.code = HexFormat.of().parseHex(hex.replace(" ", ""));
		}

		ModuleSpec pub(String symbol, int offset) {
			publicNames.add(symbol);
			publicOffsets.add(offset);
			return this;
		}

		ModuleSpec fixup(int offset) {
			fixups.add(offset);
			return this;
		}

		/** A raw record of {@code type}, written after the module's own data and fixups. */
		ModuleSpec record(int type, String hex) {
			extraTypes.add(type);
			extraContents.add(HexFormat.of().parseHex(hex.replace(" ", "")));
			return this;
		}
	}

	private OmfTestLibrary() {
	}

	/** A library: LIBHDR with 16-byte pages, each module page-aligned, LIBEND. */
	static byte[] library(ModuleSpec... modules) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int page = 16;
		record(out, 0xf0, new byte[page - 4]); // header content padded to one page
		for (ModuleSpec module : modules) {
			byte[] bytes = module(module);
			out.writeBytes(bytes);
			pad(out, page);
		}
		record(out, 0xf1, new byte[0]);
		return out.toByteArray();
	}

	static byte[] module(ModuleSpec spec) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		record(out, 0x80, name(spec.name));
		ByteArrayOutputStream names = new ByteArrayOutputStream();
		names.writeBytes(name(""));
		names.writeBytes(name("TEST_TEXT"));
		names.writeBytes(name("CODE"));
		record(out, 0x96, names.toByteArray()); // indexes 1 "", 2 TEST_TEXT, 3 CODE
		record(out, 0x98, new byte[] { 0x68, (byte) spec.code.length, (byte) (spec.code.length >> 8),
			2, 3, 1 });
		ByteArrayOutputStream pubdef = new ByteArrayOutputStream();
		pubdef.write(0); // group
		pubdef.write(1); // segment
		for (int i = 0; i < spec.publicNames.size(); i++) {
			pubdef.writeBytes(name(spec.publicNames.get(i)));
			int offset = spec.publicOffsets.get(i);
			pubdef.write(offset);
			pubdef.write(offset >> 8);
			pubdef.write(0); // type
		}
		record(out, 0x90, pubdef.toByteArray());
		ByteArrayOutputStream ledata = new ByteArrayOutputStream();
		ledata.write(1);
		ledata.write(0);
		ledata.write(0);
		ledata.writeBytes(spec.code);
		record(out, 0xa0, ledata.toByteArray());
		if (!spec.fixups.isEmpty()) {
			ByteArrayOutputStream fixupp = new ByteArrayOutputStream();
			for (int offset : spec.fixups) {
				// LOCAT: fixup, segment-relative, 16-bit offset; FIXDAT: target's frame (F5),
				// target given by segment index (T0), no displacement; target datum: segment 1.
				fixupp.write(0x80 | 0x40 | (1 << 2) | ((offset >> 8) & 3));
				fixupp.write(offset);
				fixupp.write(0x54);
				fixupp.write(1);
			}
			record(out, 0x9c, fixupp.toByteArray());
		}
		for (int i = 0; i < spec.extraTypes.size(); i++) {
			record(out, spec.extraTypes.get(i), spec.extraContents.get(i));
		}
		record(out, 0x8a, new byte[] { 0 });
		return out.toByteArray();
	}

	private static void record(ByteArrayOutputStream out, int type, byte[] content) {
		int length = content.length + 1;
		byte[] header = { (byte) type, (byte) length, (byte) (length >> 8) };
		int sum = 0;
		for (byte b : header) {
			sum += b & 0xff;
		}
		for (byte b : content) {
			sum += b & 0xff;
		}
		out.writeBytes(header);
		out.writeBytes(content);
		out.write((-sum) & 0xff);
	}

	private static byte[] name(String name) {
		byte[] bytes = name.getBytes(StandardCharsets.ISO_8859_1);
		byte[] out = new byte[bytes.length + 1];
		out[0] = (byte) bytes.length;
		System.arraycopy(bytes, 0, out, 1, bytes.length);
		return out;
	}

	private static void pad(ByteArrayOutputStream out, int page) {
		while (out.size() % page != 0) {
			out.write(0);
		}
	}
}
