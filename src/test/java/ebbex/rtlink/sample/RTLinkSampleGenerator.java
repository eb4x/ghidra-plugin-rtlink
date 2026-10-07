package ebbex.rtlink.sample;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Generates {@code src/test/smoke/rtlink-sample.exe}, the committed sample the smoke test
 * imports: a small MZ executable laid out like an RTLink/Plus VM program, with a resident
 * image and three overlay page records chained past the MZ image end.
 * <p>
 * Every byte is written here; nothing comes from Pocket Soft. The sample is for static
 * analysis only: the dispatcher is a placeholder with the shape of the VM nucleus' constant-pair
 * dispatch, not an overlay manager, so the program does not run under DOS. It deliberately
 * carries neither the RTLink error text nor the runtime fixup-loop fingerprint: detection is
 * structural, and those two signatures only decide which blocks the DS assumption skips (covered
 * by {@code RTLinkRuntimeDataSegmentTest}).
 * <p>
 * What each part exercises:
 * <ul>
 * <li>{@code TEXT}: the {@code $$VM_INITW}-shaped entry stub and a startup that loads DGROUP
 *     (entry seeding, DS assumption); DS-relative and address-of references into BSS (xrefs);
 *     a float routine written for the emulator, {@code INT 34h}-{@code 3Dh} (emulated float);
 *     an abort reached through a code vector and a call to it with a zeroed table behind
 *     (flow repair).</li>
 * <li>{@code NUC}: the dispatch stubs, both the 12- and the 14-byte form, two resident-target
 *     trampolines, and a dispatcher ending in the constant-pair dispatch (stub discovery, VM
 *     entry seeding, dispatcher jump).</li>
 * <li>Record 0: a direct list-1 far call into the resident image and a call through a
 *     trampoline. Record 1: two modules, an intra-page far call carrying a list-2 relocation,
 *     and in the second module, which only a 14-byte stub names, a CS-relative switch (module
 *     bases, switch table and override). Record 2: an overlay-to-overlay call through a
 *     stub.</li>
 * </ul>
 * Run {@code ./gradlew generateSmokeSample} after changing this class; {@code
 * RTLinkSampleTest} fails while the committed sample and this generator disagree.
 */
public final class RTLinkSampleGenerator {

	/** Where the sample lives, relative to the project directory. */
	public static final String SAMPLE_PATH = "src/test/smoke/rtlink-sample.exe";

	/** Page frame size in paragraphs written into every record header. */
	public static final int FRAME_SIZE = 0x100;

	/** Size of initialized DGROUP; BSS (the MZ minimum allocation) starts right after it. */
	private static final int DGROUP_INIT_SIZE = 0x20;
	private static final int BSS_PARAGRAPHS = 0x20;
	private static final int STACK_TOP = 0x0200;

	/** DGROUP offsets of the BSS globals the code references. */
	public static final int G_COUNT = 0x0020;
	public static final int G_FLAG = 0x0022;
	public static final int G_VALUE = 0x0024;
	public static final int G_BUFFER = 0x0030;

	/** Emulator-call blocks in the float routine; six calls each. */
	private static final int FLOAT_REPEATS = 6;

	/** Paragraph where the MZ load module begins; header plus relocation table fit below it. */
	private static final int HEADER_PARAGRAPHS = 8;
	private static final int RELOC_TABLE_OFFSET = 0x40;

	private RTLinkSampleGenerator() {
	}

	public static void main(String[] args) throws IOException {
		Path out = Path.of(args.length > 0 ? args[0] : SAMPLE_PATH);
		Files.createDirectories(out.toAbsolutePath().getParent());
		Files.write(out, generate());
		System.out.println("wrote " + out);
	}

	/** The sample's bytes. Deterministic: the same generator always yields the same file. */
	public static byte[] generate() {
		Code text = new Code("TEXT");
		Code nuc = new Code("NUC");
		Code dgroup = new Code("DGROUP");
		Code rec0 = new Code("REC0");
		Code rec1a = new Code("REC1.M0");
		Code rec1b = new Code("REC1.M1");
		Code rec2 = new Code("REC2");

		emitText(text, nuc, dgroup);
		emitNucleus(nuc, text);
		emitDgroup(dgroup);
		emitRecord0(rec0, text, nuc);
		emitRecord1(rec1a, rec1b);
		emitRecord2(rec2, nuc);

		List<Code> resident = List.of(text, nuc, dgroup);
		List<Page> pages = List.of(new Page(rec0), new Page(rec1a, rec1b), new Page(rec2));
		return link(resident, pages);
	}

	// ---------------------------------------------------------------- resident image

	private static void emitText(Code t, Code nuc, Code dgroup) {
		// The $$VM_INITW-shaped entry: CALLF <init body> ; JMPF <startup>.
		t.label("entry");
		t.far(0x9A, nuc, "vm_init");
		t.far(0xEA, t, "startup");

		t.label("startup");
		t.op(0xB8).seg(dgroup);                      // MOV AX,DGROUP
		t.op(0x8E, 0xD8);                            // MOV DS,AX
		t.op(0x8E, 0xD0);                            // MOV SS,AX
		t.op(0xBC).word(STACK_TOP);                  // MOV SP,STACK_TOP
		t.op(0xE8).rel16("main");                    // CALL main
		t.op(0xB8).word(0x4C00);                     // MOV AX,0x4C00
		t.op(0xCD, 0x21);                            // INT 21h

		t.label("main");
		t.op(0x55);                                  // PUSH BP
		t.op(0x8B, 0xEC);                            // MOV BP,SP
		t.op(0xA1).word(G_COUNT);                    // MOV AX,[g_count]
		t.op(0x40);                                  // INC AX
		t.op(0xA3).word(G_COUNT);                    // MOV [g_count],AX
		t.op(0x68).word(G_BUFFER);                   // PUSH g_buffer   (address-of)
		t.op(0x59);                                  // POP CX
		t.far(0x9A, nuc, "stub0");                   // CALLF stub0 -> record 0
		t.far(0x9A, nuc, "stub1");                   // CALLF stub1 -> record 1, module 0
		t.far(0x9A, nuc, "stub3");                   // CALLF stub3 -> record 2
		t.op(0xE8).rel16("fpu");                     // CALL fpu
		t.op(0x83, 0x3E).word(G_FLAG).op(0x00);      // CMP word ptr [g_flag],0
		t.op(0x75).rel8("fail");                     // JNZ fail
		t.op(0x5D);                                  // POP BP
		t.op(0xC3);                                  // RET

		// The abort path: the call cannot return, and the bytes behind it are a table.
		t.label("fail");
		t.far(0x9A, t, "abort");                     // CALLF abort
		t.label("handler_table");
		t.zeros(16);

		t.label("abort");
		t.op(0x2E, 0xFF, 0x2E).off16("abort_vector"); // JMP FAR CS:[abort_vector]
		t.label("abort_handler");
		t.op(0xB8).word(0x4C01);                     // MOV AX,0x4C01
		t.op(0xCD, 0x21);                            // INT 21h
		t.label("abort_vector");
		t.farPointer(t, "abort_handler");

		// A float routine as an emulator-model compiler emits it: each ESC n becomes INT 34h+n.
		t.label("fpu");
		t.op(0x55);                                  // PUSH BP
		t.op(0x8B, 0xEC);                            // MOV BP,SP
		t.op(0x83, 0xEC, 0x10);                      // SUB SP,0x10
		for (int i = 0; i < FLOAT_REPEATS; i++) {
			t.op(0xCD, 0x39, 0x46, 0xF8);            // FLD qword ptr [BP-8]
			t.op(0xCD, 0x38, 0x46, 0xF0);            // FADD qword ptr [BP-16]
			t.op(0xCD, 0x39, 0x5E, 0xF8);            // FSTP qword ptr [BP-8]
			t.op(0xCD, 0x39, 0x46, 0xF0);            // FLD qword ptr [BP-16]
			t.op(0xCD, 0x3A, 0xD9);                  // FCOMPP
			t.op(0xCD, 0x39, 0x7E, 0xFE);            // FSTSW word ptr [BP-2]
		}
		t.op(0xC4, 0x5E, 0x04);                      // LES BX,[BP+4]
		t.op(0xCD, 0x3C, 0xDD, 0x07);                // FLD qword ptr ES:[BX]  (INT 3Ch form)
		t.op(0xCD, 0x3D);                            // FWAIT                  (INT 3Dh)
		t.op(0x8B, 0xE5);                            // MOV SP,BP
		t.op(0x5D);                                  // POP BP
		t.op(0xC3);                                  // RET

		// Resident routines reached from overlay code: one by a direct far call, one only
		// through a trampoline.
		t.label("res_fn");
		t.op(0x55);                                  // PUSH BP
		t.op(0x8B, 0xEC);                            // MOV BP,SP
		t.op(0x8B, 0x46, 0x06);                      // MOV AX,[BP+6]
		t.op(0x5D);                                  // POP BP
		t.op(0xCB);                                  // RETF
		t.label("res_fn2");
		t.op(0xB8).word(0x0001);                     // MOV AX,1
		t.op(0xCB);                                  // RETF
	}

	private static void emitNucleus(Code n, Code text) {
		// The stub table first. Each 12-byte stub is followed by another dispatcher CALLF,
		// which is what tells it apart from the 14-byte form.
		n.label("stub0");
		stub(n, 1, "ovl0_main", false);
		n.label("stub1");
		stub(n, 2, "ovl1_a", false);
		n.label("stub2");
		stub(n, 2, "ovl1_b", true);                  // 14-byte: module 1 of record 1
		n.label("stub3");
		stub(n, 3, "ovl2_fn", false);
		n.label("tramp0");
		n.far(0x9A, n, "dispatcher");
		n.far(0xEA, text, "res_fn");
		n.label("tramp1");
		n.far(0x9A, n, "dispatcher");
		n.far(0xEA, text, "res_fn2");

		// A placeholder dispatcher ending in the nucleus' constant-pair dispatch.
		n.label("dispatcher");
		n.op(0x8B, 0xF4);                            // MOV SI,SP
		n.op(0x83, 0xC6, 0x04);                      // ADD SI,4
		n.op(0xB8).off16("vm_call");                 // MOV AX,vm_call
		n.op(0xBA).off16("vm_call_body");            // MOV DX,vm_call_body
		n.op(0x2E, 0xF6, 0x06).off16("vm_flag").op(0xFF); // TEST byte ptr CS:[vm_flag],0xFF
		n.op(0x74, 0x06);                            // JZ +6
		n.op(0xB8).off16("vm_callr");                // MOV AX,vm_callr
		n.op(0xBA).off16("vm_callr_body");           // MOV DX,vm_callr_body
		n.op(0x89, 0x44, 0xFC);                      // MOV [SI-4],AX   (return-slot patch)
		n.op(0xFF, 0xE2);                            // JMP DX

		n.label("vm_call");
		n.op(0x55);                                  // PUSH BP
		n.op(0x8B, 0xEC);                            // MOV BP,SP
		n.label("vm_call_body");
		n.op(0x5D);                                  // POP BP
		n.op(0xCB);                                  // RETF
		n.label("vm_callr");
		n.op(0x55);                                  // PUSH BP
		n.op(0x8B, 0xEC);                            // MOV BP,SP
		n.label("vm_callr_body");
		n.op(0x33, 0xC0);                            // XOR AX,AX
		n.op(0x5D);                                  // POP BP
		n.op(0xCB);                                  // RETF

		n.label("vm_init");
		n.op(0x33, 0xC0);                            // XOR AX,AX
		n.op(0xCB);                                  // RETF

		n.label("vm_flag");
		n.op(0x00);
	}

	/**
	 * A dispatch stub: {@code CALLF dispatcher ; JMPF 0000:offset ; dw page_id [; dw module]}.
	 * The 14-byte form ({@code moduleWord}) names the target module's base paragraph, and its
	 * JMPF offset is relative to that module; the 12-byte form targets module 0.
	 */
	private static void stub(Code n, int pageId, String target, boolean moduleWord) {
		n.far(0x9A, n, "dispatcher");
		n.op(0xEA).moduleOff16(target).word(0x0000);
		n.word(pageId);
		if (moduleWord) {
			n.moduleBase(target);
		}
	}

	private static void emitDgroup(Code d) {
		byte[] text = "rtlink sample: analysis only".getBytes(StandardCharsets.US_ASCII);
		d.bytes(text);
		d.zeros(DGROUP_INIT_SIZE - text.length);
	}

	// ---------------------------------------------------------------- overlay records

	private static void emitRecord0(Code r, Code text, Code nuc) {
		r.label("ovl0_main");
		r.op(0x55);                                  // PUSH BP
		r.op(0x8B, 0xEC);                            // MOV BP,SP
		r.op(0xA1).word(G_FLAG);                     // MOV AX,[g_flag]
		r.op(0x50);                                  // PUSH AX
		r.far(0x9A, text, "res_fn");                 // CALLF res_fn       (list 1)
		r.op(0x83, 0xC4, 0x02);                      // ADD SP,2
		r.far(0x9A, nuc, "tramp1");                  // CALLF tramp1       (list 1)
		r.op(0xA3).word(G_VALUE);                    // MOV [g_value],AX
		r.op(0x5D);                                  // POP BP
		r.op(0xCB);                                  // RETF
	}

	private static void emitRecord1(Code m0, Code m1) {
		m0.label("ovl1_a");
		m0.op(0x55);                                 // PUSH BP
		m0.op(0x8B, 0xEC);                           // MOV BP,SP
		m0.op(0xB8).word(0x0002);                    // MOV AX,2
		m0.op(0x50);                                 // PUSH AX
		m0.far(0x9A, m1, "ovl1_b");                  // CALLF ovl1_b       (list 2)
		m0.op(0x83, 0xC4, 0x02);                     // ADD SP,2
		m0.op(0x5D);                                 // POP BP
		m0.op(0xCB);                                 // RETF

		// A switch whose table is module-relative: CS is the page frame plus this
		// module's base paragraph, which only the 14-byte stub names.
		m1.label("ovl1_b");
		m1.op(0x55);                                 // PUSH BP
		m1.op(0x8B, 0xEC);                           // MOV BP,SP
		m1.op(0x8B, 0x46, 0x06);                     // MOV AX,[BP+6]
		m1.op(0x3D).word(0x0003);                    // CMP AX,3
		m1.op(0x77).rel8("default");                 // JA default
		m1.op(0xD1, 0xE0);                           // SHL AX,1
		m1.op(0x93);                                 // XCHG AX,BX
		m1.op(0x2E, 0xFF, 0xA7).off16("table");      // JMP word ptr CS:[BX+table]
		m1.label("table");
		m1.off16("case0").off16("case1").off16("case2").off16("case3");
		for (int i = 0; i < 4; i++) {
			m1.label("case" + i);
			m1.op(0xB8).word(10 * (i + 1));          // MOV AX,10*(i+1)
			m1.op(0xEB).rel8("done");                // JMP done
		}
		m1.label("default");
		m1.op(0x33, 0xC0);                           // XOR AX,AX
		m1.label("done");
		m1.op(0x5D);                                 // POP BP
		m1.op(0xCB);                                 // RETF
	}

	private static void emitRecord2(Code r, Code nuc) {
		r.label("ovl2_fn");
		r.op(0x55);                                  // PUSH BP
		r.op(0x8B, 0xEC);                            // MOV BP,SP
		r.far(0x9A, nuc, "stub2");                   // CALLF stub2        (list 1)
		r.op(0xA1).word(G_VALUE);                    // MOV AX,[g_value]
		r.op(0x5D);                                  // POP BP
		r.op(0xCB);                                  // RETF
	}

	// ---------------------------------------------------------------- linking

	private static byte[] link(List<Code> resident, List<Page> pages) {
		// Resident segments, paragraph-aligned in load-module order.
		int paragraph = 0;
		for (Code segment : resident) {
			segment.paragraph = paragraph;
			paragraph += paragraphs(segment.size());
		}
		int imageSize = paragraph * 16;
		for (Page page : pages) {
			int base = 0;
			for (Code module : page.modules) {
				module.page = page;
				module.paragraph = base;
				base += paragraphs(module.size());
			}
		}

		Map<String, Code> owners = new HashMap<>();
		for (Code code : concat(resident, pages)) {
			for (String label : code.labels.keySet()) {
				if (owners.put(label, code) != null) {
					throw new IllegalStateException("duplicate label " + label);
				}
			}
		}

		List<int[]> mzRelocs = new ArrayList<>();
		for (Code code : concat(resident, pages)) {
			code.resolve(owners);
			for (int site : code.segmentSites) {
				if (code.page == null) {
					mzRelocs.add(new int[] { site, code.paragraph });
				}
			}
		}

		ByteArrayOutputStream image = new ByteArrayOutputStream();
		for (Code segment : resident) {
			if (segment != resident.get(0)) {
				segment.checkNoFarReturnNearStart();
			}
			image.writeBytes(pad(segment.bytes(), paragraphs(segment.size()) * 16));
		}

		int headerSize = HEADER_PARAGRAPHS * 16;
		if (RELOC_TABLE_OFFSET + 4 * mzRelocs.size() > headerSize) {
			throw new IllegalStateException("relocation table does not fit the header");
		}
		int fileImageEnd = headerSize + imageSize;
		Code dgroup = resident.get(resident.size() - 1);

		Bytes header = new Bytes();
		header.word(0x5A4D);                                // e_magic "MZ"
		header.word(fileImageEnd % 512);                    // e_cblp
		header.word((fileImageEnd + 511) / 512);            // e_cp
		header.word(mzRelocs.size());                       // e_crlc
		header.word(HEADER_PARAGRAPHS);                     // e_cparhdr
		header.word(BSS_PARAGRAPHS);                        // e_minalloc
		header.word(0xFFFF);                                // e_maxalloc
		header.word(dgroup.paragraph);                      // e_ss
		header.word(STACK_TOP);                             // e_sp
		header.word(0);                                     // e_csum
		header.word(resident.get(0).labels.get("entry"));  // e_ip
		header.word(resident.get(0).paragraph);             // e_cs
		header.word(RELOC_TABLE_OFFSET);                    // e_lfarlc
		header.word(0);                                     // e_ovno
		header.zerosTo(RELOC_TABLE_OFFSET);                 // no e_lfanew: a plain MZ
		for (int[] reloc : mzRelocs) {
			header.word(reloc[0]);                          // offset within its segment
			header.word(reloc[1]);                          // segment, load-module relative
		}
		header.zerosTo(headerSize);

		ByteArrayOutputStream file = new ByteArrayOutputStream();
		file.writeBytes(header.toArray());
		file.writeBytes(image.toByteArray());
		for (Page page : pages) {
			file.writeBytes(page.record());
		}
		return file.toByteArray();
	}

	private static List<Code> concat(List<Code> resident, List<Page> pages) {
		List<Code> all = new ArrayList<>(resident);
		pages.forEach(page -> all.addAll(page.modules));
		return all;
	}

	private static int paragraphs(int bytes) {
		return (bytes + 15) / 16;
	}

	private static byte[] pad(byte[] bytes, int length) {
		return Arrays.copyOf(bytes, length);
	}

	/** One overlay record: its modules, paragraph-aligned, after a header and two lists. */
	private static final class Page {
		final List<Code> modules;

		Page(Code... modules) {
			this.modules = List.of(modules);
		}

		byte[] record() {
			// List 1: resident segment words in the page. List 2: page-relative paragraphs
			// (intra-page far calls). Each entry is (offset, seg_index) with the site at
			// page-linear seg_index*16 + offset; seg_index here is the module's base.
			List<int[]> list1 = new ArrayList<>();
			List<int[]> list2 = new ArrayList<>();
			for (Code module : modules) {
				for (int i = 0; i < module.segmentSites.size(); i++) {
					int[] entry = { module.segmentSites.get(i), module.paragraph };
					(module.segmentSiteIntraPage.get(i) ? list2 : list1).add(entry);
				}
			}

			int list2Index = (list1.size() + 3) & ~3;
			int overheadBytes = 16 + (list2Index + list2.size()) * 4;
			int overhead = paragraphs(overheadBytes);

			ByteArrayOutputStream code = new ByteArrayOutputStream();
			for (Code module : modules) {
				code.writeBytes(pad(module.bytes(), paragraphs(module.size()) * 16));
			}
			int total = overhead + paragraphs(code.size());

			Bytes record = new Bytes();
			record.word(total);
			record.word(overhead);
			record.word(FRAME_SIZE);
			record.word(0);                                 // reloc_start_index
			record.word(list1.size());
			record.word(list2.size());
			record.word(0);                                 // reloc_count_3
			record.word(0);                                 // codeview_word
			list1.forEach(e -> record.word(e[0]).word(e[1]));
			record.zerosTo(16 + list2Index * 4);
			list2.forEach(e -> record.word(e[0]).word(e[1]));
			record.zerosTo(overhead * 16);
			record.bytes(pad(code.toByteArray(), (total - overhead) * 16));
			return record.toArray();
		}
	}

	/** A little-endian byte buffer. */
	private static class Bytes {
		private final ByteArrayOutputStream out = new ByteArrayOutputStream();

		Bytes op(int... values) {
			for (int value : values) {
				out.write(value);
			}
			return this;
		}

		Bytes word(int value) {
			out.write(value & 0xff);
			out.write((value >> 8) & 0xff);
			return this;
		}

		Bytes bytes(byte[] values) {
			out.writeBytes(values);
			return this;
		}

		Bytes zeros(int count) {
			out.writeBytes(new byte[count]);
			return this;
		}

		void zerosTo(int length) {
			if (out.size() > length) {
				throw new IllegalStateException("overflow past " + length);
			}
			zeros(length - out.size());
		}

		int size() {
			return out.size();
		}

		byte[] toArray() {
			return out.toByteArray();
		}
	}

	/**
	 * A resident segment or a page module: bytes, labels, and the fixups that need the
	 * layout. Offsets are always relative to this segment or module, which is also what
	 * CS-relative tables and near flow inside it are relative to.
	 */
	private static final class Code extends Bytes {
		final String name;
		final Map<String, Integer> labels = new LinkedHashMap<>();
		final List<Fixup> fixups = new ArrayList<>();
		/** Sites of segment words that need a relocation (MZ, list 1 or list 2). */
		final List<Integer> segmentSites = new ArrayList<>();
		final List<Boolean> segmentSiteIntraPage = new ArrayList<>();
		Page page;
		int paragraph;
		private byte[] resolved;

		Code(String name) {
			this.name = name;
		}

		@Override
		Code op(int... values) {
			super.op(values);
			return this;
		}

		@Override
		Code word(int value) {
			super.word(value);
			return this;
		}

		void label(String label) {
			if (labels.put(label, size()) != null) {
				throw new IllegalStateException(name + ": duplicate label " + label);
			}
		}

		/** A rel8 displacement to {@code label} in this code. */
		Code rel8(String label) {
			fixups.add(new Fixup(Kind.REL8, size(), null, label));
			return op(0);
		}

		/** A rel16 displacement to {@code label} in this code. */
		Code rel16(String label) {
			fixups.add(new Fixup(Kind.REL16, size(), null, label));
			return word(0);
		}

		/** {@code label}'s offset within this segment or module. */
		Code off16(String label) {
			fixups.add(new Fixup(Kind.OFF16, size(), null, label));
			return word(0);
		}

		/** {@code label}'s offset within whichever module defines it. */
		Code moduleOff16(String label) {
			fixups.add(new Fixup(Kind.MODULE_OFF16, size(), null, label));
			return word(0);
		}

		/** The base paragraph, within its page, of the module that defines {@code label}. */
		Code moduleBase(String label) {
			fixups.add(new Fixup(Kind.MODULE_BASE, size(), null, label));
			return word(0);
		}

		/** A segment word naming {@code target}, with the relocation it needs. */
		Code seg(Code target) {
			fixups.add(new Fixup(Kind.SEGMENT, size(), target, null));
			return word(0);
		}

		/** {@code opcode} followed by a far pointer to {@code label} in {@code target}. */
		Code far(int opcode, Code target, String label) {
			op(opcode);
			return farPointer(target, label);
		}

		/** A far pointer (offset, segment) to {@code label} in {@code target}. */
		Code farPointer(Code target, String label) {
			fixups.add(new Fixup(Kind.FAR_OFFSET, size(), target, label));
			word(0);
			return seg(target);
		}

		void resolve(Map<String, Code> owners) {
			byte[] bytes = toArray();
			for (Fixup fixup : fixups) {
				Code owner = fixup.label == null ? null : owners.get(fixup.label);
				if (fixup.label != null && owner == null) {
					throw new IllegalStateException(name + ": undefined label " + fixup.label);
				}
				int value = switch (fixup.kind) {
					case REL8 -> local(fixup.label) - (fixup.site + 1);
					case REL16 -> local(fixup.label) - (fixup.site + 2);
					case OFF16 -> local(fixup.label);
					case MODULE_OFF16 -> owner.labels.get(fixup.label);
					case MODULE_BASE -> owner.paragraph;
					case FAR_OFFSET -> fixup.target.labels.get(fixup.label);
					case SEGMENT -> segment(fixup);
				};
				if (fixup.kind == Kind.REL8) {
					if (value < -128 || value > 127) {
						throw new IllegalStateException(name + ": rel8 out of range " + fixup);
					}
					bytes[fixup.site] = (byte) value;
				}
				else {
					bytes[fixup.site] = (byte) value;
					bytes[fixup.site + 1] = (byte) (value >> 8);
				}
			}
			resolved = bytes;
		}

		private int segment(Fixup fixup) {
			Code target = fixup.target;
			boolean intraPage = page != null && target.page == page;
			if (target.page != null && !intraPage) {
				throw new IllegalStateException(name + ": far pointer into another page");
			}
			segmentSites.add(fixup.site);
			segmentSiteIntraPage.add(intraPage);
			return target.paragraph;
		}

		private int local(String label) {
			Integer offset = labels.get(label);
			if (offset == null) {
				throw new IllegalStateException(name + ": " + label + " is not local");
			}
			return offset;
		}

		byte[] bytes() {
			return resolved;
		}

		/**
		 * MzLoader moves the start of every block but the first when a RETF (0xCB) sits in
		 * its first 16 bytes, which would shift this segment's block boundary.
		 */
		void checkNoFarReturnNearStart() {
			for (int i = 0; i < Math.min(16, resolved.length); i++) {
				if ((resolved[i] & 0xff) == 0xCB) {
					throw new IllegalStateException(name + ": 0xCB at +" + i);
				}
			}
		}
	}

	private enum Kind {
		REL8, REL16, OFF16, MODULE_OFF16, MODULE_BASE, FAR_OFFSET, SEGMENT
	}

	private record Fixup(Kind kind, int site, Code target, String label) {
	}
}
