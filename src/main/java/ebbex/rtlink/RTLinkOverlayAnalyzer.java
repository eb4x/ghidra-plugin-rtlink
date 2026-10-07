package ebbex.rtlink;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MzLoader;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Detects and loads RTLink/Plus overlay pages from DOS MZ executables.
 * <p>
 * RTLink/Plus was a widely-used overlay manager for late-DOS commercial
 * software (Microprose, Sierra, etc.). Overlay pages are stored at file offsets
 * past the MZ image end and are invisible to {@link MzLoader}'s static
 * analysis. This analyzer creates overlay memory blocks for each page, applies
 * segment relocations, and wires cross-references from dispatch stubs to
 * overlay functions.
 * <p>
 * Dispatch stubs are 12- or 14-byte sequences: {@code CALLF seg:0DAB} (5 bytes) +
 * {@code JMPF 0000:offset} (5 bytes) + page_id (2 bytes) + an optional module_word
 * (2 bytes). Bits 0-13 of page_id hold a 1-based descriptor index into the overlay
 * descriptor table; descriptor index N is overlay record N - 1, so page_id 1 targets
 * record 0. Record 0 is a real code page like the rest (in VICEROY.EXE it holds 15.6KB
 * of code, with its own relocations and 47 stubs targeting it); an earlier revision
 * assumed it was a non-code "global overlay table" and silently dropped every stub
 * aimed at it.
 * <p>
 * Pages contain multiple link-time modules, each with its own segment base
 * (CS = page frame + module base paragraph), so the JMPF offset is
 * module-relative. 12-byte stubs target module 0 (JMPF offset = in-page code
 * offset); 14-byte stubs carry the target module's base paragraph in module_word,
 * and the in-page code offset is {@code JMPF offset + module_word * 16}. See
 * {@link #scanForJmpfStubs} for how the two forms are told apart.
 * <p>
 * The same jump table also holds 10-byte <em>resident-target trampolines</em>:
 * {@code CALLF seg:disp} + {@code JMPF seg:off} with a real (relocated) target
 * segment. RTLink routes far calls from movable overlay code into resident code
 * through these so the overlay manager can re-vector the caller's far return
 * address if its page moves. Each one is converted into a thunk of its JMPF
 * target; see {@link #scanForResidentTrampolines} for why leaving them as plain
 * functions damages decompilation at every call site.
 */
public class RTLinkOverlayAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Overlay";
	private static final String DESCRIPTION =
		"Detects and loads RTLink/Plus overlay pages from DOS MZ executables. " +
			"Creates overlay memory blocks, applies segment relocations, and " +
			"creates cross-references from dispatch stubs to overlay functions.";
	/**
	 * PROGRAM_INFO property set when overlay analysis completes; gates
	 * {@link RTLinkXrefAnalyzer}'s far call/jump pass.
	 */
	static final String ANALYZED_FLAG = "RTLink Overlay Analyzed";
	/** PROGRAM_INFO property set once DS (DGROUP) has been assumed, so re-runs don't redo it. */
	static final String DS_ASSUMED_FLAG = "RTLink Data Segment Assumed";

	/**
	 * Program-info key prefix, completed with an overlay block's name, recording the
	 * page's module base paragraphs as comma-separated hex — the anchor points that
	 * CS-relative displacements in module code are relative to. Read back by
	 * {@link RTLinkSwitchTableAnalyzer} to resolve overlay switch tables.
	 */
	static final String MODULE_BASES_PREFIX = "RTLink Module Bases ";

	private static final int INITIAL_SEGMENT_VAL = 0x1000;

	static final byte OPCODE_CALLF = (byte) 0x9A;
	static final byte OPCODE_JMPF = (byte) 0xEA;
	private static final int PAGE_ID_MASK = 0x3FFF;

	// Far calling convention (x86-16.cspec: extrapop=4, stackshift=4) stamped on every
	// stub/trampoline target so thunk call sites model the far return address and decode
	// their arguments at the correct stack offsets.
	private static final String FAR_CALLING_CONVENTION = "__cdecl16far";

	// A real overlay dispatcher is the CALLF target shared by many stubs. Any
	// physical address hit by at least this many CALLF+JMPF stub candidates is
	// treated as a dispatcher, replacing the old hardcoded 0x0DAB dispatch offset
	// so the analyzer adapts to binaries linked with the dispatcher elsewhere.
	private static final int MIN_DISPATCHER_STUB_COUNT = 4;

	/**
	 * The overlay manager's relocation fixup loop — a byte-identical blob the linker stamps
	 * into every VM program (see the "Fingerprint" section of {@code docs/rtlink-format.md}).
	 * Used here only to locate the code segment the manager lives in.
	 */
	private static final byte[] RUNTIME_FIXUP_FINGERPRINT = {
		(byte) 0xe3, 0x19, 0x06, 0x57, (byte) 0xd1, (byte) 0xe6, (byte) 0xd1, (byte) 0xe6,
		(byte) 0xad, (byte) 0x8b, (byte) 0xf8, (byte) 0xad, 0x03, (byte) 0xc3, (byte) 0x8e,
		(byte) 0xc0, 0x26, 0x01, 0x15, (byte) 0xe2, (byte) 0xf3, (byte) 0xd1, (byte) 0xee,
		(byte) 0xd1, (byte) 0xee, 0x5f, 0x07, (byte) 0xc3
	};

	/**
	 * The error text the RTLink support code carries in its own code segment. It is what
	 * marks a binary as RTLink at all, and it is present even in section-only binaries that
	 * have no VM manager (and so no {@link #RUNTIME_FIXUP_FINGERPRINT}).
	 */
	private static final byte[] RUNTIME_SIGNATURE =
		"Internal error in .RTLink(R)/Plus run-time code.".getBytes(StandardCharsets.US_ASCII);

	private static final String OPTION_APPLY_RELOCS = "Apply Relocations";
	private static final String OPTION_CREATE_XREFS = "Create Stub Cross-References";
	private static final String OPTION_MARKUP_HEADERS = "Markup Page Headers";
	private static final String OPTION_ASSUME_DS = "Assume Data Segment (DS)";

	/** Max instructions to decode when hunting the DGROUP load in the C startup. */
	private static final int STARTUP_SCAN_LIMIT = 200;

	/**
	 * Bodies of the dispatch stubs/trampolines this run actually resolved — the set that
	 * {@link #analysisEnded} sweeps clean of the disassembler's stale "Bad Instruction"
	 * marks. Analyzer instances are created per program, so this is program-scoped.
	 */
	private AddressSet resolvedStubBodies = new AddressSet();

	private boolean applyRelocations = true;
	private boolean createStubXrefs = true;
	private boolean markupHeaders = true;
	private boolean assumeDataSegment = true;

	private long lastTxId = -1;

	public RTLinkOverlayAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
		// Offer this analyzer in Analysis -> One Shot so it can be re-run on an
		// already-analyzed program to retrofit the assumed data segment (DS/DGROUP)
		// and overlay markup without re-importing.
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isSegmentedMzProgram(program);
	}

	/**
	 * Returns true if {@code program} is an MZ executable with a segmented (16-bit
	 * real mode) default address space — the only programs RTLink overlay analysis
	 * applies to.
	 */
	static boolean isSegmentedMzProgram(Program program) {
		if (!MzLoader.MZ_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		return program.getAddressFactory()
				.getDefaultAddressSpace() instanceof SegmentedAddressSpace;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			return true;
		}
		lastTxId = txId;

		if (isOverlayAnalyzed(program)) {
			// Overlays were processed by a prior run; still retrofit what can be repaired
			// in place on re-analysis so an already-analyzed program benefits without
			// re-importing: disassemble and rebuild "husk" functions whose code the old
			// disassembler abandoned, re-wire dispatch-stub thunks (clearing stale
			// no-return flags that silently truncate every caller's decompilation) and
			// assume DS. Husks first, so the thunk pass finds real code at its targets.
			repairHuskFunctions(program, log, monitor);
			if (createStubXrefs) {
				repairStubThunks(program, log, monitor);
				// Retrofit the VM-runtime entry seeds too: dispatch-stub discovery is a
				// cheap byte scan, and everything seedVmRuntimeEntryPoints does is a
				// no-op where a prior run or hand analysis already claimed the address.
				seedVmRuntimeEntryPoints(program, discoverDispatchers(program, monitor),
					log, monitor);
			}
			maybeAssumeDataSegment(program, log);
			return true;
		}

		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			return false;
		}

		FileBytes fileBytes = allFileBytes.get(0);
		try (FileBytesProvider provider = new FileBytesProvider(fileBytes)) {
			BinaryReader reader = new BinaryReader(provider, true);

			OldDOSHeader header = new OldDOSHeader(reader);
			if (!header.isDosSignature()) {
				return false;
			}

			long imageEnd = computeImageEnd(header);
			long overlayStart = (imageEnd + 15) & ~15L;
			if (overlayStart <= 0 || overlayStart >= fileBytes.getSize()) {
				return false;
			}

			if (!detectRTLinkOverlay(reader, overlayStart, fileBytes.getSize())) {
				return false;
			}

			List<RTLinkOverlayPage> allPages =
				RTLinkOverlayPage.parseAllPages(reader, overlayStart, fileBytes.getSize());
			if (allPages.size() < 2) {
				return false;
			}

			Msg.info(this, String.format(
				"RTLink/Plus: Found %d overlay pages at file offset 0x%X",
				allPages.size(), overlayStart));

			List<OverlayBlockInfo> overlayBlocks =
				createOverlayBlocks(program, fileBytes, allPages, log, monitor);

			if (applyRelocations && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Applying overlay relocations...");
				for (OverlayBlockInfo info : overlayBlocks) {
					monitor.checkCancelled();
					applyOverlayRelocations(program, info.block(), info.page(), log);
				}
			}

			if (createStubXrefs && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Discovering dispatch stubs...");
				discoverAndProcessStubs(program, overlayBlocks, log, monitor);
			}

			if (markupHeaders) {
				monitor.setMessage("RTLink: Marking up page headers...");
				markupOverlayHeaders(program, fileBytes, allPages, log, monitor);
			}

			monitor.setMessage("RTLink: Determining data segment (DGROUP)...");
			maybeAssumeDataSegment(program, log);

			program.getOptions(Program.PROGRAM_INFO).setBoolean(ANALYZED_FLAG, true);
			return true;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendMsg("RTLink: Analysis failed: " + e.getMessage());
			Msg.error(this, "RTLink overlay analysis failed", e);
			return false;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_APPLY_RELOCS, applyRelocations, null,
			"Rebase unrelocated segment words in overlay code by the image base, " +
				"at the sites given by each page's relocation table.");
		options.registerOption(OPTION_CREATE_XREFS, createStubXrefs, null,
			"Discover dispatch stubs and resident-target trampolines; create " +
				"cross-references and thunks to their targets.");
		options.registerOption(OPTION_MARKUP_HEADERS, markupHeaders, null,
			"Create data structures for RTLink page headers in the listing.");
		options.registerOption(OPTION_ASSUME_DS, assumeDataSegment, null,
			"Detect DGROUP from the C startup and assume it for DS over all code, so the " +
				"decompiler resolves DS-relative data accesses (bare offsets like " +
				"*(int *)0x8542) to real addresses.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyRelocations = options.getBoolean(OPTION_APPLY_RELOCS, applyRelocations);
		createStubXrefs = options.getBoolean(OPTION_CREATE_XREFS, createStubXrefs);
		markupHeaders = options.getBoolean(OPTION_MARKUP_HEADERS, markupHeaders);
		assumeDataSegment = options.getBoolean(OPTION_ASSUME_DS, assumeDataSegment);
	}

	// ---- Private implementation ----

	private record OverlayBlockInfo(RTLinkOverlayPage page, MemoryBlock block) {
	}

	/** A resolved dispatch stub awaiting thunk creation once its target is a real function. */
	private record StubTarget(Address stubAddr, Address targetAddr, int stubSize) {
	}

	/**
	 * Digit width used in OVERLAY_/RTLINK_HDR_/OVLSTUB_/OVL numbering: two, or more
	 * once a record index needs it. A fixed {@code %02d} made SPHERE.EXE (105
	 * records) collate OVERLAY_100 before OVERLAY_11 in every sorted listing.
	 */
	private static int nameWidth(int maxRecordIndex) {
		return Math.max(2, String.valueOf(maxRecordIndex).length());
	}

	/** The largest record index among {@code overlayBlocks}. */
	private static int maxRecordIndex(List<OverlayBlockInfo> overlayBlocks) {
		int max = 0;
		for (OverlayBlockInfo info : overlayBlocks) {
			max = Math.max(max, info.page().getPageIndex());
		}
		return max;
	}

	/**
	 * The overlay block holding {@code record}'s code under the current width-padded
	 * naming, or under the fixed-{@code %02d} naming of programs imported before the
	 * width fix, or null.
	 */
	private static MemoryBlock findOverlayBlock(Memory memory, int record, int width) {
		MemoryBlock block =
			memory.getBlock(String.format("OVERLAY_%0" + width + "d", record));
		if (block == null) {
			block = memory.getBlock(String.format("OVERLAY_%02d", record));
		}
		return block;
	}

	/**
	 * True if {@code addr} lies in resident code memory — an initialized, executable,
	 * non-overlay block.
	 * <p>
	 * The scans below iterate blocks but must range-check against <em>memory</em>, not
	 * against the block they happen to be iterating: MZ segment blocks are contiguous in
	 * flat space, and a stub can straddle the boundary between two of them. VMEX1.EXE has
	 * one — its jump table's first stub begins two bytes before the end of the preceding
	 * segment block — and a per-block check silently dropped it, leaving the stub
	 * unresolved and its {@code JMPF 0000:xxxx} to be walked into unmapped memory.
	 */
	private static boolean isCodeMemory(Memory memory, Address addr) {
		MemoryBlock block = memory.getBlock(addr);
		return block != null && !block.isOverlay() && block.isExecute() &&
			block.isInitialized();
	}

	/**
	 * Index {@code overlayBlocks} by overlay record index (= page index). Stub scans
	 * look pages up by record index rather than list position, so a record skipped for
	 * having no code cannot shift every later page onto the wrong block.
	 */
	private static Map<Integer, OverlayBlockInfo> blocksByRecord(
			List<OverlayBlockInfo> overlayBlocks) {
		Map<Integer, OverlayBlockInfo> byRecord = new HashMap<>();
		for (OverlayBlockInfo info : overlayBlocks) {
			byRecord.put(info.page().getPageIndex(), info);
		}
		return byRecord;
	}

	static boolean isOverlayAnalyzed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(ANALYZED_FLAG, false);
	}

	static boolean isDataSegmentAssumed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(DS_ASSUMED_FLAG, false);
	}

	/**
	 * Establish DS if the option is on.
	 *
	 * <p>Runs on every pass rather than once, because it is corrective, not just additive:
	 * a program analyzed by a build that assumed DGROUP over the whole executable image
	 * carries that context in its runtime blocks, and nothing else will ever take it back
	 * out. Re-running is cheap (a bounded PseudoDisassembler walk of the startup) and
	 * idempotent, so Analysis -&gt; One Shot repairs such a program in place, without a
	 * re-import that would cost every name, type and comment already applied to it.
	 */
	private void maybeAssumeDataSegment(Program program, MessageLog log) {
		if (assumeDataSegment) {
			assumeDataSegmentRegister(program, log);
		}
	}

	/**
	 * Establish the data segment (DGROUP) so the decompiler can resolve DS-relative data
	 * accesses. In the small-data DOS model DS == SS == DGROUP, loaded once in the C startup
	 * (e.g. {@code MOV DI,DGROUP; MOV SS,DI; PUSH SS; POP DS}). We follow the entry's initial
	 * far jump into the startup, linearly decode it while tracking register immediates, and
	 * take the value moved into SS/DS as DGROUP. That value is then assumed for DS over all
	 * executable memory; without it every DS-relative global collapses to a bare offset in an
	 * unmapped space (e.g. {@code *(int *)0x8542}) that ignores applied data types.
	 */
	private void assumeDataSegmentRegister(Program program, MessageLog log) {
		Register ds = program.getLanguage().getRegister("DS");
		if (ds == null) {
			return;
		}
		Address entry = firstEntryPoint(program);
		if (entry == null) {
			return;
		}
		Integer dgroup = detectDataSegment(program, entry);
		if (dgroup == null) {
			log.appendMsg("RTLink: could not determine DGROUP from startup; DS left unset");
			return;
		}
		ProgramContext context = program.getProgramContext();
		BigInteger value = BigInteger.valueOf(dgroup & 0xffffL);
		Set<MemoryBlock> runtime = findRuntimeCodeBlocks(program, dgroup);
		int blocks = 0;
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!block.isExecute()) {
					continue;
				}
				if (runtime.contains(block)) {
					// Clear rather than merely skip: an earlier build may have assumed DGROUP
					// over the whole image, and that context would otherwise stay forever.
					context.remove(block.getStart(), block.getEnd(), ds);
					continue;
				}
				context.setValue(ds, block.getStart(), block.getEnd(), value);
				blocks++;
			}
		}
		catch (ContextChangeException e) {
			log.appendMsg("RTLink: failed to assume DS: " + e.getMessage());
			return;
		}
		program.getOptions(Program.PROGRAM_INFO).setBoolean(DS_ASSUMED_FLAG, true);
		// Msg.info only, never log.appendMsg: any content in the analysis MessageLog makes
		// AutoAnalysisPlugin.analysisEnded() pop a "There were warnings/errors issued during
		// analysis" dialog. The MessageLog above is for the paths where DS could not be assumed.
		Msg.info(this, String.format(
			"RTLink: Assuming DS = 0x%04X (DGROUP) over %d executable blocks; skipped %d " +
				"RTLink runtime block(s), where DS is not DGROUP",
			dgroup, blocks, runtime.size()));
	}

	/**
	 * The executable blocks holding the RTLink runtime, which the DS assumption does not
	 * cover.
	 *
	 * <p>{@code DS == DGROUP} is a property of compiler-generated code. The runtime is
	 * hand-written assembly, and it owns DS: the overlay manager reloads it throughout from
	 * its own saved-segment slots (in VICEROY.EXE, {@code MOV DS,word ptr CS:[0x3999]},
	 * {@code CS:[0x39a1]}, {@code CS:[0x39a5]}, and {@code MOV DS,CS} in its error paths),
	 * while the support code addresses every one of its variables CS-relative and never loads
	 * DS at all.
	 *
	 * <p>Leaving DS unset over these blocks is the honest state — we do not know what DS holds
	 * at an arbitrary point in the runtime — and it is what makes {@link RTLinkXrefAnalyzer}
	 * decline them, since both its DS-relative pass and its address-of-immediate pass are gated
	 * on a present DS value. Were DGROUP asserted here instead, a {@code MOV BX,0x44a7} naming
	 * a string in the manager's own segment would resolve to {@code DGROUP:44a7} and plant a
	 * data reference on an unrelated global.
	 *
	 * <p>Both halves of the runtime carry a signature documented in {@code docs/rtlink-format.md}:
	 * the VM manager the fixup-loop fingerprint, the support code the RTLink error text (present
	 * even in section-only binaries, which have no VM manager and so no fingerprint). DGROUP's
	 * own block is never disowned, however those signatures happen to fall.
	 *
	 * <p>Package-private so tests can drive it directly.
	 */
	static Set<MemoryBlock> findRuntimeCodeBlocks(Program program, int dgroup) {
		Memory memory = program.getMemory();
		Set<MemoryBlock> runtime = new HashSet<>();
		for (byte[] signature : List.of(RUNTIME_FIXUP_FINGERPRINT, RUNTIME_SIGNATURE)) {
			Address hit = memory.findBytes(memory.getMinAddress(), signature, null, true,
				TaskMonitor.DUMMY);
			if (hit == null) {
				continue;
			}
			MemoryBlock block = memory.getBlock(hit);
			if (block == null || !block.isExecute()) {
				continue;
			}
			if (block.getStart() instanceof SegmentedAddress start &&
				start.getSegment() == dgroup) {
				continue;
			}
			runtime.add(block);
		}
		return runtime;
	}

	private static Address firstEntryPoint(Program program) {
		AddressIterator it = program.getSymbolTable().getExternalEntryPointIterator();
		return it.hasNext() ? it.next() : null;
	}

	/**
	 * Follow the entry's initial unconditional (far) jump into the C startup, then linearly
	 * decode instructions tracking each general register's last immediate. Returns the segment
	 * value moved into SS or DS (DGROUP), or null if not found within {@link #STARTUP_SCAN_LIMIT}
	 * instructions. Decoding is done with a {@link PseudoDisassembler} so it works before the
	 * program is disassembled and commits nothing.
	 */
	private static Integer detectDataSegment(Program program, Address entry) {
		Register ss = program.getLanguage().getRegister("SS");
		Register ds = program.getLanguage().getRegister("DS");
		PseudoDisassembler disassembler = new PseudoDisassembler(program);

		// Follow the entry's first unconditional jump (entry -> ... -> startup).
		Address addr = entry;
		for (int i = 0; i < 8 && addr != null; i++) {
			PseudoInstruction instr = safeDecode(disassembler, addr);
			if (instr == null) {
				break;
			}
			FlowType flow = instr.getFlowType();
			if (flow.isJump() && !flow.isConditional()) {
				Address[] flows = instr.getFlows();
				if (flows != null && flows.length == 1) {
					addr = flows[0];
					break;
				}
			}
			addr = nextLinear(instr);
		}
		if (addr == null) {
			addr = entry;
		}

		// Linearly decode the startup, watching for the SS/DS segment load.
		Map<Register, Long> regImm = new HashMap<>();
		for (int i = 0; i < STARTUP_SCAN_LIMIT; i++) {
			PseudoInstruction instr = safeDecode(disassembler, addr);
			if (instr == null) {
				return null;
			}
			if ("MOV".equals(instr.getMnemonicString())) {
				Register dest = movDestination(instr);
				if (dest != null && (dest.equals(ss) || dest.equals(ds))) {
					Register src = movSourceRegister(instr);
					Long imm = src != null ? regImm.get(src) : null;
					if (imm != null) {
						return (int) (imm.longValue() & 0xffffL);
					}
				}
				else if (dest != null) {
					int type = instr.getOperandType(1);
					Register src = movSourceRegister(instr);
					Scalar scalar = instr.getScalar(1);
					if (scalar != null && OperandType.isScalar(type) &&
						!OperandType.isAddress(type)) {
						// A true immediate (not a memory displacement like [0x2]).
						regImm.put(dest, scalar.getUnsignedValue());
					}
					else if (src != null && regImm.containsKey(src)) {
						regImm.put(dest, regImm.get(src));
					}
					else {
						regImm.remove(dest);
					}
				}
			}
			else {
				// Any other write to a tracked register invalidates its known immediate.
				for (Object result : instr.getResultObjects()) {
					if (result instanceof Register reg) {
						regImm.remove(reg);
					}
				}
			}
			addr = nextLinear(instr);
			if (addr == null) {
				return null;
			}
		}
		return null;
	}

	/**
	 * The one register {@code mov} writes, read from its p-code results rather than its
	 * operand list, or null if it writes memory or more than one register. Stock Ghidra
	 * 12.1.3 and 12.1.4 display {@code MOV Sreg,r/m16} ({@code 8E}) with its operands swapped
	 * (GP-7018: {@code 8e d8} reads {@code MOV AX,DS}), so operand 0 is the <i>source</i>
	 * there; the p-code was never affected. Shared with {@link RTLinkXrefAnalyzer}.
	 */
	static Register movDestination(Instruction mov) {
		Register written = null;
		for (Object result : mov.getResultObjects()) {
			if (!(result instanceof Register register) || written != null) {
				return null;
			}
			written = register;
		}
		return written;
	}

	/**
	 * The register {@code mov} copies, read from its p-code inputs: its only input, or null
	 * for an immediate or memory source. See {@link #movDestination} for why not operand 1.
	 */
	static Register movSourceRegister(Instruction mov) {
		Object[] inputs = mov.getInputObjects();
		return inputs.length == 1 && inputs[0] instanceof Register register ? register : null;
	}

	private static PseudoInstruction safeDecode(PseudoDisassembler disassembler, Address addr) {
		try {
			return disassembler.disassemble(addr);
		}
		catch (Exception e) {
			return null;
		}
	}

	/** The next physical instruction address (fall-through preferred), or null past the block. */
	private static Address nextLinear(PseudoInstruction instr) {
		Address fallThrough = instr.getFallThrough();
		if (fallThrough != null) {
			return fallThrough;
		}
		try {
			return instr.getAddress().add(instr.getLength());
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private static long computeImageEnd(OldDOSHeader header) {
		int pages = Short.toUnsignedInt(header.e_cp());
		int lastPageBytes = Short.toUnsignedInt(header.e_cblp());
		if (pages == 0) {
			return 0;
		}
		if (lastPageBytes == 0) {
			return (long) pages * 512;
		}
		return ((long) (pages - 1)) * 512 + lastPageBytes;
	}

	private static boolean detectRTLinkOverlay(BinaryReader reader, long overlayStart,
			long fileLength) {
		if (overlayStart + RTLinkPageHeader.HEADER_SIZE > fileLength) {
			return false;
		}
		try {
			reader.setPointerIndex(overlayStart);
			RTLinkPageHeader first = new RTLinkPageHeader(reader);
			if (!first.isValid()) {
				return false;
			}
			if (first.getTotalSizeBytes() > fileLength - overlayStart) {
				return false;
			}

			long secondOffset = overlayStart + first.getTotalSizeBytes();
			if (secondOffset + RTLinkPageHeader.HEADER_SIZE <= fileLength) {
				reader.setPointerIndex(secondOffset);
				RTLinkPageHeader second = new RTLinkPageHeader(reader);
				if (second.isValid() && second.getFrameSize() == first.getFrameSize()) {
					return true;
				}
			}

			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Create an overlay memory block named {@code OVERLAY_<record>} for every overlay
	 * record with code — including record 0, which earlier revisions wrongly skipped as
	 * a non-code "global overlay table". Block numbering therefore matches the
	 * OVLSTUB_NN / RTLINK_HDR_NN record numbering.
	 */
	private List<OverlayBlockInfo> createOverlayBlocks(Program program, FileBytes fileBytes,
			List<RTLinkOverlayPage> pages, MessageLog log, TaskMonitor monitor)
			throws Exception {
		List<OverlayBlockInfo> result = new ArrayList<>();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Address overlayBase = space.getAddress(overlayBaseSegment(program), 0);
		long fileSize = fileBytes.getSize();
		int width = nameWidth(pages.get(pages.size() - 1).getPageIndex());

		for (RTLinkOverlayPage page : pages) {
			monitor.checkCancelled();

			int codeSize = page.getCodeSize();
			if (codeSize <= 0) {
				log.appendMsg(
					"RTLink: Overlay page " + page.getPageIndex() + " has no code, skipping");
				continue;
			}

			// The final page's header-declared (paragraph-rounded) code size can run a
			// few bytes past the physical end of file, because the image is not padded
			// to a full paragraph. Clamp to the bytes actually present so block creation
			// does not read past FileBytes.
			long codeFileOffset = page.getCodeFileOffset();
			long available = fileSize - codeFileOffset;
			if (available <= 0) {
				log.appendMsg("RTLink: Overlay page " + page.getPageIndex() +
					" code starts past end of file, skipping");
				continue;
			}
			if (codeSize > available) {
				codeSize = (int) available;
			}

			String blockName = String.format("OVERLAY_%0" + width + "d", page.getPageIndex());

			// Note the module bases known from the relocation table in the block
			// comment; CS-relative absolute offsets in module code (e.g. switch jump
			// tables) are relative to these paragraphs, not to the page start. The
			// stub scan later contributes the modules the relocation table cannot
			// name (see mergeStubModuleBases).
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, true,
				blockName, overlayBase, fileBytes, codeFileOffset, codeSize,
				blockComment(page, page.getModuleBases()), "RTLink", true, false, true, log);

			if (block != null) {
				result.add(new OverlayBlockInfo(page, block));
				recordModuleBases(program, blockName, page.getModuleBases());
			}
			else {
				log.appendMsg(
					"RTLink: Failed to create block for page " + page.getPageIndex());
			}
		}

		Msg.debug(this, "RTLink/Plus: Created " + result.size() + " overlay memory blocks");
		return result;
	}

	/**
	 * Segment paragraph where the overlay blocks are based: the first 0x100-paragraph
	 * boundary past the end of the loaded image (highest base-space block). Basing the
	 * overlays above the image — instead of on top of its low segments at the old
	 * fixed 0x1000 — keeps the overlay address spaces from shadowing resident code. A
	 * list-1-relocated far call/jump in overlay code always targets the resident
	 * image (the statically encoded intra-page far calls are the list-2 sites, whose
	 * frame-relative words land inside the block itself, where overlay-space binding
	 * is correct), but the disassembler binds a flow whose flat target lies inside the
	 * instruction's own overlay space back into that space. Under the old base that
	 * planted garbage code over real page bytes: NEBULAR.EXE OVERLAY_59 held
	 * {@code CALLF 1089:01a1} (= resident 1085:01e1), which was bound to the page's
	 * own 0xa31 and collided with the genuine stub entry at 0xa2e, leaving a husk
	 * and an uncleared ERROR bookmark.
	 */
	private static int overlayBaseSegment(Program program) {
		AddressSpace base = program.getAddressFactory().getDefaultAddressSpace();
		long maxEnd = 0;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			Address end = block.getEnd();
			if (end.getAddressSpace().equals(base) && end.getOffset() > maxEnd) {
				maxEnd = end.getOffset();
			}
		}
		int segment = (int) ((maxEnd >> 4) + 1 + 0xff) & ~0xff;
		if (segment + 0x1000 > 0xffff) {
			// The image nearly fills the segmented space; fall back to the old base
			// rather than collide with the 20-bit limit. Shadowing returns, but only
			// for an image layout no RTLink binary seen so far comes close to.
			return INITIAL_SEGMENT_VAL;
		}
		return segment;
	}

	/**
	 * Record {@code bases} as the module base paragraphs of {@code blockName} in program
	 * info (see {@link #MODULE_BASES_PREFIX}) so {@link RTLinkSwitchTableAnalyzer} can
	 * resolve module-relative switch-table displacements in the overlay block.
	 */
	private static void recordModuleBases(Program program, String blockName,
			Collection<Integer> bases) {
		StringBuilder text = new StringBuilder();
		for (int base : bases) {
			if (text.length() > 0) {
				text.append(',');
			}
			text.append(Integer.toHexString(base));
		}
		program.getOptions(Program.PROGRAM_INFO)
				.setString(MODULE_BASES_PREFIX + blockName, text.toString());
	}

	/** The overlay block's comment, naming {@code bases} as its module base paragraphs. */
	private static String blockComment(RTLinkOverlayPage page, Collection<Integer> bases) {
		StringBuilder comment = new StringBuilder(
			String.format("RTLink/Plus overlay page %d (frame=0x%X)",
				page.getPageIndex(), page.getFrameSize()));
		if (bases.size() > 1) {
			comment.append(", module base paragraphs:");
			for (int base : bases) {
				comment.append(String.format(" 0x%X", base));
			}
		}
		return comment.toString();
	}

	/**
	 * Fold the module bases observed in the dispatch stubs into each page's recorded set.
	 * <p>
	 * A page's relocation table only names a module that some relocation is <i>sited</i>
	 * in, so a module carrying no segment fixups of its own is invisible there — yet the
	 * 14-byte stubs that call into it still spell out its base paragraph. In VICEROY.EXE
	 * this is the sole module of OVERLAY_03 (0x642) and the sixth of OVERLAY_29 (0x67);
	 * both are confirmed by the segment list, whose per-page flag word marks OVERLAY_03
	 * as multi-module even though its 652 relocations are all module 0.
	 * <p>
	 * Without this the two sets disagree and {@link RTLinkSwitchTableAnalyzer} — which
	 * anchors a CS-relative displacement to the module containing the dispatch — cannot
	 * place a switch table in such a module, so it (correctly, but needlessly) rejects it.
	 */
	private void mergeStubModuleBases(Program program, List<OverlayBlockInfo> overlayBlocks,
			Map<String, SortedSet<Integer>> stubModuleBases) {
		int pagesExtended = 0;
		int basesAdded = 0;

		for (OverlayBlockInfo info : overlayBlocks) {
			String blockName = info.block().getName();
			SortedSet<Integer> fromStubs = stubModuleBases.get(blockName);
			if (fromStubs == null) {
				continue;
			}

			SortedSet<Integer> merged = new TreeSet<>(info.page().getModuleBases());
			int before = merged.size();
			merged.addAll(fromStubs);
			if (merged.size() == before) {
				continue;
			}

			recordModuleBases(program, blockName, merged);
			info.block().setComment(blockComment(info.page(), merged));
			pagesExtended++;
			basesAdded += merged.size() - before;
		}

		if (pagesExtended > 0) {
			// Msg.info only, never log.appendMsg: any content in the analysis MessageLog
			// makes AutoAnalysisPlugin pop a "warnings/errors issued during analysis"
			// dialog, and this is a clean-run success count.
			Msg.info(this, String.format(
				"RTLink/Plus: Added %d stub-only module base(s) across %d overlay page(s)",
				basesAdded, pagesExtended));
		}
	}

	static void applyOverlayRelocations(Program program, MemoryBlock block,
			RTLinkOverlayPage page, MessageLog log) {
		Memory memory = program.getMemory();
		Address blockStart = block.getStart();
		int pageDisplay = page.getPageIndex();

		// The runtime fixup loop (210d:2e59 in VICEROY.EXE) addresses each patch
		// site as (frame + seg_index):offset — page-linear seg_index*16 + offset —
		// and adds a delta to the unrelocated segment word found there, regardless of
		// seg_index. The two lists differ only in what that word points at, and hence
		// in which delta it takes.
		//
		// List 1: the word is a segment in the RESIDENT IMAGE. It takes the image load
		// delta, once. MzLoader bases the image at INITIAL_SEGMENT_VAL without setting
		// the program image base, so getImageBase() would yield 0 here.
		//
		// List 2: the word is a PAGE-RELATIVE segment — a paragraph offset within the
		// page (0 = the page's own base, or one of its module bases). Every site seen
		// is the segment word of a statically encoded intra-page far call between two
		// modules of the same page (CALLF module:offset). Verified two ways: 211 of 211
		// list-2 sites across NEBULAR, ROE2MAIN and SPHERE hold a value below their
		// page's paragraph count (list-1 sites essentially never do), and the runtime
		// list-2 fixup call (VICEROY 210d:233f; byte-identical in NEBULAR and SPHERE)
		// reads the count from header +0xA, rounds the start index up to a 4-entry
		// group exactly as RTLinkPageHeader models, and adds currentFrame -
		// previousFrame on every page move — the invariant is word = file word +
		// current frame. Statically the page's "frame" is the overlay block's own base
		// segment, so that is the delta to add here; the patched word then lands the
		// call inside its own overlay block, which is also where the disassembler
		// binds it.
		//
		// The two deltas coincided at 0x1000 before the overlays were rebased above
		// the image; they are different quantities and differ in every program now, so
		// derive each one. The block's start cannot be cast to SegmentedAddress (an
		// overlay of a segmented space hands back a GenericAddress), so take its
		// paragraph from the offset.
		int loadDelta = INITIAL_SEGMENT_VAL;
		int frameDelta = (int) (blockStart.getOffset() >>> 4) & 0xffff;

		applyRelocationList(program, memory, blockStart, page.getRelocations(), loadDelta,
			pageDisplay, log);
		applyRelocationList(program, memory, blockStart, page.getSecondRelocations(),
			frameDelta, pageDisplay, log);

		// List 3 is not applied, and that is final rather than provisional: beyond being
		// empty on every page of every binary seen, the RTLink/Plus 6.10 linker has been
		// shown by construction to be incapable of emitting one (its resident-site patch
		// path announces itself and then writes nothing — see RTLinkPageHeader's class
		// comment and ~/dosbox/RTLTEST/HANDOFF.md). A nonzero count would mean a
		// different linker version, and its sites would live in the resident image, not
		// this block, with yet another base segment.
	}

	/**
	 * Add {@code delta} to the unrelocated segment word at each of {@code relocations}'
	 * sites, and record the fixups in the relocation table.
	 */
	private static void applyRelocationList(Program program, Memory memory, Address blockStart,
			List<RTLinkRelocation> relocations, int delta, int pageDisplay, MessageLog log) {
		for (RTLinkRelocation reloc : relocations) {
			int siteOffset = reloc.getSiteOffset();

			try {
				Address relocAddr = blockStart.add(siteOffset);
				short currentValue = memory.getShort(relocAddr);
				int segmentValue = (Short.toUnsignedInt(currentValue) + delta) & 0xffff;

				memory.setShort(relocAddr, (short) segmentValue);

				program.getRelocationTable().add(relocAddr, Status.APPLIED, 0,
					new long[] { reloc.getOffset(), reloc.getSegmentIndex(), segmentValue },
					2, null);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				log.appendMsg(String.format(
					"RTLink: Failed to apply relocation at offset 0x%04X in page %d: %s",
					siteOffset, pageDisplay, e.getMessage()));
			}
		}
	}

	private void discoverAndProcessStubs(Program program,
			List<OverlayBlockInfo> overlayBlocks, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		AddressSet overlayEntryPoints = new AddressSet();
		List<StubTarget> pendingThunks = new ArrayList<>();
		Map<String, SortedSet<Integer>> stubModuleBases = new HashMap<>();

		Map<Long, Integer> dispatcherSegs = discoverDispatchers(program, monitor);
		Set<Long> dispatchers = dispatcherSegs.keySet();
		if (!dispatchers.isEmpty()) {
			Msg.debug(this, "RTLink/Plus: Discovered " + dispatchers.size() +
				" overlay dispatcher entry point(s)");
		}

		int jmpfStubs = scanForJmpfStubs(program, overlayBlocks, dispatchers,
			overlayEntryPoints, pendingThunks, stubModuleBases, log, monitor);
		int int3fStubs = 0;

		// The stubs are the only place a module carrying no relocations is named, so
		// fold what they revealed into each page's module base set before the switch
		// table analyzer reads it back.
		mergeStubModuleBases(program, overlayBlocks, stubModuleBases);

		if (jmpfStubs == 0) {
			int3fStubs = scanForInt3fStubs(program, overlayBlocks, overlayEntryPoints,
				pendingThunks, log, monitor);
		}

		// Resident-target trampolines share the jump table with the CALLF+JMPF
		// dispatch stubs, so only look for them once segment-0 stubs have
		// corroborated that this binary uses that scheme (an INT 3Fh-era binary has
		// no smart-vectoring helper, and a shared CALLF+JMPF pair count alone is a
		// weaker signal when the JMPF segment is a plausible real value).
		AddressSet trampolineTargets = new AddressSet();
		List<StubTarget> pendingTrampolines = new ArrayList<>();
		int trampolines = 0;
		if (jmpfStubs > 0) {
			trampolines = scanForResidentTrampolines(program, dispatchers,
				trampolineTargets, pendingTrampolines, monitor);
		}

		int total = jmpfStubs + int3fStubs;
		if (total == 0 && trampolines == 0) {
			log.appendMsg("RTLink: No dispatch stubs found");
			return;
		}

		FunctionManager funcMgr = program.getFunctionManager();

		if (total > 0) {
			// Disassemble the overlay code reachable from the resolved entry points and
			// promote each entry point to a function with a real body. Without this the
			// overlay pages hold no instructions, so intra-overlay calls and jumps never
			// get references and every overlay "function" is a one-byte husk.
			disassembleOverlayCode(program, overlayBlocks, overlayEntryPoints, log, monitor);

			// Now that the overlay targets are real functions, wire each dispatch stub to
			// its target as a thunk.
			for (StubTarget stub : pendingThunks) {
				monitor.checkCancelled();
				if (createThunkAtStub(funcMgr, stub.stubAddr(), stub.targetAddr(),
					stub.stubSize(), log)) {
					clearStubErrorBookmarks(program, stub, monitor);
				}
			}
		}

		if (trampolines > 0) {
			disassembleResidentTargets(program, trampolineTargets, log, monitor);
			for (StubTarget stub : pendingTrampolines) {
				monitor.checkCancelled();
				if (createThunkAtStub(funcMgr, stub.stubAddr(), stub.targetAddr(),
					stub.stubSize(), log)) {
					clearStubErrorBookmarks(program, stub, monitor);
				}
			}
		}

		Msg.info(this, "RTLink/Plus: Resolved " + total + " dispatch stub(s) and " +
			trampolines + " resident-target trampoline(s)");

		// Only a corroborated VM-nucleus binary (real CALLF+JMPF stubs) gets its runtime
		// entry points seeded; an INT 3Fh-era binary has no nucleus to seed.
		if (jmpfStubs > 0) {
			seedVmRuntimeEntryPoints(program, dispatcherSegs, log, monitor);
		}
	}

	/**
	 * Discover overlay dispatcher entry points instead of hardcoding one offset.
	 * <p>
	 * Every dispatch stub begins with {@code CALLF seg:disp} immediately followed by
	 * {@code JMPF ...}. The dispatcher is therefore the CALLF target shared by a large
	 * number of such CALLF+JMPF pairs. This scans every executable non-overlay block,
	 * tallies the physical CALLF target of each candidate pair, and returns those hit at
	 * least {@link #MIN_DISPATCHER_STUB_COUNT} times. Keying on the physical (flat)
	 * address collapses the many segment:offset aliases that resolve to one dispatcher.
	 * <p>
	 * Each dispatcher maps to its <b>stub-declared segment</b> — the CS the stubs' CALLF
	 * operands carry, i.e. the segment the VM nucleus actually runs in. That segment, not
	 * the canonical segment Ghidra happens to display a nucleus address under, is what
	 * {@link #seedVmDispatchTargets} must resolve the dispatch immediates against.
	 */
	private Map<Long, Integer> discoverDispatchers(Program program, TaskMonitor monitor)
			throws CancelledException {
		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Map<Long, Integer> counts = new HashMap<>();
		Map<Long, Integer> stubSegments = new HashMap<>();

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_CALLF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address jmpfAddr = searchAddr.add(5);
					if (isCodeMemory(memory, jmpfAddr) &&
						memory.getByte(jmpfAddr) == OPCODE_JMPF) {
						int off = Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
						int seg = Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
						long target = space.getAddress(seg, off).getOffset();
						counts.merge(target, 1, Integer::sum);
						stubSegments.putIfAbsent(target, seg);
					}
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}

		Map<Long, Integer> dispatchers = new HashMap<>();
		for (Map.Entry<Long, Integer> e : counts.entrySet()) {
			if (e.getValue() >= MIN_DISPATCHER_STUB_COUNT) {
				dispatchers.put(e.getKey(), stubSegments.get(e.getKey()));
			}
		}
		return dispatchers;
	}

	/**
	 * Program-info option recording how many VM-runtime function entries
	 * {@link #seedVmRuntimeEntryPoints} seeded, so the headless smoke script can assert
	 * the pass actually fired on a known-good target.
	 */
	static final String VM_SEED_COUNT_OPTION = "RTLink VM Runtime Seeds";

	/**
	 * The VM nucleus's constant-pair dispatch — the shape ending each of {@code $$VM_UNK}'s
	 * two arms (transcribed from {@code vmnuc.asm} in the vendor's RTLUTILS.LIB, and present
	 * byte-identically in the VICEROY variant that matches no reference build):
	 *
	 * <pre>
	 *   +0   B8 ii ii            MOV  AX, imm16     ; vendor entry ($$VM_CALL / $$VM_JMP)
	 *   +3   BA ii ii            MOV  DX, imm16     ; inner entry, past that routine's prologue
	 *   +6   2E F6 06 aa aa FF   TEST byte CS:[flag], 0xFF
	 *   +12  74 06               JE   +6
	 *   +14  B8 ii ii            MOV  AX, imm16     ; flag-set pair ($$VM_CALLR / $$VM_JMPR)
	 *   +17  BA ii ii            MOV  DX, imm16
	 *   +20  89 44 FC            MOV  [SI-4], AX    ; return-slot patch
	 *   +23  FF E2               JMP  DX
	 * </pre>
	 *
	 * AX is stored into the caller's far-return offset slot, so both AX immediates are
	 * function entries (they are exactly the {@code $$VM_*} PUBDEF symbols in the vendor
	 * object); the DX immediates are jump targets inside those routines' bodies. All four
	 * resolve against the runtime CS the dispatch stubs call the dispatcher through — not
	 * against the site's canonical segment, which is why the stock constant analyzer's
	 * same-block resolution of this very shape is bogus (and stays deleted by
	 * {@link RTLinkDispatcherJumpAnalyzer}) while this one is exact.
	 */
	private static final byte[] VM_DISPATCH_PATTERN = {
		(byte) 0xB8, 0, 0, (byte) 0xBA, 0, 0,
		0x2E, (byte) 0xF6, 0x06, 0, 0, (byte) 0xFF,
		0x74, 0x06,
		(byte) 0xB8, 0, 0, (byte) 0xBA, 0, 0,
		(byte) 0x89, 0x44, (byte) 0xFC, (byte) 0xFF, (byte) 0xE2 };
	private static final byte[] VM_DISPATCH_MASK = {
		-1, 0, 0, -1, 0, 0,
		-1, -1, -1, 0, 0, -1,
		-1, -1,
		-1, 0, 0, -1, 0, 0,
		-1, -1, -1, -1, -1 };

	/** Pattern offsets of the two AX immediates — vendor function entries. */
	private static final int[] VM_DISPATCH_FUNCTION_IMMS = { 1, 15 };
	/** Pattern offsets of the two DX immediates — mid-routine jump targets. */
	private static final int[] VM_DISPATCH_FLOW_IMMS = { 4, 18 };

	/**
	 * Seed the RTLink VM runtime's function starts that nothing else ever reaches: the MZ
	 * entry stub's two far targets, and the nucleus entries the {@code $$VM_UNK} dispatch
	 * arms select by constant pair. These are real, evidenced entries reached only through
	 * data (a patched return slot, a register-indirect jump), so neither auto-analysis nor
	 * the decompiler's jump-table recovery ever disassembles them. Naming beyond
	 * {@code __astart}/{@code $$VM_INITW} is deliberately left to FID against the vendor's
	 * {@code vmnuc} objects — the nucleus ships in at least nine build variants with
	 * shifting offsets, so only body hashes, never positions, identify the rest.
	 * <p>
	 * Everything here is a no-op where an earlier run or hand analysis already claimed the
	 * address, so the pass is safe to retrofit onto an analyzed program. Exposed
	 * package-private so tests can drive it directly.
	 */
	static int seedVmRuntimeEntryPoints(Program program, Map<Long, Integer> dispatchers,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		AddressSet functionSeeds = new AddressSet();
		AddressSet flowSeeds = new AddressSet();
		PseudoDisassembler disassembler = new PseudoDisassembler(program);

		seedEntryStub(program, disassembler, functionSeeds);
		seedVmDispatchTargets(program, dispatchers, disassembler, functionSeeds, flowSeeds,
			monitor);

		if (functionSeeds.isEmpty() && flowSeeds.isEmpty()) {
			return 0;
		}

		AddressSet residentRange = new AddressSet();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isOverlay() && block.isExecute() && block.isInitialized()) {
				residentRange.add(block.getStart(), block.getEnd());
			}
		}

		monitor.setMessage("RTLink: Disassembling VM runtime entry points...");
		AddressSet toDisassemble = functionSeeds.union(flowSeeds);
		DisassembleCommand disCmd = new DisassembleCommand(toDisassemble, residentRange, true);
		disCmd.applyTo(program, monitor);
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating VM runtime functions...");
		CreateFunctionCmd funcCmd = new CreateFunctionCmd(functionSeeds, SourceType.ANALYSIS);
		funcCmd.applyTo(program, monitor);

		verifyEntryPointsBecameCode(program, functionSeeds, "VM runtime entry point", log,
			monitor);

		int count = (int) functionSeeds.getNumAddresses();
		program.getOptions(Program.PROGRAM_INFO).setInt(VM_SEED_COUNT_OPTION, count);
		Msg.info(RTLinkOverlayAnalyzer.class, String.format(
			"RTLink/Plus: Seeded %d VM runtime function entr%s and %d dispatch flow target(s)",
			count, count == 1 ? "y" : "ies", flowSeeds.getNumAddresses()));
		return count;
	}

	/**
	 * The MZ entry of an RTLink/Plus VM program is the linker's own 10-byte stub — the
	 * vendor object's public {@code $$VM_INITW}: {@code CALLF <vm init body>} followed by
	 * {@code JMPF <startup>}, both operands carrying real MZ-relocated segments. Label the
	 * stub and the startup, and seed both far targets as functions: the init body is
	 * reached from nowhere else, and the JMPF tail-jump never makes the startup a function
	 * on its own. The startup label {@code __astart} is the MSC CRT's entry symbol — the
	 * corpus toolchain; on a non-MSC RTLink binary the function start would still be
	 * right and only the name conventional.
	 */
	private static void seedEntryStub(Program program, PseudoDisassembler disassembler,
			AddressSet functionSeeds) {
		Address entry = firstEntryPoint(program);
		if (entry == null) {
			return;
		}
		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		try {
			if (memory.getByte(entry) != OPCODE_CALLF ||
				memory.getByte(entry.add(5)) != OPCODE_JMPF) {
				return;
			}
			Address initBody = space.getAddress(
				Short.toUnsignedInt(memory.getShort(entry.add(3))),
				Short.toUnsignedInt(memory.getShort(entry.add(1))));
			Address startup = space.getAddress(
				Short.toUnsignedInt(memory.getShort(entry.add(8))),
				Short.toUnsignedInt(memory.getShort(entry.add(6))));
			if (initBody.equals(startup) || initBody.equals(entry) || startup.equals(entry)) {
				return;
			}
			if (!isCodeMemory(memory, initBody) || !isCodeMemory(memory, startup)) {
				return;
			}
			if (safeDecode(disassembler, initBody) == null ||
				safeDecode(disassembler, startup) == null) {
				return;
			}
			SymbolTable symbolTable = program.getSymbolTable();
			try {
				// Additional label: the loader's `entry` stays primary.
				symbolTable.createLabel(entry, "$$VM_INITW", SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				// ignore
			}
			labelAddress(symbolTable, "__astart", startup);
			functionSeeds.add(initBody);
			functionSeeds.add(startup);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// not the stub; leave the entry alone
		}
	}

	/**
	 * Scan each resident block holding a discovered dispatcher for
	 * {@link #VM_DISPATCH_PATTERN} sites and collect their immediates — AX pairs as
	 * function seeds, DX pairs as flow-only seeds — resolved against the dispatcher's
	 * stub-declared segment. A target must land in the same block and decode as an
	 * instruction, so a wrong segment or a data immediate fails closed.
	 */
	private static void seedVmDispatchTargets(Program program, Map<Long, Integer> dispatchers,
			PseudoDisassembler disassembler, AddressSet functionSeeds, AddressSet flowSeeds,
			TaskMonitor monitor) throws CancelledException {
		if (dispatchers.isEmpty()) {
			return;
		}
		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();

		Map<MemoryBlock, Set<Integer>> segsByBlock = new HashMap<>();
		for (Map.Entry<Long, Integer> e : dispatchers.entrySet()) {
			int seg = e.getValue();
			long off = e.getKey() - seg * 16L;
			if (off < 0 || off > 0xffff) {
				continue;
			}
			MemoryBlock block = memory.getBlock(space.getAddress(seg, (int) off));
			if (block != null && !block.isOverlay()) {
				segsByBlock.computeIfAbsent(block, k -> new HashSet<>()).add(seg);
			}
		}

		for (Map.Entry<MemoryBlock, Set<Integer>> e : segsByBlock.entrySet()) {
			MemoryBlock block = e.getKey();
			Address searchAddr = block.getStart();
			while (searchAddr != null && searchAddr.compareTo(block.getEnd()) < 0) {
				monitor.checkCancelled();
				searchAddr = memory.findBytes(searchAddr, block.getEnd(), VM_DISPATCH_PATTERN,
					VM_DISPATCH_MASK, true, monitor);
				if (searchAddr == null) {
					break;
				}
				for (int seg : e.getValue()) {
					collectDispatchImms(memory, space, block, disassembler, searchAddr, seg,
						VM_DISPATCH_FUNCTION_IMMS, functionSeeds);
					collectDispatchImms(memory, space, block, disassembler, searchAddr, seg,
						VM_DISPATCH_FLOW_IMMS, flowSeeds);
				}
				searchAddr = searchAddr.add(1);
			}
		}
	}

	/** Resolve and validate the pattern immediates at {@code immOffsets} into {@code seeds}. */
	private static void collectDispatchImms(Memory memory, SegmentedAddressSpace space,
			MemoryBlock block, PseudoDisassembler disassembler, Address match, int segment,
			int[] immOffsets, AddressSet seeds) {
		for (int off : immOffsets) {
			try {
				int imm = Short.toUnsignedInt(memory.getShort(match.add(off)));
				if (imm == 0) {
					continue;
				}
				Address target = space.getAddress(segment, imm);
				if (!block.contains(target)) {
					continue;
				}
				if (safeDecode(disassembler, target) == null) {
					continue;
				}
				seeds.add(target);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException ex) {
				// skip
			}
		}
	}

	/**
	 * Disassemble overlay code starting from the resolved stub entry points, following
	 * intra-page flow but staying within the overlay blocks, then create a function with
	 * a computed body at each entry point.
	 * <p>
	 * This is what makes overlay code visible to the rest of Ghidra: the disassembler
	 * creates flow references for the near calls and jumps between overlay routines (which
	 * {@code OperandReferenceAnalyzer} never creates for 16-bit spaces), and the follow-on
	 * far-call analyzer then wires overlay-to-main references.
	 */
	private void disassembleOverlayCode(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet overlayEntryPoints, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (overlayEntryPoints.isEmpty()) {
			return;
		}

		AddressSet overlayRange = new AddressSet();
		for (OverlayBlockInfo info : overlayBlocks) {
			overlayRange.add(info.block().getStart(), info.block().getEnd());
		}

		monitor.setMessage("RTLink: Disassembling overlay code...");
		DisassembleCommand disCmd =
			new DisassembleCommand(overlayEntryPoints, overlayRange, true);
		if (!disCmd.applyTo(program, monitor)) {
			log.appendMsg("RTLink: Overlay disassembly reported: " + disCmd.getStatusMsg());
		}
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating overlay functions...");
		CreateFunctionCmd funcCmd =
			new CreateFunctionCmd(overlayEntryPoints, SourceType.ANALYSIS);
		funcCmd.applyTo(program, monitor);

		verifyEntryPointsBecameCode(program, overlayEntryPoints, "overlay entry point", log,
			monitor);

		AddressSetView disassembled = disCmd.getDisassembledAddressSet();
		long byteCount = disassembled == null ? 0 : disassembled.getNumAddresses();
		Msg.debug(this, String.format(
			"RTLink/Plus: Disassembled %d overlay byte(s) from %d entry point(s)",
			byteCount, overlayEntryPoints.getNumAddresses()));
	}

	/**
	 * Scan for dispatch stubs by finding JMPF instructions with segment 0x0000, then
	 * validating that a CALLF to a {@link #discoverDispatchers discovered dispatcher}
	 * precedes them.
	 * <p>
	 * Stub layout (12 or 14 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo 00 00   JMPF 0000:offset
	 *   [10-11] pp pp             page_id (bits 0-13 = 1-based descriptor index)
	 *   [12-13] mm mm             module_word (14-byte form only)
	 * </pre>
	 * page_id is a 1-based descriptor index over the overlay records: page_id N targets
	 * record N - 1, so page_id 1 is record 0 — a real code page, not (as an earlier
	 * revision assumed) a non-code global table.
	 * The JMPF offset is relative to the target module's base paragraph within the
	 * page: 12-byte stubs target module 0, so it is the in-page code offset directly;
	 * 14-byte stubs carry the module's base paragraph in module_word, and the in-page
	 * code offset is JMPF offset + module_word * 16.
	 * <p>
	 * Nothing in page_id flags the stub length (bits 14-15 are always clear), so the
	 * two forms are told apart structurally: if the bytes at +12 begin another
	 * dispatcher stub (a CALLF whose target is a discovered dispatcher), the stub is
	 * 12 bytes; otherwise a word at +12 smaller than the page's total paragraph count
	 * is a module_word. The module_word cannot be validated against the page's
	 * relocation seg_index values ({@link RTLinkOverlayPage#getModuleBases()}) — a
	 * module referenced only by stubs never appears there. Every module_word observed
	 * here is collected into {@code stubModuleBases}, keyed by overlay block name, so
	 * {@link #mergeStubModuleBases} can complete each page's set with exactly those
	 * modules the relocation table cannot name.
	 */
	private int scanForJmpfStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			Set<Long> dispatchers, AddressSet overlayEntryPoints,
			List<StubTarget> pendingThunks, Map<String, SortedSet<Integer>> stubModuleBases,
			MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (overlayBlocks.isEmpty() || dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Map<Integer, OverlayBlockInfo> blocksByRecord = blocksByRecord(overlayBlocks);
		int width = nameWidth(maxRecordIndex(overlayBlocks));
		int count = 0;
		int moduleResolved = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_JMPF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					// Need 5 bytes before (CALLF) and 7 bytes after (JMPF + page_id)
					Address callfAddr = searchAddr.subtract(5);
					Address pageIdAddr = searchAddr.add(5);

					if (!isCodeMemory(memory, callfAddr) ||
						!isCodeMemory(memory, pageIdAddr.add(1))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetSegment =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
					if (targetSegment != 0x0000) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Validate CALLF opcode and that it targets a discovered dispatcher.
					byte callfOpcode = memory.getByte(callfAddr);
					int callfOffset =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(1)));
					int callfSegment =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(3)));
					long callfTarget = space.getAddress(callfSegment, callfOffset).getOffset();
					if (callfOpcode != OPCODE_CALLF || !dispatchers.contains(callfTarget)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int jmpfOffset =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
					int pageId = Short.toUnsignedInt(memory.getShort(pageIdAddr));
					// The stored value is a 1-based descriptor index: descriptor N is
					// overlay record N - 1, so page_id 1 targets record 0 (a real code
					// page — see the class javadoc). pageNumber is the record index,
					// shared by the OVLSTUB/OVL label convention and (since the
					// record-0 fix) the OVERLAY_NN block names.
					int descriptorIndex = pageId & PAGE_ID_MASK;
					int pageNumber = descriptorIndex - 1;

					OverlayBlockInfo target = blocksByRecord.get(pageNumber);
					if (target == null) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Distinguish the 12- and 14-byte stub forms (see the method javadoc):
					// the bytes at +12 either begin the next stub (12-byte form, module 0)
					// or hold the target module's base paragraph within the page.
					int stubSize = 12;
					int moduleBase = 0;
					Address moduleWordAddr = callfAddr.add(12);
					if (isCodeMemory(memory, moduleWordAddr.add(1)) &&
						!isDispatcherCallf(memory, space, dispatchers, moduleWordAddr)) {
						int word = Short.toUnsignedInt(memory.getShort(moduleWordAddr));
						if (word < target.page().getHeader().getTotalParagraphs()) {
							stubSize = 14;
							moduleBase = word;
						}
					}
					int targetOffset = jmpfOffset + moduleBase * 16;

					Address targetAddr = target.block().getStart().add(targetOffset);

					if (!target.block().contains(targetAddr)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Only now that the stub has fully checked out is its module_word
					// trustworthy enough to record as one of the page's module bases.
					if (moduleBase != 0) {
						stubModuleBases
								.computeIfAbsent(target.block().getName(), k -> new TreeSet<>())
								.add(moduleBase);
					}

					Address stubAddr = callfAddr;
					refManager.addMemoryReference(stubAddr, targetAddr,
						RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

					labelAddress(symbolTable,
						String.format("OVLSTUB_%0" + width + "d_%04X", pageNumber,
							targetOffset),
						stubAddr);
					labelAddress(symbolTable,
						String.format("OVL%0" + width + "d_%04X", pageNumber, targetOffset),
						targetAddr);

					overlayEntryPoints.add(targetAddr);
					pendingThunks.add(new StubTarget(stubAddr, targetAddr, stubSize));
					if (moduleBase != 0) {
						moduleResolved++;
					}
					count++;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}
		if (moduleResolved > 0) {
			Msg.debug(this, "RTLink/Plus: " + moduleResolved +
				" stub(s) resolved through a nonzero module base");
		}
		return count;
	}

	/**
	 * Returns true if the 5 bytes at {@code addr} form a far call to one of the
	 * discovered overlay dispatchers — i.e. the start of another dispatch stub.
	 */
	private static boolean isDispatcherCallf(Memory memory, SegmentedAddressSpace space,
			Set<Long> dispatchers, Address addr) {
		try {
			if (!isCodeMemory(memory, addr) || !isCodeMemory(memory, addr.add(4))) {
				return false;
			}
			if (memory.getByte(addr) != OPCODE_CALLF) {
				return false;
			}
			int off = Short.toUnsignedInt(memory.getShort(addr.add(1)));
			int seg = Short.toUnsignedInt(memory.getShort(addr.add(3)));
			return dispatchers.contains(space.getAddress(seg, off).getOffset());
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Scan for resident-target trampolines in the RTLink jump table.
	 * <p>
	 * Trampoline layout (10 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo ss ss   JMPF seg:off     (relocated resident target)
	 * </pre>
	 * RTLink routes far calls from (movable) overlay code into resident code through
	 * these shims: the dispatcher entry re-vectors the caller's far return address in
	 * case its overlay page moves, then the JMPF tail-jumps to the real function —
	 * semantically a plain far call. Trampolines are told apart from overlay dispatch
	 * stubs by the JMPF segment: dispatch stubs carry the unrelocated {@code 0000},
	 * trampolines a real segment that lands in resident executable memory.
	 * <p>
	 * Each trampoline is queued for conversion into a thunk of its JMPF target. Left
	 * as plain functions they degrade decompilation at every call site: having no RET
	 * of their own, convention analysis leaves them on the default (near) convention,
	 * parameters are modeled one stack slot too low, and every caller decompiles with
	 * a junk leading argument that swallows a real one. A thunk delegates name,
	 * signature and (far) calling convention to the target.
	 */
	private int scanForResidentTrampolines(Program program, Set<Long> dispatchers,
			AddressSet trampolineTargets, List<StubTarget> pendingThunks,
			TaskMonitor monitor) throws CancelledException {
		if (dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		int count = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_JMPF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address callfAddr = searchAddr.subtract(5);
					if (!isCodeMemory(memory, callfAddr) ||
						!isCodeMemory(memory, searchAddr.add(4))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetSegment =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
					if (targetSegment == 0x0000) {
						// Unrelocated segment: an overlay dispatch stub, not a
						// trampoline (handled by scanForJmpfStubs).
						searchAddr = searchAddr.add(1);
						continue;
					}

					if (!isDispatcherCallf(memory, space, dispatchers, callfAddr)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetOffset =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
					Address targetAddr = space.getAddress(targetSegment, targetOffset);

					MemoryBlock targetBlock = memory.getBlock(targetAddr);
					if (targetBlock == null || targetBlock.isOverlay() ||
						!targetBlock.isExecute() || !targetBlock.isInitialized()) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// A jump back into the trampoline's own bytes is not a trampoline.
					long delta = targetAddr.getOffset() - callfAddr.getOffset();
					if (delta >= 0 && delta < 10) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					trampolineTargets.add(targetAddr);
					pendingThunks.add(new StubTarget(callfAddr, targetAddr, 10));
					count++;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}

		if (count > 0) {
			Msg.debug(this,
				"RTLink/Plus: Found " + count + " resident-target trampoline(s)");
		}
		return count;
	}

	/**
	 * Disassemble the resident trampoline targets and promote each to a function, so
	 * {@link #createThunkAtStub} has real functions to thunk to. Many targets are
	 * reachable only through the trampolines (far calls from overlay code), so regular
	 * flow analysis alone may never get there. Targets that land inside an existing
	 * function's body are left alone here and skipped by the thunk pass.
	 */
	private void disassembleResidentTargets(Program program, AddressSet targets,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (targets.isEmpty()) {
			return;
		}

		AddressSet residentRange = new AddressSet();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isOverlay() && block.isExecute() && block.isInitialized()) {
				residentRange.add(block.getStart(), block.getEnd());
			}
		}

		monitor.setMessage("RTLink: Disassembling trampoline targets...");
		DisassembleCommand disCmd = new DisassembleCommand(targets, residentRange, true);
		if (!disCmd.applyTo(program, monitor)) {
			log.appendMsg(
				"RTLink: Trampoline target disassembly reported: " + disCmd.getStatusMsg());
		}
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating trampoline target functions...");
		CreateFunctionCmd funcCmd = new CreateFunctionCmd(targets, SourceType.ANALYSIS);
		funcCmd.applyTo(program, monitor);

		verifyEntryPointsBecameCode(program, targets, "trampoline target", log, monitor);
	}

	/**
	 * Verify that every entry point in {@code entryPoints} was actually disassembled.
	 * A seed the disassembler could not decode leaves {@link CreateFunctionCmd} to
	 * plant a 1-byte function over the undefined bytes -- a husk that looks resolved
	 * to every downstream consumer while hiding the failure. Tear such a husk down
	 * and report the entry: no function at all is strictly better than a function
	 * with no code.
	 */
	private static void verifyEntryPointsBecameCode(Program program, AddressSetView entryPoints,
			String what, MessageLog log, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager funcMgr = program.getFunctionManager();
		for (Address entry : entryPoints.getAddresses(true)) {
			monitor.checkCancelled();
			if (listing.getInstructionAt(entry) != null) {
				continue;
			}
			if (listing.getInstructionContaining(entry) != null) {
				// Offcut into existing code, not undefined bytes: a pre-existing
				// overlap the thunk pass reports on its own terms, not a silent
				// disassembly failure.
				continue;
			}
			Function husk = funcMgr.getFunctionAt(entry);
			if (husk != null && !husk.isThunk()) {
				funcMgr.removeFunction(entry);
			}
			log.appendMsg(String.format("RTLink: %s %s could not be disassembled%s", what,
				entry, husk != null ? "; removed the 1-byte husk function created over it"
						: "; no function created"));
		}
	}

	/**
	 * Scan for INT 3Fh (CD 3F) stubs used by older RTLink versions.
	 * Pattern: CD 3F xx xx yy yy (INT 3Fh, overlay_id, offset)
	 */
	private int scanForInt3fStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet overlayEntryPoints, List<StubTarget> pendingThunks,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		byte[] pattern = { (byte) 0xCD, (byte) 0x3F };
		Map<Integer, OverlayBlockInfo> blocksByRecord = blocksByRecord(overlayBlocks);
		int width = nameWidth(maxRecordIndex(overlayBlocks));
		int count = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd, pattern, null, true,
					monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address idAddr = searchAddr.add(2);
					Address offAddr = searchAddr.add(4);

					if (!isCodeMemory(memory, offAddr.add(1))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int overlayId = Short.toUnsignedInt(memory.getShort(idAddr));
					int targetOffset = Short.toUnsignedInt(memory.getShort(offAddr));

					// overlay_id is interpreted as a record index, consistent with the
					// OVLSTUB naming convention.
					OverlayBlockInfo info = blocksByRecord.get(overlayId);
					if (info != null) {
						Address targetAddr =
							info.block().getStart().add(targetOffset);

						if (info.block().contains(targetAddr)) {
							refManager.addMemoryReference(searchAddr, targetAddr,
								RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

							int pageNum = info.page().getPageIndex();
							labelAddress(symbolTable,
								String.format("OVLSTUB_%0" + width + "d_%04X", pageNum,
									targetOffset),
								searchAddr);
							labelAddress(symbolTable,
								String.format("OVL%0" + width + "d_%04X", pageNum,
									targetOffset),
								targetAddr);

							overlayEntryPoints.add(targetAddr);
							pendingThunks.add(new StubTarget(searchAddr, targetAddr, 6));
							count++;
						}
					}
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}
		return count;
	}

	/**
	 * Wire {@code stubAddr} to {@code targetAddr} as a thunk.
	 *
	 * @return true if the stub is resolved (a thunk to its target now exists at it),
	 *         false if resolution failed or the site was skipped — the caller only
	 *         clears the stub's stale ERROR bookmarks when this returns true, so a
	 *         genuine decode failure keeps its mark.
	 */
	private static boolean createThunkAtStub(FunctionManager funcMgr, Address stubAddr,
			Address targetAddr, int stubSize, MessageLog log) {
		// A CALLF+JMPF pair inside a larger function's body is fallthrough-reachable
		// code, not a free-standing stub — the overlay manager's own code contains
		// guarded dispatcher calls (TEST flag / JNZ past / CALLF dispatcher / JMPF)
		// whose tail is byte-identical to a trampoline. Carving a thunk there would
		// split the containing function, so leave the site alone.
		Function containing = funcMgr.getFunctionContaining(stubAddr);
		if (containing != null && !containing.getEntryPoint().equals(stubAddr)) {
			Msg.debug(RTLinkOverlayAnalyzer.class, String.format(
				"RTLink: skipping stub thunk at %s -> %s: embedded in %s at %s",
				stubAddr, targetAddr, containing.getName(), containing.getEntryPoint()));
			return false;
		}

		Function overlayFunc = funcMgr.getFunctionAt(targetAddr);
		if (overlayFunc == null) {
			Program program = funcMgr.getProgram();
			if (program.getListing().getInstructionAt(targetAddr) == null) {
				// The stub's target never became code. Creating a function anyway
				// would plant a 1-byte husk over undefined bytes -- worse than no
				// function at all, because it looks resolved to every downstream
				// consumer. Leave the stub unthunked and say so.
				log.appendMsg(String.format(
					"RTLink: no code at target %s for stub %s; stub left unthunked",
					targetAddr, stubAddr));
				return false;
			}
			// The target is code but the bulk CreateFunctionCmd did not cover it
			// (e.g. the repair path found a new stub). Create it with a real
			// flow-computed body, never a fabricated 1-byte one.
			new CreateFunctionCmd(targetAddr).applyTo(program);
			overlayFunc = funcMgr.getFunctionAt(targetAddr);
			if (overlayFunc == null) {
				log.appendMsg(String.format(
					"RTLink: could not create target function at %s for stub %s " +
						"(target is likely inside another function's body)",
					targetAddr, stubAddr));
				return false;
			}
		}

		// A thunk delegates its signature to its target, so a far call site only decodes
		// correctly when the target carries a far convention. Stamp it before wiring.
		stampFarConvention(overlayFunc, log);

		// A no-return flag on the overlay target truncates the decompilation of every
		// caller of every stub that forwards to it: stub thunks delegate hasNoReturn()
		// to their target. Ghidra's no-return discovery mis-fires on dispatch stubs
		// while overlay flow is still unresolved (the stub's JMPF 0000:offset decodes
		// as a jump into unmapped memory), and setNoReturn(true) on the stub thunk
		// lands on the overlay target. If the target's disassembled body demonstrably
		// returns, the flag is stale — clear it.
		if (overlayFunc.hasNoReturn() && bodyReturns(overlayFunc)) {
			log.appendMsg(String.format(
				"RTLink: clearing stale no-return flag on %s at %s (body returns)",
				overlayFunc.getName(), targetAddr));
			overlayFunc.setNoReturn(false);
		}

		Function existingStub = funcMgr.getFunctionAt(stubAddr);
		if (existingStub != null) {
			// Already the correct thunk (e.g. a re-run) — nothing to do.
			if (existingStub.isThunk() &&
				overlayFunc.equals(existingStub.getThunkedFunction(false))) {
				return true;
			}
			try {
				// Clear any no-return flag discovered while the stub was still a
				// plain function before converting it: a dispatch stub returns iff
				// its overlay target returns.
				existingStub.setNoReturn(false);
				existingStub.setThunkedFunction(overlayFunc);
				return true;
			}
			catch (IllegalArgumentException e) {
				// A plain function was already carved at the stub (auto-analysis
				// reaches it from a real CALLF before we run) and cannot be
				// converted in place. Remove it and recreate below as a thunk so
				// the stub still forwards to its overlay target.
				log.appendMsg(String.format(
					"RTLink: recreating stub thunk at %s -> %s (%s)",
					stubAddr, targetAddr, e.getMessage()));
				funcMgr.removeFunction(stubAddr);
			}
		}

		try {
			AddressSet stubBody = new AddressSet(stubAddr, stubAddr.add(stubSize - 1));
			funcMgr.createThunkFunction(null, null, stubAddr, stubBody,
				overlayFunc, SourceType.ANALYSIS);
			return true;
		}
		catch (OverlappingFunctionException e) {
			log.appendMsg(String.format(
				"RTLink: could not create stub thunk at %s -> %s: %s",
				stubAddr, targetAddr, e.getMessage()));
			return false;
		}
	}

	/**
	 * Drop the disassembler's stale ERROR bookmarks from a stub we just resolved, and
	 * remember the stub's body so {@link #analysisEnded} can sweep it again.
	 * <p>
	 * A dispatch stub's {@code JMPF 0000:offset} points into unmapped memory until the
	 * overlay manager patches it at run time, so every disassembly of the stub hits
	 * "Could not follow disassembly flow into non-existing memory" and drops an ERROR
	 * "Bad Instruction" bookmark. This analyzer relocates the page, resolves the stub
	 * and wires it to a real thunk target — which makes that mark a fossil — but nothing
	 * removed it: a fresh VICEROY.EXE import carried 540 ERROR bookmarks, every one of
	 * them on a correctly resolved stub. An error channel that is 100% false positives
	 * is worse than no channel: it is the disassembler's own record of what it could not
	 * decode, and it was reporting 540 broken things in a DB where nothing was broken.
	 * <p>
	 * Only resolved stubs are cleared and recorded. A stub whose resolution genuinely
	 * failed keeps its bookmark (and its log line), so {@code filter=error} still means
	 * something.
	 */
	private void clearStubErrorBookmarks(Program program, StubTarget stub,
			TaskMonitor monitor) throws CancelledException {
		AddressSet stubBody;
		try {
			stubBody = new AddressSet(stub.stubAddr(), stub.stubAddr().add(stub.stubSize() - 1));
		}
		catch (AddressOutOfBoundsException e) {
			// Stub body runs off the end of its block — nothing to clear.
			return;
		}
		// Clear both severities: a resolved stub whose overlay target offset is 0 carries a
		// JMPF 0000:0000 whose literal (unrelocated) operand the disassembler flags as a
		// WARNING ("flow into non-existing memory at 0000:0000"), while a conflicting decode
		// leaves an ERROR — both are stale once the stub is a thunk to its real target.
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(stubBody, BookmarkType.ERROR, monitor);
		bookmarkMgr.removeBookmarks(stubBody, BookmarkType.WARNING, monitor);
		resolvedStubBodies.add(stubBody);
	}

	/**
	 * Sweep the stale ERROR bookmarks off the stubs this analyzer resolved, once all
	 * other analyzers are done.
	 * <p>
	 * Clearing at resolve time is not enough on a fresh import: this analyzer runs at
	 * {@code FORMAT_ANALYSIS.after()} — it has to, since it creates the overlay memory
	 * blocks everything else depends on — so it resolves each stub <em>before</em> the
	 * disassembler ever walks into it. The "Bad Instruction" marks are therefore stamped
	 * after we are finished, and are already stale the moment they are written. Removing
	 * them when analysis ends is the only point at which both facts are on the table.
	 * The resolve-time clear still matters for the retrofit/one-shot path, where the
	 * marks are already present when we run.
	 */
	@Override
	public void analysisEnded(Program program) {
		// Repair husk functions now that every function is finally in place. added() runs at
		// FORMAT_ANALYSIS.after (before the husks exist), so it can only repair them on the
		// retrofit/one-shot path; and even the dead-last flow-repair pass runs before the
		// final re-analysis round that fabricates these call-target husks (its once-per-txn
		// guard then skips its re-invocation). analysisEnded is the one hook after every
		// round. Idempotent — a no-op once no husks remain — so it is harmless on the
		// retrofit path where added() already ran it. Failures go to a throwaway log
		// because analysisEnded cannot surface the analysis warnings dialog.
		try {
			program.withTransaction("RTLink: repair husk functions",
				() -> repairHuskFunctions(program, new MessageLog(), TaskMonitor.DUMMY));
		}
		catch (CancelledException e) {
			// DUMMY monitor never cancels
		}

		if (resolvedStubBodies.isEmpty()) {
			return;
		}
		AddressSet stubs = resolvedStubBodies;
		resolvedStubBodies = new AddressSet();

		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		// Both severities are stale on a resolved stub (see clearStubErrorBookmarks): a
		// conflicting decode leaves an ERROR, an offset-0 stub's JMPF 0000:0000 leaves a
		// WARNING, and neither describes anything broken once the stub is a thunk.
		long stale = bookmarkMgr.getBookmarkAddresses(BookmarkType.ERROR)
				.union(bookmarkMgr.getBookmarkAddresses(BookmarkType.WARNING))
				.intersect(stubs)
				.getNumAddresses();
		if (stale == 0) {
			return;
		}
		try {
			program.withTransaction("RTLink: clear resolved-stub bad-instruction bookmarks",
				() -> {
					bookmarkMgr.removeBookmarks(stubs, BookmarkType.ERROR, TaskMonitor.DUMMY);
					bookmarkMgr.removeBookmarks(stubs, BookmarkType.WARNING, TaskMonitor.DUMMY);
				});
		}
		catch (CancelledException e) {
			return; // DUMMY monitor never cancels
		}
		Msg.info(this, "RTLink/Plus: Cleared " + stale +
			" stale Bad Instruction bookmark(s) on resolved dispatch stubs");
	}

	/**
	 * Returns true if {@code func}'s disassembled body contains a return instruction —
	 * proof that a no-return flag on it is wrong.
	 */
	private static boolean bodyReturns(Function func) {
		InstructionIterator it =
			func.getProgram().getListing().getInstructions(func.getBody(), true);
		while (it.hasNext()) {
			if (it.next().getFlowType() == RefType.TERMINATOR) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Stamp {@code __cdecl16far} on a stub/trampoline target whose signature Ghidra has
	 * not yet pinned down. A thunk delegates its signature to its target, so a far call
	 * site only decodes correctly when the target carries a far convention; left on the
	 * x86-16 default (near) convention the target models its parameters one stack slot
	 * too low and every caller decompiles with a junk leading argument that swallows a
	 * real one. Every function reached through a jump-table dispatch stub or a resident
	 * trampoline is far-called by construction, so this is safe for exactly that set.
	 * User-provided signatures are never touched, and the default/unknown-convention
	 * guard makes re-runs idempotent (a second pass sees the convention already set).
	 */
	private static void stampFarConvention(Function overlayFunc, MessageLog log) {
		SourceType sigSource = overlayFunc.getSignatureSource();
		if (sigSource != SourceType.DEFAULT && sigSource != SourceType.ANALYSIS) {
			return;
		}
		String convention = overlayFunc.getCallingConventionName();
		boolean conventionUnset = overlayFunc.getCallingConvention() == null ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention);
		if (!conventionUnset) {
			return;
		}
		try {
			overlayFunc.setCallingConvention(FAR_CALLING_CONVENTION);
		}
		catch (InvalidInputException e) {
			log.appendMsg(String.format("RTLink: could not set %s on %s at %s: %s",
				FAR_CALLING_CONVENTION, overlayFunc.getName(), overlayFunc.getEntryPoint(),
				e.getMessage()));
		}
	}

	/**
	 * Find and repair "husk" functions: functions whose entry holds no instruction, so
	 * their body collapsed to a single byte of undefined data. Programs analyzed before
	 * the deferred-call-flow fix in {@code Disassembler} are full of them: a restricted
	 * disassembly (the overlay pass) silently abandoned every pending call flow the
	 * first time one landed outside the restriction, so intra-page near-call targets
	 * were never disassembled, and every later {@code CreateFunctionCmd} on such a
	 * target fabricated a 1-byte body over the undefined bytes.
	 * <p>
	 * Each husk entry is disassembled with unrestricted flow, its body recomputed, and
	 * call targets newly exposed by that code are promoted to functions of their own.
	 * Every husk found is counted; entries that still fail to disassemble are reported
	 * in the analysis log with target and reason.
	 */
	/**
	 * Disassemble every husk function (a function object with no code at its entry, left
	 * by CreateFunctionCmd over a call target the disassembler never followed) and rebuild
	 * its body from the now-real flow. Package-private static so {@link
	 * RTLinkFlowRepairAnalyzer} can invoke it on the fresh-import path: this analyzer runs
	 * at FORMAT_ANALYSIS.after, before the husks are fabricated, so it can only repair them
	 * on the retrofit/one-shot path; the dead-last flow-repair pass runs after they exist.
	 */
	static void repairHuskFunctions(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager funcMgr = program.getFunctionManager();
		Memory memory = program.getMemory();

		List<Address> husks = new ArrayList<>();
		for (Function function : funcMgr.getFunctions(true)) {
			monitor.checkCancelled();
			if (function.isThunk() || function.isExternal()) {
				continue;
			}
			Address entry = function.getEntryPoint();
			MemoryBlock block = memory.getBlock(entry);
			if (block == null || !block.isExecute() || !block.isInitialized()) {
				continue;
			}
			if (listing.getInstructionAt(entry) == null &&
				listing.getInstructionContaining(entry) == null) {
				husks.add(entry);
				Msg.debug(RTLinkOverlayAnalyzer.class, "RTLink: husk function (no code at entry) " +
					function.getName() + " at " + entry);
			}
		}
		if (husks.isEmpty()) {
			return;
		}

		monitor.setMessage("RTLink: Repairing husk functions...");
		AddressSet repaired = new AddressSet();
		AddressSet newCode = new AddressSet();
		int failed = 0;
		for (Address entry : husks) {
			monitor.checkCancelled();
			DisassembleCommand disCmd = new DisassembleCommand(entry, null, true);
			disCmd.applyTo(program, monitor);
			if (listing.getInstructionAt(entry) == null) {
				log.appendMsg(String.format(
					"RTLink: husk function at %s could not be repaired: %s", entry,
					disCmd.getStatusMsg()));
				failed++;
				continue;
			}
			repaired.add(entry);
			AddressSetView disassembled = disCmd.getDisassembledAddressSet();
			if (disassembled != null) {
				newCode.add(disassembled);
			}
		}

		// The repair exposed new code; promote its call targets to functions so the
		// husk's callees (reachable only through it) become functions too.
		AddressSet callTargets = new AddressSet();
		ReferenceManager refMgr = program.getReferenceManager();
		AddressIterator sources = refMgr.getReferenceSourceIterator(newCode, true);
		while (sources.hasNext()) {
			monitor.checkCancelled();
			for (Reference ref : refMgr.getReferencesFrom(sources.next())) {
				Address target = ref.getToAddress();
				if (ref.getReferenceType().isCall() &&
					listing.getInstructionAt(target) != null &&
					funcMgr.getFunctionAt(target) == null) {
					callTargets.add(target);
				}
			}
		}
		if (!callTargets.isEmpty()) {
			new CreateFunctionCmd(callTargets, SourceType.ANALYSIS).applyTo(program, monitor);
		}

		// Recompute each repaired function's body from its now-real flow.
		for (Address entry : repaired.getAddresses(true)) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, listing.getInstructionAt(entry),
				monitor);
		}

		// Msg.info only, never log.appendMsg: this is a clean-run success count, and any
		// content in the analysis MessageLog pops the warnings dialog. The failures above
		// did go to the MessageLog -- those are genuine.
		Msg.info(RTLinkOverlayAnalyzer.class, String.format(
			"RTLink: Repaired %d husk function(s) (no code at entry), " +
				"%d new function(s) at exposed call targets%s",
			repaired.getNumAddresses(), callTargets.getNumAddresses(),
			failed > 0 ? ", " + failed + " unrepairable" : ""));
	}

	/**
	 * Re-run dispatch-stub discovery and thunk wiring — including resident-target
	 * trampolines — on a program whose overlays were created by a prior (possibly
	 * older) run of this analyzer, without re-importing.
	 * <p>
	 * Everything this does is idempotent: existing labels, references and functions are
	 * kept (a plain function converted to a thunk keeps its user-defined name), correct
	 * thunks are left untouched, and {@link #createThunkAtStub} repairs stubs that
	 * ended up as plain functions as well as overlay targets carrying a stale
	 * no-return flag (which silently truncates the decompilation of every caller of
	 * every stub forwarding to them).
	 */
	private void repairStubThunks(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			return;
		}
		FileBytes fileBytes = allFileBytes.get(0);
		try (FileBytesProvider provider = new FileBytesProvider(fileBytes)) {
			BinaryReader reader = new BinaryReader(provider, true);
			OldDOSHeader header = new OldDOSHeader(reader);
			long overlayStart = (computeImageEnd(header) + 15) & ~15L;
			List<RTLinkOverlayPage> allPages =
				RTLinkOverlayPage.parseAllPages(reader, overlayStart, fileBytes.getSize());
			if (allPages.size() < 2) {
				return;
			}

			// Rebuild the OverlayBlockInfo list from the existing blocks, mirroring
			// createOverlayBlocks()'s skip logic so stub page indexing lines up.
			// Programs imported before the record-0 fix name record i's block
			// OVERLAY_(i-1) and have no block for record 0 at all. Detect that legacy
			// scheme by the absence of a block for the last code-bearing record, and
			// keep pairing each record with the block that holds its code, so One Shot
			// still repairs old DBs (whose record-0 stubs stay unresolved — resolving
			// them needs a re-import).
			Memory memory = program.getMemory();
			int lastCodeRecord = -1;
			for (RTLinkOverlayPage page : allPages) {
				if (page.getCodeSize() > 0) {
					lastCodeRecord = page.getPageIndex();
				}
			}
			int width = nameWidth(allPages.get(allPages.size() - 1).getPageIndex());
			boolean legacyNames = lastCodeRecord >= 0 &&
				findOverlayBlock(memory, lastCodeRecord, width) == null;
			List<OverlayBlockInfo> overlayBlocks = new ArrayList<>();
			for (RTLinkOverlayPage page : allPages) {
				if (page.getCodeSize() <= 0) {
					continue;
				}
				int nameIndex = page.getPageIndex() - (legacyNames ? 1 : 0);
				if (nameIndex < 0) {
					continue; // legacy program: no block exists for record 0
				}
				MemoryBlock block = findOverlayBlock(memory, nameIndex, width);
				if (block == null) {
					// Unexpected layout (blocks renamed/removed); leave the program alone.
					return;
				}
				overlayBlocks.add(new OverlayBlockInfo(page, block));
				// Retrofit the module base record onto programs imported before it
				// existed, so overlay switch-table recovery works there on re-analysis.
				// discoverAndProcessStubs() then merges in the stub-only modules.
				recordModuleBases(program, block.getName(), page.getModuleBases());
			}

			discoverAndProcessStubs(program, overlayBlocks, log, monitor);
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendMsg("RTLink: stub thunk retrofit failed: " + e.getMessage());
		}
	}

	private static void labelAddress(SymbolTable symbolTable, String label, Address addr) {
		try {
			Symbol existing = symbolTable.getPrimarySymbol(addr);
			if (existing == null || existing.isDynamic()) {
				symbolTable.createLabel(addr, label, SourceType.ANALYSIS);
			}
		}
		catch (InvalidInputException e) {
			// ignore
		}
	}

	private void markupOverlayHeaders(Program program, FileBytes fileBytes,
			List<RTLinkOverlayPage> allPages, MessageLog log, TaskMonitor monitor)
			throws Exception {
		int width = nameWidth(allPages.get(allPages.size() - 1).getPageIndex());
		for (RTLinkOverlayPage page : allPages) {
			monitor.checkCancelled();

			int headerAndRelocSize = page.getHeader().getOverheadSizeBytes();
			Address headerBase = AddressSpace.OTHER_SPACE.getAddress(0);
			String name = String.format("RTLINK_HDR_%0" + width + "d", page.getPageIndex());

			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				name, headerBase, fileBytes, page.getFileOffset(), headerAndRelocSize,
				"RTLink page " + page.getPageIndex() + " header", "RTLink",
				false, false, false, log);

			if (headerBlock == null) {
				continue;
			}

			try {
				Address addr = headerBlock.getStart();
				DataUtilities.createData(program, addr, page.getHeader().toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

				if (!page.getRelocations().isEmpty()) {
					var relocType = page.getRelocations().get(0).toDataType();
					int relocSize = relocType.getLength();
					Address relocAddr = addr.add(RTLinkPageHeader.HEADER_SIZE);
					for (int j = 0; j < page.getRelocations().size(); j++) {
						monitor.checkCancelled();
						DataUtilities.createData(program,
							relocAddr.add((long) j * relocSize), relocType, -1,
							DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					}
				}
			}
			catch (Exception e) {
				log.appendMsg(
					"RTLink: Failed to markup header for page " + page.getPageIndex());
			}
		}
	}
}
