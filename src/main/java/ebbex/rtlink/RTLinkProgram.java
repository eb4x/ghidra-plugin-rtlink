package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.util.opinion.MzLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * Everything the analyzers record in a program for one another, the checks every one of
 * them makes before acting, and how they report what they did. One analyzer writes each record and later ones read it: that is
 * how the pipeline hands results along, since an analyzer must work as well on a program
 * reopened, or re-run from One Shot, as on a fresh import.
 * <p>
 * The records are program-info options (flags, the overlay module bases, the VM seed count)
 * and one user property map (the switches still waiting for their override). The program is the only state; nothing
 * here is cached.
 */
final class RTLinkProgram {

	/** Set when overlay analysis completes; every other RTLink pass is gated on it. */
	private static final String OVERLAY_ANALYZED = "RTLink Overlay Analyzed";

	/** Set once DS (DGROUP) has been assumed over the program's compiled code. */
	private static final String DATA_SEGMENT_ASSUMED = "RTLink Data Segment Assumed";

	/**
	 * Key prefix, completed with an overlay block's name, for that page's module base
	 * paragraphs as comma-separated hex — the anchors CS-relative displacements in module code
	 * are relative to.
	 */
	private static final String MODULE_BASES_PREFIX = "RTLink Module Bases ";

	/**
	 * How many VM-runtime function entries were seeded. Read by name by the headless smoke and
	 * VICEROY scripts, which cannot reach this package.
	 */
	private static final String VM_RUNTIME_SEEDS = "RTLink VM Runtime Seeds";

	/**
	 * Set once the program is found to be float-emulated. The detector reads the very bytes
	 * the rewrite replaces, so without it a later pass would find none and decline.
	 */
	private static final String FLOAT_EMULATED = "DOS Emulated Floating Point";

	/**
	 * User property map holding, per switch dispatch still waiting for its decompiler override,
	 * the targets the table pass recovered (hex offsets, space-separated).
	 */
	private static final String PENDING_SWITCHES = "RTLink pending switch";

	/** The target-less marks of 0.8.20 and earlier; see {@link #dropLegacySwitchMarks}. */
	private static final String LEGACY_SWITCH_DISPATCHES = "RTLink switch dispatch";

	private RTLinkProgram() {
	}

	// ---------------------------------------------------------------- gates

	/**
	 * True if {@code program} is an MZ executable with a segmented (16-bit real mode) default
	 * address space — what every RTLink analyzer's {@code canAnalyze} accepts. It is asked
	 * before analysis, when nothing else is known, so it cannot say whether the program is
	 * RTLink; {@link #isOverlayAnalyzed} does that afterwards.
	 */
	static boolean isSegmentedMz(Program program) {
		return MzLoader.MZ_NAME.equals(program.getExecutableFormat()) &&
			program.getAddressFactory().getDefaultAddressSpace() instanceof SegmentedAddressSpace;
	}

	/**
	 * True if the analyzer named {@code name} is enabled for {@code program}. Needed in
	 * {@code analysisEnded}, which Ghidra calls on every analyzer whose {@code canAnalyze}
	 * passed, enabled or not.
	 */
	static boolean isAnalyzerEnabled(Program program, String name) {
		return program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(name, true);
	}

	/**
	 * Log {@code count} through {@code format} if it is nonzero. A success count goes to
	 * {@link Msg#info}, never the analysis {@code MessageLog}: any content there makes
	 * {@code AutoAnalysisPlugin} pop a "warnings/errors issued during analysis" dialog, so
	 * the MessageLog is for genuine failures only.
	 */
	static void report(Object origin, long count, String format) {
		if (count > 0) {
			Msg.info(origin, String.format(format, count));
		}
	}

	// ---------------------------------------------------------------- flags

	static boolean isOverlayAnalyzed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(OVERLAY_ANALYZED, false);
	}

	static void markOverlayAnalyzed(Program program) {
		program.getOptions(Program.PROGRAM_INFO).setBoolean(OVERLAY_ANALYZED, true);
	}

	static boolean isDataSegmentAssumed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(DATA_SEGMENT_ASSUMED, false);
	}

	static void markDataSegmentAssumed(Program program) {
		program.getOptions(Program.PROGRAM_INFO).setBoolean(DATA_SEGMENT_ASSUMED, true);
	}

	static boolean isFloatEmulated(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(FLOAT_EMULATED, false);
	}

	static void markFloatEmulated(Program program) {
		program.getOptions(Program.PROGRAM_INFO).setBoolean(FLOAT_EMULATED, true);
	}

	static void recordVmRuntimeSeeds(Program program, int count) {
		program.getOptions(Program.PROGRAM_INFO).setInt(VM_RUNTIME_SEEDS, count);
	}

	// ---------------------------------------------------------------- module bases

	/** Record {@code bases} as the module base paragraphs of the overlay block {@code blockName}. */
	static void recordModuleBases(Program program, String blockName, Collection<Integer> bases) {
		String text = bases.stream().map(Integer::toHexString).collect(Collectors.joining(","));
		program.getOptions(Program.PROGRAM_INFO).setString(MODULE_BASES_PREFIX + blockName, text);
	}

	/**
	 * The module base paragraphs recorded for {@code block}, in recorded (ascending) order, or
	 * null if there is no valid record.
	 */
	static List<Integer> moduleBases(Program program, MemoryBlock block) {
		String recorded = program.getOptions(Program.PROGRAM_INFO)
				.getString(MODULE_BASES_PREFIX + block.getName(), null);
		if (recorded == null || recorded.isEmpty()) {
			return null;
		}
		List<Integer> bases = new ArrayList<>();
		for (String base : recorded.split(",")) {
			try {
				bases.add(Integer.parseInt(base.trim(), 16));
			}
			catch (NumberFormatException _) {
				return null;
			}
		}
		return bases;
	}

	// ---------------------------------------------------------------- pending switches

	/**
	 * Record {@code targets} as the switch at {@code dispatch} that still needs its override.
	 * The targets are kept with the record because the references cannot be trusted later:
	 * stock switch analysis may replace them before the function exists.
	 */
	static void recordSwitch(Program program, Address dispatch, List<Address> targets) {
		PropertyMapManager properties = program.getUsrPropertyManager();
		StringPropertyMap pending = properties.getStringPropertyMap(PENDING_SWITCHES);
		if (pending == null) {
			try {
				pending = properties.createStringPropertyMap(PENDING_SWITCHES);
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(e); // just looked it up
			}
		}
		pending.add(dispatch, targets.stream()
				.map(target -> Long.toHexString(target.getOffset()))
				.collect(Collectors.joining(" ")));
	}

	/** The dispatches within {@code set} still waiting for their override. */
	static AddressIterator pendingSwitches(Program program, AddressSetView set) {
		StringPropertyMap pending = program.getUsrPropertyManager().getStringPropertyMap(PENDING_SWITCHES);
		return pending == null ? AddressIterator.EMPTY_ITERATOR : pending.getPropertyIterator(set);
	}

	/** The targets recorded for the pending switch at {@code dispatch}, or an empty list. */
	static List<Address> switchTargets(Program program, Address dispatch) {
		StringPropertyMap pending = program.getUsrPropertyManager().getStringPropertyMap(PENDING_SWITCHES);
		String recorded = pending == null ? null : pending.getString(dispatch);
		if (recorded == null || recorded.isBlank()) {
			return List.of();
		}
		List<Address> targets = new ArrayList<>();
		for (String offset : recorded.split(" ")) {
			try {
				targets.add(dispatch.getNewAddress(Long.parseLong(offset, 16)));
			}
			catch (NumberFormatException _) {
				return List.of();
			}
		}
		return targets;
	}

	/** Drop the pending record at {@code dispatch}: its override exists or cannot be written. */
	static void consumeSwitch(Program program, Address dispatch) {
		StringPropertyMap pending = program.getUsrPropertyManager().getStringPropertyMap(PENDING_SWITCHES);
		if (pending != null) {
			pending.remove(dispatch);
		}
	}

	/**
	 * Remove the switch marks of 0.8.20 and earlier, which carried no targets. Every marked
	 * dispatch in {@code /COLONIZE/VICEROY.EXE} already has its override (confirmed by viceroy),
	 * so nothing is lost. Delete once viceroy confirms the program has been through it.
	 */
	static void dropLegacySwitchMarks(Program program) {
		PropertyMapManager properties = program.getUsrPropertyManager();
		if (properties.getVoidPropertyMap(LEGACY_SWITCH_DISPATCHES) != null) {
			properties.removePropertyMap(LEGACY_SWITCH_DISPATCHES);
		}
	}
}
