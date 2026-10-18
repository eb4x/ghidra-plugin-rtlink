package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the CS-relative switch tables in RTLink/Plus resident code, which the stock
 * decompiler-driven switch analysis gets wrong.
 * <p>
 * <b>Why the stock path fails.</b> A resident logical segment is based at a paragraph that is not a
 * 64KB-page boundary (e.g. {@code 1aea:000b}). The x86 {@code currentCS} subconstructor
 * ({@code ia.sinc}) does not read the CS register; it recomputes a code segment from the program
 * counter as {@code (inst_next >> 4) & 0xf000}, which for such a block yields the enclosing page
 * ({@code 0x1000}) instead of the real paragraph. That recompute exists on purpose — {@code CALLF}
 * ({@code ptr1616}) writes the callee's segment into CS and nothing restores it on return, so CS is
 * untrustworthy — but it is correct only when a code segment happens to start on a page boundary.
 * The write-back also lands <i>before</i> the memory operand's address is built, so both the table
 * load and the jump target resolve against the page segment: {@code JMP word ptr CS:[BX+0x22]} at
 * {@code 1aea:001d} reads its table at {@code 1000:0022} rather than {@code 1aea:0022} and scatters
 * computed-jump references across unrelated segments.
 * <p>
 * <b>What this does.</b> It matches the dispatch idiom, reads the table at the block's true
 * paragraph, and lays down the correct {@code COMPUTED_JUMP} references itself. That both fixes the
 * flow and — because {@code DecompilerSwitchAnalyzer} skips any computed branch that already carries
 * computed references — stops the stock analyzer from ever disassembling the bogus targets. It must
 * therefore run <i>before</i> {@code CODE_ANALYSIS}: once the wrong references and their wrong
 * disassembly exist, nothing rewrites them.
 * <p>
 * Fixing the references leaves the decompiler's own p-code still reading the table at the page
 * segment. {@link RTLinkSwitchOverrideAnalyzer} completes the repair once functions exist.
 * <p>
 * <b>The formatter FSM</b> fails for a third reason: its switch index is produced by
 * {@code XLAT}, so no {@code CMP} in the instruction stream bounds it and the decompiler
 * fabricates cases for the whole byte range. The bound lives in the FSM's own state table;
 * see {@link FormatterFsm}.
 * <p>
 * <b>Overlay blocks</b> fail differently. They are based at {@code 1000:0000}, so the paragraph
 * {@code currentCS} synthesises is right — but only for the page's <i>first</i> module. RTLink
 * packs several link-time modules into one page, and each executes with CS = page frame + its own
 * base paragraph, so a dispatch in a later module reads its table (and interprets every entry)
 * relative to that module base, which nothing in the address stream reveals. The bases are
 * recorded per block by {@link RTLinkOverlayAnalyzer} when the overlay is created; the module
 * containing the dispatch is the one whose base is nearest at or below it.
 * <p>
 * Each form is read by its own class ({@link CsSwitchTables}, {@link OverlaySwitchTables},
 * {@link DataSwitchTables}, {@link FormatterFsm}); this class only chooses between them and
 * lays down what they find.
 */
public class RTLinkSwitchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Switch Table";
	private static final String DESCRIPTION =
		"Recovers CS-relative jump tables in resident code whose segment is not 64KB-page " +
			"aligned, which the x86 currentCS constructor resolves against the wrong paragraph, " +
			"and module-relative jump tables in overlay pages.";

	public RTLinkSwitchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Before CODE_ANALYSIS, which is where DecompilerSwitchAnalyzer runs. It ignores any
		// computed branch that already has computed references, so winning this race is what
		// keeps the bogus targets from being disassembled into other segments.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkProgram.isSegmentedMz(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (!RTLinkProgram.isOverlayAnalyzed(program)) {
			return false; // canAnalyze accepts any segmented MZ; these tables are RTLink's
		}
		ReferenceManager refManager = program.getReferenceManager();
		AddressSet targets = new AddressSet();
		List<Instruction> dispatches = new ArrayList<>();

		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();

			List<Address> destinations = recoverTable(program, instruction);
			if (destinations == null || hasComputedReference(refManager, instruction)) {
				continue;
			}
			for (Address destination : destinations) {
				refManager.addMemoryReference(instruction.getMinAddress(), destination,
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
				targets.addRange(destination, destination);
			}
			// The mark and the references are what RTLinkSwitchOverrideAnalyzer writes its
			// override from: re-deriving the table later would read a program that has
			// changed since (more functions, more code) and could disagree with them.
			RTLinkProgram.markSwitchDispatch(program, instruction.getMinAddress());
			dispatches.add(instruction);
		}

		int recovered = dispatches.size();
		if (recovered == 0) {
			return true;
		}
		// Disassemble the real targets now; leaving them undefined would let a later pass drift
		// back into the table bytes.
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);

		// The references above extend flows that existing function bodies do not yet
		// cover, and nothing downstream recomputes them for switches resolved here
		// (DecompilerSwitchAnalyzer performs this fixup only for its own). Left alone,
		// a case region discovered late stays outside its owner's body — in
		// NEBULAR.EXE OVERLAY_19 an entire case chain, containing a second dispatch,
		// was orphaned that way. Fixups run after the whole recovery loop so a body
		// absorbs the case flows of every dispatch it reaches, not just the first.
		for (Instruction dispatch : dispatches) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, dispatch, monitor);
		}

		// Msg.info only — see RTLinkSwitchOverrideAnalyzer: a success count in the analysis
		// MessageLog pops the "warnings/errors issued during analysis" dialog.
		Msg.info(this,
			String.format("RTLink/Plus: Recovered %d switch table(s)", recovered));
		return true;
	}

	/**
	 * Returns the switch destinations for {@code instruction} if it is a CS-relative
	 * dispatch whose table can be read with confidence, otherwise null.
	 */
	static List<Address> recoverTable(Program program, Instruction instruction) {
		MemoryBlock block = program.getMemory().getBlock(instruction.getMinAddress());
		if (block == null || !block.isExecute()) {
			return null;
		}
		if (block.isOverlay()) {
			return OverlaySwitchTables.recover(program, instruction, block);
		}
		List<Address> dataTable = DataSwitchTables.recover(program, instruction, block);
		if (dataTable != null) {
			return dataTable;
		}
		int displacement = CsSwitchTables.displacement(instruction);
		if (displacement < 0) {
			return null;
		}
		// The formatter FSM is matched regardless of segment alignment: its dispatch is
		// unbounded for the decompiler even where currentCS resolves correctly, so it
		// needs the references (and the override) either way.
		List<Address> fsmTable = FormatterFsm.recover(program, instruction, block, displacement);
		if (fsmTable != null) {
			return fsmTable;
		}
		return CsSwitchTables.recoverResident(program, instruction, block, displacement);
	}

	/** True if Ghidra already recorded a computed flow from this branch. */
	private static boolean hasComputedReference(ReferenceManager refManager,
			Instruction instruction) {
		for (Reference reference : refManager.getReferencesFrom(instruction.getMinAddress())) {
			if (reference.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}
}
