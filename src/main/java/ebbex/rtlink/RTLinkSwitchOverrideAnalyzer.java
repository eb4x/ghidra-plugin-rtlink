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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.JumpTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Tells the decompiler where the RTLink/Plus switch tables — resident and overlay — really go.
 * <p>
 * {@link RTLinkSwitchTableAnalyzer} repairs the <i>references</i>, which is what keeps the listing
 * and function bodies sane. It cannot repair the decompiler, whose own p-code still resolves
 * {@code JMP word ptr CS:[BX+disp]} against the 64KB-page segment that the x86 {@code currentCS}
 * subconstructor synthesises — so those functions still decompile into whichever segment the page
 * happens to cover, with "Unable to resolve constructor" errors along the way.
 * <p>
 * A jump-table override fixes that, and Ghidra stores one purely as symbols: a namespace
 * {@code <func>::override::jmp_<branchaddr>} holding a {@code switch} label at the branch and a
 * {@code case_N} label at each destination (see {@link JumpTable#writeOverride}). The decompiler
 * reads them back through {@code HighFunction.grabOverrides()} and emits
 * "Switch is manually overridden" instead of guessing.
 * <p>
 * This runs after {@code FUNCTION_ANALYSIS} because {@code grabOverrides()} ignores anything that is
 * not a {@link FunctionDB} — the override symbols have nowhere to live until the dispatcher has a
 * defined function to hang a namespace off.
 */
public class RTLinkSwitchOverrideAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Switch Override";
	private static final String DESCRIPTION =
		"Writes decompiler jump-table overrides for the CS-relative switches recovered by the " +
			"RTLink/Plus Switch Table analyzer, so the decompiler stops resolving them against " +
			"the 64KB-page segment.";

	public RTLinkSwitchOverrideAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		int written = 0;

		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();

			List<Address> destinations = RTLinkSwitchTableAnalyzer.recoverTable(program,
				instruction);
			if (destinations == null) {
				continue;
			}
			Address switchAddress = instruction.getMinAddress();
			Function function =
				program.getFunctionManager().getFunctionContaining(switchAddress);
			if (!(function instanceof FunctionDB)) {
				// No defined function yet; a later pass over this instruction will catch it.
				continue;
			}

			JumpTable override = new JumpTable(switchAddress, new ArrayList<>(destinations), true,
				EquateSymbol.FORMAT_DEFAULT);
			try {
				// writeOverride() clears the jmp_<addr> namespace first, so re-running is safe.
				override.writeOverride(function);
				written++;
			}
			catch (InvalidInputException e) {
				log.appendMsg(String.format(
					"RTLink: could not override switch at %s in %s: %s", switchAddress,
					function.getName(), e.getMessage()));
			}
		}

		if (written > 0) {
			// Msg.info only, never log.appendMsg: any content in the analysis MessageLog makes
			// AutoAnalysisPlugin.analysisEnded() pop a "There were warnings/errors issued during
			// analysis" dialog, so routing a success count there cries wolf on a clean run. The
			// MessageLog is for things that went wrong (see the failure paths above).
			Msg.info(this,
				String.format("RTLink/Plus: Wrote %d switch table override(s)", written));
		}
		return true;
	}
}
