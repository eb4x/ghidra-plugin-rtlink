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
// Headless smoke test for the RTLink extension: run as -postScript after a fresh
// import+analysis of an RTLink-linked overlay EXE (see the smokeTest gradle task).
// Asserts that the RTLink analyzers actually ran: overlay memory blocks were created
// and code ended up inside them. Prints its own verdict because analyzeHeadless
// exits 0 even when a post-script throws.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class RTLinkSmokeScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		int overlayBlocks = 0;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName().startsWith("OVERLAY_")) {
				overlayBlocks++;
			}
		}
		if (overlayBlocks == 0) {
			println("UNEXPECTED: no OVERLAY_ memory blocks — RTLinkOverlayAnalyzer did not run?");
			return;
		}
		println("smoke: " + overlayBlocks + " overlay blocks");

		int overlayFunctions = 0;
		int thunks = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getEntryPoint().getAddressSpace().getName().startsWith("OVERLAY_")) {
				overlayFunctions++;
			}
			if (f.isThunk()) {
				thunks++;
			}
		}
		if (overlayFunctions == 0) {
			println("UNEXPECTED: overlay blocks exist but contain no functions");
			return;
		}
		println("smoke: " + overlayFunctions + " functions in overlay blocks, " +
			thunks + " thunks program-wide");

		println("SMOKE COMPLETE");
	}
}
