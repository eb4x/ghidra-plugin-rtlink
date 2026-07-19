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

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

/**
 * Regression test for {@link RTLinkOverlayAnalyzer#findRuntimeCodeBlocks}.
 *
 * <p>{@code DS = DGROUP} holds for compiler-generated code, not for the RTLink runtime:
 * the overlay manager reloads DS from its own saved-segment slots throughout, and the
 * support code addresses everything CS-relative. Assuming DGROUP over either segment made
 * {@link RTLinkXrefAnalyzer} resolve the runtime's own pointers against DGROUP — a
 * {@code MOV BX,0x44a7} naming a string in the manager's segment became a data reference
 * to {@code DGROUP:44a7}, planting a bogus label on an unrelated game global. On
 * VICEROY.EXE that was 103 references over 19 globals.
 *
 * <p>The memory map mirrors VICEROY.EXE: the VM manager (its {@code 210d}, carrying the
 * fixup-loop fingerprint), the RTLink support code (its {@code 275d}, carrying the error
 * text), an ordinary application block, and DGROUP.
 */
public class RTLinkRuntimeDataSegmentTest extends AbstractGenericTest {

	private static final int DGROUP = 0x2b5a;

	/** The fixup loop the linker stamps into every VM program. */
	private static final String FINGERPRINT_BYTES =
		"e3 19 06 57 d1 e6 d1 e6 ad 8b f8 ad 03 c3 8e c0 " +
			"26 01 15 e2 f3 d1 ee d1 ee 5f 07 c3";

	private static final String RUNTIME_TEXT =
		"Internal error in .RTLink(R)/Plus run-time code.";

	@Test
	public void testRuntimeBlocksAreFoundAndApplicationBlocksAreNot() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DS", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock app = builder.createMemory("CODE_APP", "0x1000:0x0000", 0x40);
			MemoryBlock manager = builder.createMemory("CODE_VM", "0x210d:0x0000", 0x40);
			MemoryBlock support = builder.createMemory("CODE_RTL", "0x275d:0x0000", 0x60);
			MemoryBlock dgroup = builder.createMemory("CODE_DG", "0x2b5a:0x0000", 0x40);
			builder.withTransaction(() -> {
				app.setExecute(true);
				manager.setExecute(true);
				support.setExecute(true);
				dgroup.setExecute(true);
			});

			builder.setBytes("0x210d:0x0010", FINGERPRINT_BYTES);
			builder.setBytes("0x275d:0x0008", asHex(RUNTIME_TEXT));

			Program program = builder.getProgram();
			Set<MemoryBlock> runtime =
				RTLinkOverlayAnalyzer.findRuntimeCodeBlocks(program, DGROUP);

			assertEquals("both halves of the runtime are found", 2, runtime.size());
			assertTrue("VM manager block (fixup-loop fingerprint)", runtime.contains(manager));
			assertTrue("RTLink support block (error text)", runtime.contains(support));
			assertFalse("application code keeps DS = DGROUP", runtime.contains(app));
			assertFalse("DGROUP itself is never disowned", runtime.contains(dgroup));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * A binary with no runtime signature at all — not RTLink, or an unrecognised build —
	 * must not lose the DS assumption anywhere.
	 */
	@Test
	public void testNoSignaturesMeansNoBlocksDisowned() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DS", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock app = builder.createMemory("CODE_APP", "0x1000:0x0000", 0x40);
			builder.withTransaction(() -> app.setExecute(true));

			Set<MemoryBlock> runtime =
				RTLinkOverlayAnalyzer.findRuntimeCodeBlocks(builder.getProgram(), DGROUP);

			assertTrue("nothing is disowned without a signature", runtime.isEmpty());
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * If a signature somehow lands in DGROUP's own block, DGROUP must survive: disowning it
	 * would strip DS from the very code the assumption exists to serve.
	 */
	@Test
	public void testDgroupBlockIsNeverDisowned() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DS", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock dgroup = builder.createMemory("CODE_DG", "0x2b5a:0x0000", 0x40);
			builder.withTransaction(() -> dgroup.setExecute(true));
			builder.setBytes("0x2b5a:0x0010", FINGERPRINT_BYTES);

			Set<MemoryBlock> runtime =
				RTLinkOverlayAnalyzer.findRuntimeCodeBlocks(builder.getProgram(), DGROUP);

			assertTrue("DGROUP keeps DS even carrying the fingerprint", runtime.isEmpty());
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The runtime blocks are also swept clean of DGROUP references at the end of analysis.
	 * Leaving DS unset stops *our* passes from inventing them, but Ghidra's stock
	 * constant-propagation reference analyzer propagates a DS value through the runtime's
	 * hand-written assembly regardless and resolves against it — 46 such references on a
	 * fresh VICEROY.EXE, none of them founded (CS-overridden operands, register-indirect
	 * accesses, and a bitmask constant). References from application code are untouched.
	 */
	@Test
	public void testRuntimeDgroupReferencesAreSweptButApplicationOnesSurvive() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DS", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock app = builder.createMemory("CODE_APP", "0x1000:0x0000", 0x40);
			MemoryBlock manager = builder.createMemory("CODE_VM", "0x210d:0x0000", 0x40);
			builder.createUninitializedMemory("DATA", "0x2b5a:0x1000", 0x100);
			builder.withTransaction(() -> {
				app.setExecute(true);
				manager.setExecute(true);
			});
			builder.setBytes("0x210d:0x0010", FINGERPRINT_BYTES);

			Program program = builder.getProgram();
			// DS is asserted over compiler-generated code only — which is also how the sweep
			// recovers DGROUP.
			builder.withTransaction(() -> {
				try {
					program.getProgramContext().setValue(
						program.getProgramContext().getRegister("DS"), app.getStart(),
						app.getEnd(), java.math.BigInteger.valueOf(DGROUP));
				}
				catch (Exception e) {
					throw new RuntimeException(e);
				}
			});

			ReferenceManager refs = program.getReferenceManager();
			Address fromRuntime = builder.addr("0x210d:0x0004");
			Address fromApp = builder.addr("0x1000:0x0004");
			Address target = builder.addr("0x2b5a:0x1010");
			builder.withTransaction(() -> {
				refs.addMemoryReference(fromRuntime, target, RefType.READ, SourceType.ANALYSIS, 0);
				refs.addMemoryReference(fromApp, target, RefType.READ, SourceType.ANALYSIS, 0);
			});
			assertEquals(2, refs.getReferenceCountTo(target));

			int[] removed = new int[1];
			builder.withTransaction(
				() -> removed[0] = RTLinkXrefAnalyzer.removeRuntimeDgroupRefs(program));

			assertEquals("only the runtime's reference is swept", 1, removed[0]);
			assertEquals("the application's reference survives", 1,
				refs.getReferenceCountTo(target));
			assertEquals("and it is the application's", fromApp,
				refs.getReferencesTo(target).iterator().next().getFromAddress());
		}
		finally {
			builder.dispose();
		}
	}

	private static String asHex(String ascii) {
		StringBuilder sb = new StringBuilder();
		for (byte b : ascii.getBytes(java.nio.charset.StandardCharsets.US_ASCII)) {
			sb.append(String.format("%02x ", b));
		}
		return sb.toString().trim();
	}
}
