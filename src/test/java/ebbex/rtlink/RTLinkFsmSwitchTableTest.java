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

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Tests for {@code RTLinkSwitchTableAnalyzer.recoverFormatterFsmTable}: the MSC
 * {@code _output} formatter state machine whose dispatch index comes out of an
 * {@code XLAT} and whose entry count is derived from the FSM's own class/transition
 * table.
 * <p>
 * The code and table bytes are transcribed from VICEROY.EXE ({@code 1d1d:199c} and
 * {@code 2b5a:2a56}) — the routine and table are the C library's, byte-identical
 * across all four corpus binaries, so the test is hermetic the same way the overlay
 * relocation test's transcribed page is: it exercises exactly the bytes the analyzer
 * has to handle in the wild.
 */
public class RTLinkFsmSwitchTableTest extends AbstractGenericTest {

	/**
	 * The combined class/transition table, VICEROY {@code 2b5a:2a56}, {@code 0x59} bytes
	 * (the {@code CMP AL,0x58} bound). Low nibble of {@code table[c-' ']} = character
	 * class; high nibble of {@code table[class*8 + state]} = next state. Max reachable
	 * state is 7, so the FSM has 8 states.
	 */
	private static final String LOOKUP_TABLE =
	// @formatter:off
		"06 00 00 06 00 01 00 00 10 00 03 06 00 06 02 10 " +
		"04 45 45 45 05 05 05 05 05 35 30 00 50 00 00 00 " +
		"00 20 20 30 50 58 07 08 00 30 30 30 57 50 07 00 " +
		"00 20 20 00 00 00 00 00 08 60 60 60 60 60 60 00 " +
		"00 70 70 78 78 78 78 08 07 08 00 00 07 00 08 08 " +
		"08 00 00 08 00 08 00 00 08";
	// @formatter:on

	/** {@code CALL 0x0040; RET} — the call reference that lets dispatchRange resolve. */
	private static final String CALLER = "e8 3d 00 c3";

	/** Eight case-target words at {@code 0x0010}, mirroring the table below the entry. */
	private static final String JUMP_TABLE =
		"80 00 84 00 88 00 8c 00 90 00 94 00 98 00 9c 00";

	/**
	 * The FSM function at {@code 0x0040}: entry, then the prologue transcribed from
	 * VICEROY {@code 1d1d:199c-19c4} with the table base ({@code 0x2a56}) kept and the
	 * dispatch displacement retargeted to the jump table at {@code 0x0010}. The dispatch
	 * {@code JMP word ptr CS:[BX+0x10]} lands at {@code 0x0067}.
	 */
	private static final String FSM_CODE =
	// @formatter:off
		"55 8b ec " +       // 0x0040  PUSH BP; MOV BP,SP
		"bb 56 2a " +       // 0x0043  MOV BX,0x2a56
		"2c 20 " +          // 0x0046  SUB AL,0x20
		"3c 58 " +          // 0x0048  CMP AL,0x58
		"77 05 " +          // 0x004a  JA  0x0051
		"d7 " +             // 0x004c  XLAT
		"24 0f " +          // 0x004d  AND AL,0xF
		"eb 02 " +          // 0x004f  JMP 0x0053
		"b0 00 " +          // 0x0051  MOV AL,0x0
		"b1 03 " +          // 0x0053  MOV CL,0x3
		"d2 e0 " +          // 0x0055  SHL AL,CL
		"02 46 fb " +       // 0x0057  ADD AL,[BP-0x5]
		"d7 " +             // 0x005a  XLAT
		"fe c1 " +          // 0x005b  INC CL
		"d2 e8 " +          // 0x005d  SHR AL,CL
		"88 46 fb " +       // 0x005f  MOV [BP-0x5],AL
		"98 " +             // 0x0062  CBW
		"8b d8 " +          // 0x0063  MOV BX,AX
		"d1 e3 " +          // 0x0065  SHL BX,1
		"2e ff a7 10 00";   // 0x0067  JMP word ptr CS:[BX+0x10]
	// @formatter:on

	/** Eight distinct case stubs at {@code 0x0080 + 4*i}: {@code MOV AX,i; RET}. */
	private static final String CASE_STUBS =
		"b8 00 00 c3 b8 01 00 c3 b8 02 00 c3 b8 03 00 c3 " +
			"b8 04 00 c3 b8 05 00 c3 b8 06 00 c3 b8 07 00 c3";

	private static final String DISPATCH = "0x1100:0x0067";

	private ProgramBuilder buildFsmProgram(String fsmCode, String tableBytes, boolean withDs)
			throws Exception {
		ProgramBuilder builder = new ProgramBuilder("FSM", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1100:0x0000", 0x100);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1100:0x0000", CALLER);
			builder.setBytes("0x1100:0x0010", JUMP_TABLE);
			builder.setBytes("0x1100:0x0040", fsmCode);
			builder.setBytes("0x1100:0x0080", CASE_STUBS);

			builder.createMemory("TABLE", "0x2b5a:0x2a56", 0x59);
			builder.setBytes("0x2b5a:0x2a56", tableBytes);

			if (withDs) {
				builder.setRegisterValue("DS", "0x1100:0x0000", "0x1100:0x00ff", 0x2b5a);
			}
			// The disassemble range is a restricted set, so seed the caller and the FSM
			// separately. The caller's CALL still records its call reference (that is
			// what dispatchRange keys on), flow stops at the computed dispatch, and the
			// case stubs stay undefined — exactly the state a fresh import is in when
			// the analyzer runs.
			builder.disassemble("0x1100:0x0000", 4, true);
			builder.disassemble("0x1100:0x0040", 0x2c, true);
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	private static List<Address> recover(ProgramBuilder builder) {
		Program program = builder.getProgram();
		Instruction dispatch =
			program.getListing().getInstructionAt(builder.addr(DISPATCH));
		assertNotNull("dispatch instruction must exist at " + DISPATCH, dispatch);
		return RTLinkSwitchTableAnalyzer.recoverTable(program, dispatch);
	}

	@Test
	public void testRecoversFormatterFsm() throws Exception {
		ProgramBuilder builder = buildFsmProgram(FSM_CODE, LOOKUP_TABLE, true);
		try {
			List<Address> destinations = recover(builder);
			assertNotNull("the FSM dispatch must be recovered", destinations);
			assertEquals("the real table reaches 8 states", 8, destinations.size());
			for (int i = 0; i < 8; i++) {
				assertEquals(builder.addr(String.format("0x1100:0x%04x", 0x80 + 4 * i)),
					destinations.get(i));
			}
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testSyntheticFourStateTable() throws Exception {
		// Classes {0,1}; transitions 0->1->2->3->0 through class 0; everything else
		// stays at state 0. Proves the count is computed, not assumed to be 8.
		String synthetic = "10 21 30" + " 00".repeat(0x59 - 3);
		ProgramBuilder builder = buildFsmProgram(FSM_CODE, synthetic, true);
		try {
			List<Address> destinations = recover(builder);
			assertNotNull("a well-formed smaller FSM must still be recovered", destinations);
			assertEquals("the synthetic table reaches 4 states", 4, destinations.size());
			for (int i = 0; i < 4; i++) {
				assertEquals(builder.addr(String.format("0x1100:0x%04x", 0x80 + 4 * i)),
					destinations.get(i));
			}
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testDeclinesWithoutDsContext() throws Exception {
		ProgramBuilder builder = buildFsmProgram(FSM_CODE, LOOKUP_TABLE, false);
		try {
			assertNull("no DS value means the table cannot be located: decline",
				recover(builder));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testDeclinesWhenTransitionEscapesTable() throws Exception {
		// First class byte perturbed to class 15: transition index 15*8 = 120 lies past
		// the 0x59 bytes the CMP proves, so no count may be claimed.
		String escaped = "0f" + LOOKUP_TABLE.substring(2);
		ProgramBuilder builder = buildFsmProgram(FSM_CODE, escaped, true);
		try {
			assertNull("a transition escaping the proven table region must decline",
				recover(builder));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testDeclinesOnBrokenPrologue() throws Exception {
		// INC CL replaced by NOPs: the SHR width is no longer proven to be 4, so the
		// idiom must not match.
		String broken = FSM_CODE.replace("fe c1 ", "90 90 ");
		assertNotEquals(FSM_CODE, broken);
		ProgramBuilder builder = buildFsmProgram(broken, LOOKUP_TABLE, true);
		try {
			assertNull("a prologue that is not the FSM idiom must decline",
				recover(builder));
		}
		finally {
			builder.dispose();
		}
	}
}
