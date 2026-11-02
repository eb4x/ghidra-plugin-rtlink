package ebbex.rtlink;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link RTLinkDispatcherJumpAnalyzer}: the VM nucleus' constant-pair dispatch in
 * miniature. {@code JMP DX} is a near jump, so its targets are {@code CS:imm} for the
 * constants that reach it: those references are kept or added and their bodies decoded;
 * references stock resolved against the 64KB page are removed with the junk they decoded.
 * And the cases it must refuse: a legitimate register-indirect jump, a resolution into
 * another segment no constant explains, and any {@code JMP reg} lacking the return-slot patch.
 */
public class RTLinkDispatcherJumpAnalyzerTest extends RealModeTest {

	// The two-armed dispatch at 1000:0100, as in the nucleus:
	//   0100  b8 16 00   MOV AX,0x0016
	//   0103  ba 60 01   MOV DX,0x0160     ; arm 1 body
	//   0106  74 06      JZ 0x010e
	//   0108  b8 7c 00   MOV AX,0x007c
	//   010b  ba 80 01   MOV DX,0x0180     ; arm 2 body
	//   010e  89 44 fc   MOV [SI-4],AX     ; the return-slot patch (89 44 fc fingerprint)
	//   0111  ff e2      JMP DX
	private static final String DISPATCH = "b8 16 00 ba 60 01 74 06 b8 7c 00 ba 80 01 89 44 fc ff e2";
	private static final int DISPATCH_LEN = 0x13;
	private static final String JMP = "0x1000:0x0111";
	private static final String BODY_A = "0x1000:0x0160";
	private static final String BODY_B = "0x1000:0x0180";

	private RealMode dispatchProgram() throws Exception {
		RealMode builder = realMode("DISPATCH");
		builder.code("0x1000:0x0000", 0x400);
		builder.setBytes("0x1000:0x0100", DISPATCH);
		builder.setBytes(BODY_A, "33 c0 cb");             // XOR AX,AX ; RETF
		builder.setBytes(BODY_B, "5d cb");                // POP BP ; RETF
		builder.decode("0x1000:0x0100", DISPATCH_LEN, true);
		return builder;
	}

	/** Run the pass inside a transaction over the whole program and hand back the count. */
	private static int resolve(RealMode builder) throws Exception {
		Program program = builder.getProgram();
		return builder.tx(() -> RTLinkDispatcherJumpAnalyzer.resolveDispatchJumps(program,
			program.getMemory(), TaskMonitor.DUMMY));
	}

	private static void addAnalysisJump(RealMode builder, String from, String to) {
		builder.withTransaction(() -> builder.getProgram().getReferenceManager()
				.addMemoryReference(builder.addr(from), builder.addr(to), RefType.COMPUTED_JUMP,
					SourceType.ANALYSIS, 0));
	}

	/** Claim the dispatch jumps as the table pass does, inside a transaction. */
	private static int claim(RealMode builder) throws Exception {
		Program program = builder.getProgram();
		return builder.tx(() -> VmDispatch.claim(program,
			program.getMemory(), TaskMonitor.DUMMY));
	}

	/**
	 * Where {@code currentCS} resolves against the page (stock Ghidra), the jump is claimed with
	 * its two {@code CS:imm} references. Skipped on an SDK whose {@code currentCS} reads CS from
	 * context: there the claim stands aside by design.
	 */
	@Test
	public void testDispatchJumpIsClaimedWhereCsResolvesAgainstThePage() throws Exception {
		RealMode builder = dispatchProgram();
		Program program = builder.getProgram();
		assumeTrue(X86.resolvesAgainstPage(program,
			program.getListing().getInstructionAt(builder.addr(JMP))));

		assertEquals(1, claim(builder));
		assertEquals(Set.of(builder.addr(BODY_A), builder.addr(BODY_B)),
			builder.computedTargets(JMP));
	}

	/**
	 * A resolved jump is overridden once its function exists, so the decompiler shows the two
	 * arms: it never reads the references, and on its own gets the jump wrong on every SDK.
	 * Once only: resolving again records nothing, so a deleted override stays deleted.
	 */
	@Test
	public void testResolvedDispatchJumpIsOverriddenOnce() throws Exception {
		RealMode builder = dispatchProgram();
		Program program = builder.getProgram();
		Address jmp = builder.addr(JMP);

		resolve(builder);
		builder.createFunction("0x1000:0x0100");
		assertEquals(Integer.valueOf(1), writeOverrides(builder));

		Namespace space = overrideSpace(builder, jmp);
		assertNotNull("the jump carries an override", space);
		Set<Address> cases = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getSymbols(space)) {
			if (symbol.getName().startsWith("case")) {
				cases.add(symbol.getAddress());
			}
		}
		assertEquals(Set.of(builder.addr(BODY_A), builder.addr(BODY_B)), cases);

		builder.withTransaction(
			() -> program.getSymbolTable().removeSymbolSpecial(space.getSymbol()));
		resolve(builder);
		assertEquals("a second resolution records nothing", Integer.valueOf(0),
			writeOverrides(builder));
		assertNull("the deleted override stays deleted", overrideSpace(builder, jmp));
	}

	private static Integer writeOverrides(RealMode builder) throws Exception {
		Program program = builder.getProgram();
		return builder.tx(() -> RTLinkSwitchOverrideAnalyzer.writeOverrides(program,
			program.getMemory(), new MessageLog(), TaskMonitor.DUMMY));
	}

	private static Namespace overrideSpace(RealMode builder, Address jmp) {
		Program program = builder.getProgram();
		Function function = program.getFunctionManager().getFunctionContaining(jmp);
		Namespace overrides = function == null ? null : HighFunction.findOverrideSpace(function);
		return overrides == null ? null
				: HighFunction.findNamespace(program.getSymbolTable(), overrides, "jmp_" + jmp);
	}

	/** With the dispatcher analyzer switched off, the table pass claims nothing for it. */
	@Test
	public void testDisabledAnalyzerClaimsNothing() throws Exception {
		RealMode builder = dispatchProgram();
		Program program = builder.getProgram();
		assumeTrue("only where a claim would otherwise happen", X86.resolvesAgainstPage(
			program, program.getListing().getInstructionAt(builder.addr(JMP))));
		builder.withTransaction(() -> program.getOptions(Program.ANALYSIS_PROPERTIES)
				.setBoolean(RTLinkDispatcherJumpAnalyzer.NAME, false));
		Set<Address> before = builder.computedTargets(JMP);

		assertEquals(0, claim(builder));
		assertEquals("no reference is added", before, builder.computedTargets(JMP));
	}

	@Test
	public void testBodiesAreReferencedAndDecoded() throws Exception {
		RealMode builder = dispatchProgram();
		Program program = builder.getProgram();
		assertNull("setup: body A not yet decoded",
			program.getListing().getInstructionAt(builder.addr(BODY_A)));

		assertEquals(1, resolve(builder));

		assertEquals("JMP DX goes to CS:imm for both constants that reach it",
			Set.of(builder.addr(BODY_A), builder.addr(BODY_B)), builder.computedTargets(JMP));
		assertNotNull("body A is decoded",
			program.getListing().getInstructionAt(builder.addr(BODY_A)));
		assertNotNull("body B is decoded",
			program.getListing().getInstructionAt(builder.addr(BODY_B)));
		assertEquals(RTLinkDispatcherJumpAnalyzer.DISPATCHER_COMMENT,
			program.getListing().getInstructionAt(builder.addr(JMP))
					.getComment(CommentType.PLATE));
	}

	/**
	 * Where {@code currentCS} reads CS from context, stock already plants the right
	 * references and decodes the bodies: nothing is deleted and nothing cleared. The version
	 * before this one deleted exactly these and cleared VICEROY's VM runtime with them.
	 */
	@Test
	public void testCorrectReferencesAreKept() throws Exception {
		RealMode builder = dispatchProgram();
		Program program = builder.getProgram();
		builder.decode(BODY_A, 3, true);
		builder.decode(BODY_B, 2, true);
		addAnalysisJump(builder, JMP, BODY_A);
		addAnalysisJump(builder, JMP, BODY_B);

		assertEquals("nothing to change", 0, resolve(builder));

		assertEquals(Set.of(builder.addr(BODY_A), builder.addr(BODY_B)),
			builder.computedTargets(JMP));
		assertNotNull(program.getListing().getInstructionAt(builder.addr(BODY_A)));
		assertNotNull(program.getListing().getInstructionAt(builder.addr(BODY_B)));
	}

	@Test
	public void testResolutionIsIdempotent() throws Exception {
		RealMode builder = dispatchProgram();
		assertEquals(1, resolve(builder));
		assertEquals("a re-run finds nothing left to do", 0, resolve(builder));
	}

	@Test
	public void testExistingPlateCommentIsKept() throws Exception {
		RealMode builder = dispatchProgram();
		Program program = builder.getProgram();
		String own = "$$VM_UNK: dispatch to the selected entry";
		builder.withTransaction(() -> program.getListing().getInstructionAt(builder.addr(JMP))
				.setComment(CommentType.PLATE, own));

		resolve(builder);

		assertEquals(own, program.getListing().getInstructionAt(builder.addr(JMP))
				.getComment(CommentType.PLATE));
	}

	/**
	 * The nucleus has two dispatchers back to back. Each takes only the constants that reach
	 * it: the first one's {@code JMP DX} has no fall-through, so its constant never counts for
	 * the second, and the second's never flows backwards into the first.
	 * <pre>
	 *   0100  ba 60 01   MOV DX,0x0160
	 *   0103  89 44 fc   MOV [SI-4],AX
	 *   0106  ff e2      JMP DX
	 *   0108  ba 80 01   MOV DX,0x0180
	 *   010b  89 44 fc   MOV [SI-4],AX
	 *   010e  ff e2      JMP DX
	 * </pre>
	 */
	@Test
	public void testSiblingDispatchersKeepTheirOwnConstants() throws Exception {
		RealMode builder = realMode("SIBLINGS");
		builder.code("0x1000:0x0000", 0x400);
		builder.setBytes("0x1000:0x0100", "ba 60 01 89 44 fc ff e2 ba 80 01 89 44 fc ff e2");
		builder.setBytes(BODY_A, "33 c0 cb");
		builder.setBytes(BODY_B, "5d cb");
		builder.decode("0x1000:0x0100", 8, true);
		builder.decode("0x1000:0x0108", 8, true);

		assertEquals(2, resolve(builder));

		assertEquals(Set.of(builder.addr(BODY_A)), builder.computedTargets("0x1000:0x0106"));
		assertEquals(Set.of(builder.addr(BODY_B)), builder.computedTargets("0x1000:0x010e"));
	}

	/**
	 * Stock resolves the immediate against the jump's 64KB page, not its segment. MzLoader
	 * makes one block per segment, so a nucleus that starts past its page boundary sends that
	 * target into an earlier block. The committed smoke sample has this shape:
	 * <pre>
	 *   1000:0000  CODE block, 0x120 bytes of resident code:
	 *   1000:0060  f8 f9 fa     the casualty the bogus flow decoded
	 *   1000:0068  55           PUSH BP, a real function entry; the bogus flow to 0067
	 *                           collided with it, decoded nothing, and left only a mark
	 *   1012:0000  b8 16 00     MOV AX,0x0016    ; NUC block
	 *   1012:0003  ba 60 00     MOV DX,0x0060
	 *   1012:0006  74 03        JZ 0x000b
	 *   1012:0008  ba 67 00     MOV DX,0x0067
	 *   1012:000b  89 44 fc     MOV [SI-4],AX
	 *   1012:000e  ff e2        JMP DX           ; resolved by stock to page 1000 + imm
	 *   1012:0060  c3           arm 1 body
	 *   1012:0067  cb           arm 2 body
	 * </pre>
	 */
	@Test
	public void testPageBaseRefsAreReplacedBySegmentRefs() throws Exception {
		RealMode builder = pageProgram(false);
		Program program = builder.getProgram();
		assertNotNull("setup: the collision is marked", program.getBookmarkManager()
				.getBookmark(builder.addr("0x1000:0x0067"), BookmarkType.ERROR, "Bad Instruction"));

		assertEquals(1, resolve(builder));

		assertEquals("the page-based references give way to the nucleus-segment ones",
			Set.of(builder.addr("0x1012:0x0060"), builder.addr("0x1012:0x0067")),
			builder.computedTargets("0x1012:0x000e"));
		assertNull("the junk the first one decoded in the earlier block is cleared",
			program.getListing().getInstructionAt(builder.addr("0x1000:0x0060")));
		assertNull("the mark the second one left at its collision is dropped",
			program.getBookmarkManager()
					.getBookmark(builder.addr("0x1000:0x0067"), BookmarkType.ERROR,
						"Bad Instruction"));
		assertNotNull("the real code it collided with is untouched",
			program.getListing().getInstructionAt(builder.addr("0x1000:0x0068")));
		assertNotNull("arm 1's body is decoded",
			program.getListing().getInstructionAt(builder.addr("0x1012:0x0060")));
		assertNotNull("arm 2's body is decoded",
			program.getListing().getInstructionAt(builder.addr("0x1012:0x0067")));
	}

	@Test
	public void testEvidencedCodeAtPageTargetIsKept() throws Exception {
		RealMode builder = pageProgram(true); // 1000:0060 carries a non-default symbol
		assertEquals(1, resolve(builder));

		assertFalse("the page-based reference is still deleted",
			builder.computedTargets("0x1012:0x000e").contains(builder.addr("0x1000:0x0060")));
		assertNotNull("but evidenced code at its target is kept, not over-cleared",
			builder.getProgram().getListing().getInstructionAt(builder.addr("0x1000:0x0060")));
	}

	private RealMode pageProgram(boolean evidencedJunk) throws Exception {
		RealMode builder = realMode("PAGE");
		builder.code("CODE", "0x1000:0x0000", 0x120);
		builder.code("NUC", "0x1012:0x0000", 0x100);
		builder.setBytes("0x1012:0x0000", "b8 16 00 ba 60 00 74 03 ba 67 00 89 44 fc ff e2");
		builder.setBytes("0x1012:0x0060", "c3");
		builder.setBytes("0x1012:0x0067", "cb");
		builder.setBytes("0x1000:0x0060", "f8 f9 fa");
		builder.setBytes("0x1000:0x0068", "55 c3");
		builder.decode("0x1012:0x0000", 16, true);
		builder.decode("0x1000:0x0060", 3, true);
		builder.decode("0x1000:0x0068", 2, true);
		builder.createFunction("0x1000:0x0068");
		addAnalysisJump(builder, "0x1012:0x000e", "0x1000:0x0060");
		addAnalysisJump(builder, "0x1012:0x000e", "0x1000:0x0067");
		builder.errorMark("0x1000:0x0060", "conflicting data");
		builder.errorMark("0x1000:0x0067",
			"Failed to disassemble at 1000:0067 due to conflicting instruction at 1000:0068");
		if (evidencedJunk) {
			builder.createLabel("0x1000:0x0060", "keep_me");
		}
		return builder;
	}

	/**
	 * A genuine {@code MOV reg,imm16 ; JMP reg} computed jump with a correct current-segment
	 * target and <b>no</b> return-slot patch before it — the decisive control. Nothing is
	 * touched.
	 * <pre>
	 *   0200  bb 50 02   MOV BX,0x0250
	 *   0203  90         NOP            ; not a return-slot patch
	 *   0204  ff e3      JMP BX
	 *   0250  c3         RET            ; real, evidenced code
	 * </pre>
	 */
	@Test
	public void testLegitComputedJumpUntouched() throws Exception {
		RealMode builder = realMode("LEGIT");
		builder.code("0x1000:0x0000", 0x400);
		builder.setBytes("0x1000:0x0200", "bb 50 02 90 ff e3");
		builder.setBytes("0x1000:0x0250", "c3");
		builder.decode("0x1000:0x0200", 6, true);
		builder.decode("0x1000:0x0250", 1, true);
		addAnalysisJump(builder, "0x1000:0x0204", "0x1000:0x0250");
		builder.createLabel("0x1000:0x0250", "real_target");

		assertEquals(0, resolve(builder));

		assertEquals(Set.of(builder.addr("0x1000:0x0250")),
			builder.computedTargets("0x1000:0x0204"));
		assertNotNull("its target code must be untouched",
			builder.getProgram().getListing().getInstructionAt(builder.addr("0x1000:0x0250")));
	}

	/**
	 * A dispatcher whose computed reference lands in a different segment that none of its
	 * constants explains: not a stock guess, so it is left alone.
	 */
	@Test
	public void testUnexplainedCrossSegmentRefUntouched() throws Exception {
		RealMode builder = dispatchProgram();
		builder.code("OVL", "0x2000:0x0000", 0x400);
		builder.setBytes("0x2000:0x0080", "c3");
		builder.decode("0x2000:0x0080", 1, true);
		addAnalysisJump(builder, JMP, "0x2000:0x0080");

		assertEquals("the dispatch itself is still resolved", 1, resolve(builder));

		assertEquals("a resolution no constant explains survives beside the true ones",
			Set.of(builder.addr("0x2000:0x0080"), builder.addr(BODY_A), builder.addr(BODY_B)),
			builder.computedTargets(JMP));
	}

	/**
	 * The {@code MOV DX,imm16 ; JMP DX} shape with a reference but <b>no</b> return-slot patch
	 * immediately before the jump (a plain NOP instead). The gate declines it, so an arbitrary
	 * register-indirect jump is never mistaken for a dispatcher.
	 * <pre>
	 *   0100  ba 80 01   MOV DX,0x0180
	 *   0103  90         NOP            ; NOT a return-slot patch
	 *   0104  ff e2      JMP DX
	 *   0180  50 51 52 53
	 * </pre>
	 */
	@Test
	public void testMissingReturnSlotPatchDeclined() throws Exception {
		RealMode builder = realMode("NOSLOT");
		builder.code("0x1000:0x0000", 0x400);
		builder.setBytes("0x1000:0x0100", "ba 80 01 90 ff e2");
		builder.setBytes(BODY_B, "50 51 52 53");
		builder.decode("0x1000:0x0100", 6, true);
		builder.decode(BODY_B, 4, true);
		addAnalysisJump(builder, "0x1000:0x0104", BODY_B);

		assertEquals(0, resolve(builder));

		assertEquals(Set.of(builder.addr(BODY_B)), builder.computedTargets("0x1000:0x0104"));
		assertNotNull("and nothing is cleared",
			builder.getProgram().getListing().getInstructionAt(builder.addr(BODY_B)));
	}
}
