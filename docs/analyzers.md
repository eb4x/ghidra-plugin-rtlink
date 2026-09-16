# The analyzers

Six analyzers, each pinned to a different slot in the auto-analysis pipeline. An
analyzer registers exactly one `AnalyzerType` + `AnalysisPriority`, which is why this is
six classes and not one. They share package-private statics and must stay in
`ebbex.rtlink`. Listed in pipeline order.

- **`RTLinkOverlayAnalyzer`** — BYTE, `FORMAT_ANALYSIS.after()`. Detects overlay data
  past the MZ image end, parses pages, creates the overlay memory blocks, wires up the
  dispatch-stub thunks and assumes DS=DGROUP. Runs on raw bytes, before disassembly.
- **`RTLinkSwitchTableAnalyzer`** — INSTRUCTION, `CODE_ANALYSIS.before()`. Recovers the
  CS-/module-relative switch tables and fixes their *references*. Must run before
  `DecompilerSwitchAnalyzer`, which skips any computed branch that already has
  computed refs — winning that race is what keeps bogus targets from being
  disassembled into other segments.
- **`RTLinkDispatcherJumpAnalyzer`** — BYTE, `DATA_ANALYSIS.before()`. Neutralizes the
  bogus current-segment `COMPUTED_JUMP` the stock x86 Constant Reference Analyzer (596)
  plants on the overlay VM dispatcher trampoline (`MOV reg,imm16 ; MOV [base-disp],reg
  ; JMP reg`): the immediate is a bare offset into a *runtime-selected* overlay
  segment, which stock resolves against the current CS and — synchronously in the same
  pass — disassembles junk at (a string decoded as code, plus a non-string casualty).
  There is no window to pre-empt it, so this runs after 596/600/602 settle but before
  `ASCII Strings` (~905): it deletes only the *same-block* (bogus current-CS)
  computed-jump refs, clears the junk they caused, drops the confined ERROR bookmarks,
  and leaves the `JMP` honestly unresolved — so the string pass reclaims the string
  itself. Cross-block refs (a genuinely-resolved overlay target) are preserved. Gated
  by a near-unforgeable fingerprint: the return-slot patch (`MOV [base-neg-disp],reg`)
  immediately before a register-indirect `JMP`, fed by a `MOV reg,imm16`.
- **`RTLinkSwitchOverrideAnalyzer`** — INSTRUCTION, `FUNCTION_ANALYSIS.after()`. Writes
  the decompiler jump-table overrides for the same tables (shares
  `RTLinkSwitchTableAnalyzer.recoverTable()`). Cannot be merged into the table
  analyzer: the override symbols need a defined `FunctionDB` to hang a namespace off,
  which does not exist that early.
- **`RTLinkXrefAnalyzer`** — INSTRUCTION, `REFERENCE_ANALYSIS.after()`. Resolves the
  DS-relative data references that Ghidra's own reference pass declines to make on
  RTLink programs.
- **`RTLinkFlowRepairAnalyzer`** — BYTE, `LOW_PRIORITY.after()` (dead last). Recovers
  **buried code** — real, evidenced instructions left undisassembled under junk, or
  never reached at all: CALL fall-throughs onto MZ-relocated segment words sealed as
  data (`CALL_RETURN`); far jumps/calls through initialized `CS:[imm16]` vectors
  followed; provably terminating routines (`INT 21h/4Ch` and tail-jump chains into
  one) sealing their callers' fall-throughs; "conflicting instruction" bookmarks
  arbitrated by evidence; undefined gaps that decode exactly onto the code after them
  disassembled; instructions decoded out of zero fill (≥16 zero bytes) deleted when
  unreferenced. The test is always on the bytes in memory, never on the instruction
  (`00 00` is a real instruction). Unresolved dispatch stubs and NOP sleds are left
  strictly alone.

Also in the package: **`EmulatedFloatAnalyzer` / `EmulatedFloatPatcher`** — rewrites
DOS emulated floating point (INT 34h–3Dh) into the x87 it encodes.

## Housekeeping rules

- All analyzers set `setSupportsOneTimeAnalysis()` so they can be re-run from
  Analysis → One Shot on an already-analyzed program.
- Report success counts with `Msg.info`, never `log.appendMsg` — any content in the
  analysis `MessageLog` makes `AutoAnalysisPlugin` pop a "warnings/errors issued during
  analysis" dialog, so the `MessageLog` is for genuine failures only.
- Discovery is by classpath scanning (`AbstractAnalyzer` is an `ExtensionPoint`) — no
  registration files.
- Verify a change on a fresh import into `/scratch-<what>` and delete it afterwards;
  analysis bakes references into the DB, so an already-analyzed program never shows
  the effect of a fixed analyzer.
