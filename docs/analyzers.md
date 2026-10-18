# The analyzers

Seven analyzers, each pinned to a different slot in the auto-analysis pipeline. An
analyzer registers exactly one `AnalyzerType` + `AnalysisPriority`, which is why this is
seven classes and not one. They share package-private statics and must stay in
`ebbex.rtlink`. Listed in pipeline order.

- **`RTLinkOverlayAnalyzer`** — BYTE, `FORMAT_ANALYSIS.after()`. Detects overlay data
  past the MZ image end, parses pages, creates the overlay memory blocks, wires up the
  dispatch-stub thunks, sets CS over each overlay module (frame + module base; real-mode
  `currentCS` reads it from context since upstream PR #9703, and the MZ loader sets it
  only for resident blocks), sets the dailydriver fork's `cseg` context field to the same
  value where the language has it (near rel16 branches then wrap inside the module's
  64KB segment), and assumes DS=DGROUP. Runs on raw bytes, before disassembly. Passes
  that stand on their own are their own classes: `OverlayRelocations` (the page's segment
  fixups), `ModuleSegments` (module bases and the CS over each), `DataSegmentAssumption` (DS=DGROUP),
  `VmRuntimeSeeds` (the entry stub's and the VM dispatch's targets), `HuskRepair` (functions
  with no code at their entry); `CodeSeeds` holds what the seeding passes share.
- **`RTLinkSwitchTableAnalyzer`** — INSTRUCTION, `CODE_ANALYSIS.before()`. Recovers the
  CS-/module-relative switch tables and fixes their *references*. Must run before
  `DecompilerSwitchAnalyzer`, which skips any computed branch that already has
  computed refs — winning that race is what keeps bogus targets from being
  disassembled into other segments.
- **`RTLinkDispatcherJumpAnalyzer`** — BYTE, `DATA_ANALYSIS.before()`. Resolves the VM
  nucleus' constant-pair dispatch (`MOV AX,entry ; MOV DX,body ; … ; MOV [SI-4],AX ;
  JMP DX`). `JMP DX` is a near jump: its targets are `CS:imm` for the `MOV DX`
  constants that reach it (a backward reaching-definitions walk), the bodies of the VM
  entries — on VICEROY most of the VM runtime hangs off them. Stock resolves the
  offset against the 64KB *page* instead and — synchronously, inside the 596 pass —
  disassembles junk there; with no window to pre-empt it, this runs after 596/600/602
  but before `ASCII Strings` (~905): it deletes the computed-jump refs an immediate
  explains against any base but the jump's own segment, clears the junk they seeded and
  its ERROR bookmarks, then adds the `CS:imm` refs and disassembles the bodies. Where
  `currentCS` reads CS from context (the dailydriver fork) stock is already right and only
  the plate comment changes. Up to 0.6.0 this took the body for an overlay offset and
  deleted the correct refs too, clearing 37 routines of VICEROY's nucleus. Gated by a
  near-unforgeable fingerprint: the return-slot patch (`MOV [base-neg-disp],reg`)
  immediately before a register-indirect `JMP`, fed by a `MOV reg,imm16`.
- **`RTLinkSwitchOverrideAnalyzer`** — INSTRUCTION, `FUNCTION_ANALYSIS.after()`, and again
  in `analysisEnded`. Writes the decompiler jump-table overrides for the same tables, from
  the table pass's own record: the dispatches it marked (user property map
  `RTLink switch dispatch`) and the `COMPUTED_JUMP` references it laid down — never by
  re-deriving the table, which by then reads a program with more functions and code. An
  override already present (its own, or the user's) is left alone. Cannot be merged into
  the table analyzer: the override symbols need a defined `FunctionDB` to hang a namespace
  off, which does not exist that early; `analysisEnded` catches dispatches whose function
  appeared after this pass last saw them.
- **`RTLinkXrefAnalyzer`** — INSTRUCTION, `REFERENCE_ANALYSIS.after()`. Resolves the
  DS-relative data references that Ghidra's own reference pass declines to make on
  RTLink programs.
- **`RTLinkFlowRepairAnalyzer`** — BYTE, `LOW_PRIORITY.after()` (dead last). Recovers
  **buried code** — real, evidenced instructions left undisassembled under junk, or
  never reached at all: CALL fall-throughs onto MZ-relocated segment words sealed as
  data (`CALL_RETURN`); far jumps/calls through initialized `CS:[imm16]` vectors
  followed; provably terminating routines (`INT 21h/4Ch` and tail-jump chains into
  one) sealing their callers' fall-throughs; "conflicting instruction" bookmarks
  arbitrated by evidence; routines reached only through a `CS:imm` far pointer the
  program builds to itself (stored into adjacent words, handed as `DS:DX` to a routine
  that stores it so, or installed by DOS set-vector: interrupt hooks, the PSP terminate
  hook, `$$RTL_REGISTER` handlers, the VM's return vector); undefined gaps that decode
  exactly onto the code after them disassembled (a short gap shaped like one routine, or
  a run of whole routines below a routine exit — a return, a far jump or a tail jump —
  past any short zero padding, entries sharing one body included, jump-table slots and
  blocks that jump back into the routine just above excluded, each routine made a
  function); instructions decoded out of zero fill (≥16 zero bytes) deleted when
  unreferenced. The test is always on the bytes in memory, never on the instruction
  (`00 00` is a real instruction). Unresolved dispatch stubs and NOP sleds are left
  strictly alone. Each repair is its own class — `RelocationFallthroughs`,
  `ConflictArbitration`, `CodeGaps`, `FarVectorFlows`, `NonReturningCalls`,
  `FillerIslands`, `FarCodePointers` — and the analyzer only orders them.
- **`RTLinkLibrarySignatureAnalyzer`** — BYTE, `LOW_PRIORITY.after().after()` (after the
  buried-code pass). Off until its `Vendor library` option names the user's own
  `RTLUTILS.LIB`; then matches each module's public symbols against the resident code
  (whole segments, else each entry's opening with fixups and relative branch distances
  masked, kept unique, in vendor order and in one block), makes functions of the code
  entries nothing reaches and names every placed entry. Runs last because whether a public
  is code or a variable is read from the program's analysed state. See
  `docs/vendor-signatures.md`.

Also in the package: **`EmulatedFloatAnalyzer` / `EmulatedFloatPatcher`** — rewrites
DOS emulated floating point (INT 34h–3Dh) into the x87 it encodes.

## Housekeeping rules

- All analyzers set `setSupportsOneTimeAnalysis()` so they can be re-run from
  Analysis → One Shot on an already-analyzed program.
- Analyzers hand results to one another only through the program, and every such record —
  the program-info flags, the overlay module bases, the VM seed count, the switch dispatch
  marks — is read and written through `RTLinkProgram`, along with the two gates below.
- `canAnalyze` accepts any segmented MZ (`RTLinkProgram.isSegmentedMz`; it is asked before
  analysis, when nothing is known yet), so every RTLink analyzer's `added()` returns at once
  unless `RTLinkOverlayAnalyzer` found overlays (`isOverlayAnalyzed`). `EmulatedFloatAnalyzer`
  is the exception: DOS emulated float is not RTLink-specific.
- `AutoAnalysisManager` calls `analysisEnded` on every analyzer whose `canAnalyze` passed,
  enabled or not, inside the analysis transaction: an `analysisEnded` that writes checks
  its own enablement (`isAnalyzerEnabled`) and the same RTLink gate.
- Report success counts with `Msg.info`, never `log.appendMsg` — any content in the
  analysis `MessageLog` makes `AutoAnalysisPlugin` pop a "warnings/errors issued during
  analysis" dialog, so the `MessageLog` is for genuine failures only.
- Discovery is by classpath scanning (`AbstractAnalyzer` is an `ExtensionPoint`) — no
  registration files.
- Verify a change on a fresh import into `/scratch-<what>` and delete it afterwards;
  analysis bakes references into the DB, so an already-analyzed program never shows
  the effect of a fixed analyzer.
