# ghidra-plugin-rtlink

A [Ghidra](https://github.com/NationalSecurityAgency/ghidra) extension adding
**RTLink/Plus overlay support** for late-DOS MZ executables. Primary target:
`VICEROY.EXE` - *Sid Meier's Colonization* (MicroProse, 1994).

> The tools that build the tools that builds the tool.

## AI slop: fork it, don't send patches

This is AI slop at its finest. The lines of code are **ALL** AI-generated. I
have no opinions on the code, I've barely read any of it, and I have no idea
which direction it should take. I've just fed it corpora to analyze, and when
it said "80% is pretty good, maybe we stop here", I pushed back: less than
100% is completely unacceptable.

Heck even this README is mostly an AI summary.

The source is here for anyone to fork and use as their own starter plugin -
[Apache-2.0](LICENSE). But this is not an open-source *project*: I'm not
considering contributions, and there is no issue triage or roadmap.

## Why this exists

This project exists to ease development of **viceroy**, a "modern"
reimplementation of *Sid Meier's Colonization*. This extension and its sibling
[ghidra-plugin-mcp](https://github.com/eb4x/ghidra-plugin-mcp) teach Ghidra to
understand the original `VICEROY.EXE` and let agents drive the analysis, and
what Ghidra recovers informs viceroy's development.

## What it does

RTLink/Plus overlaid executables defeat stock Ghidra twice over: the overlay
pages past the MZ image end never get mapped, and the overlay VM's dispatch
stubs, trampolines and segment tricks send auto-analysis into the weeds. This
extension adds the file-format parsing plus six analyzers, each pinned to its
own slot in the auto-analysis pipeline:

- **RTLinkOverlayAnalyzer** - detects the overlay area past the MZ image end,
  parses the page chain, creates the overlay memory blocks, and wires the
  dispatch stubs up as thunks.
- **RTLinkSwitchTableAnalyzer** - recovers the CS-/module-relative switch
  tables and plants correct references before stock analysis can guess wrong.
- **RTLinkSwitchOverrideAnalyzer** - writes the decompiler jump-table
  overrides for those same tables.
- **RTLinkXrefAnalyzer** - resolves the DS-relative data references Ghidra's
  own reference pass declines to make on these programs.
- **RTLinkFlowRepairAnalyzer** - recovers buried code: seals unreturnable CALL
  fall-throughs, follows far flows through initialized `CS:[imm16]` vectors,
  arbitrates "conflicting instruction" bookmarks by evidence, disassembles
  gaps that decode exactly onto the code after them, and deletes junk decoded
  out of zero fill.
- **RTLinkDispatcherJumpAnalyzer** - removes the bogus computed-jump
  references stock analysis plants on the overlay VM's dispatcher trampoline,
  reclaiming the strings that junk disassembly destroyed.

Plus **EmulatedFloatAnalyzer**/**EmulatedFloatPatcher**, which rewrite DOS
emulated floating point (`INT 34h`-`3Dh`) into the x87 instructions it
encodes.

## The corpus

The analyzers are exercised against every RTLink-linked game binary we could
get our hands on:

| Binary | Game | Notes |
|---|---|---|
| `VICEROY.EXE` | *Sid Meier's Colonization* (MicroProse, 1994) | the primary target |
| `NEBULAR.EXE` | *Rex Nebular and the Cosmic Gender Bender* (MicroProse, 1992) | |
| `SPHERE.EXE` | *Dragonsphere* (MicroProse, 1994) | |
| `RETURN.EXE` | *Return of the Phantom* (MicroProse, 1993) | |
| `ROE2MAIN.EXE` | *Rules of Engagement 2* (Omnitrend, 1993) | the stress case: 171 overlay records, ~671 KB of overlay code, 1997 dispatch stubs - three times VICEROY's - matched a file-level census exactly |
| `XANTH.EXE` | *Companions of Xanth* (Legend Entertainment, 1993) | the negative test: overlay *sections*, not VM pages - recognized and declined cleanly, imports as a plain MZ with no damage |

The five VM-overlay binaries import at **0 errors, 0 warnings, 0 husk
functions**.

## The linker itself

The breakthrough of the project was finding the tools that *make* RTLink
executables: the **RTLink/Plus 6.10 vendor distribution** (Pocket Soft),
complete with the overlay manager's assembly source, the vendor docs, and the
VMEX example programs - and standing up a DOSBox-scripted harness around the
real linker that builds overlay executables to order. That flipped the
reverse engineering from inference over shipped binaries to **experiments by
construction**: build an EXE with exactly the feature in question and diff
it. It's how edge cases like the section-vs-page overlay variants were pinned
down, and how we could prove negatives at all (e.g. that RTLink 6.10 cannot
emit a type-3 relocation list).

**[`docs/rtlink-format.md`](docs/rtlink-format.md)** is the distilled result:
the authoritative reference for the overlay format and runtime, with every
claim tagged by its evidence class - vendor documentation, overlay-manager
source, corpus measurement, or construction.

## Ghidra fixes

The extension builds against the stock Ghidra API, but analysis quality on
these binaries depends on **five Ghidra fixes** carried on the `dailydriver`
branch of [eb4x/ghidra](https://github.com/eb4x/ghidra) (release 12.1.2 plus
the fixes). Three are submitted upstream:

- x86 Sleigh: compute 16-bit rel16 branch targets without 64KB-page wrap
  ([#9393](https://github.com/NationalSecurityAgency/ghidra/pull/9393))
- x86 Sleigh: export CS directly for 16-bit CS segment overrides
  ([#9395](https://github.com/NationalSecurityAgency/ghidra/pull/9395))
- x86 Sleigh: honor the segment override on 16-bit XLAT
  ([#9391](https://github.com/NationalSecurityAgency/ghidra/pull/9391))

Two more are held back - if the submitted ones are merged, these may follow:

- Disassembler: don't abandon deferred call flows on a restricted-set miss
- Decompiler `DynamicHash`: fix address hashing for segmented address spaces

## Build & install

Prebuilt zips for official Ghidra releases are on the
[releases page](https://github.com/eb4x/ghidra-plugin-rtlink/releases) -
download the zip matching your Ghidra version and install it through Ghidra's
*File → Install Extensions*.

To build yourself: JDK 21+ and two paths in a gitignored, project-local
`gradle.properties`:

- `GHIDRA_INSTALL_DIR` - an *extracted* Ghidra install, used only at build
  time (its `support/buildExtension.gradle` and API jars)
- `GHIDRA_USER_EXTENSIONS_DIR` - the running Ghidra's user `Extensions/`
  directory, where `installExtension` installs the built extension

```bash
./gradlew buildExtension     # -> dist/ghidra_<ver>_<date>_RTLink.zip
./gradlew installExtension   # install the zip into GHIDRA_USER_EXTENSIONS_DIR
./gradlew verify             # everything CI runs: packaging check, JUnit
./gradlew viceroyTest        # local only: headless import of VICEROY.EXE (-PrtlinkViceroy=<path>)
```

Restart Ghidra to load the new build.
