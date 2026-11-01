# Vendor library signatures

`RTLinkLibrarySignatureAnalyzer` (with `LibrarySignatures` and `OmfLibrary`) recovers the
RTLink runtime entries no evidence in a program's own bytes can find, and gives every public
runtime entry its vendor name, by matching the user's own copy of the RTLink/Plus library
against the program. It does nothing until its option names a library.

## Why

After 0.7.0 a fresh VICEROY import finds 189 of the 197 runtime routines viceroy carved
by hand (`viceroyTest`). Of the eight it cannot find, checked against `RTLUTILS.LIB` of the
RTLink/Plus 6.10 distribution (`~/dosbox/RTLINK`, 74 OMF modules):

| VICEROY | viceroy's name | in the library | recovered |
|---|---|---|---|
| `210d:1cce` | `vm_longjmp` | `vmnuc` PUBDEF `_vm_longjmp` (`_vm_setjmp` + 0x46, as `1c88` + 0x46) | yes |
| `275d:0834` | `rtlink_stub_return_cx_minus1` | `ddata` PUBDEF `$$RTLOVL_ALLOC_SAVE_FILE` = `$$RTLOVL_EXTEND_SAVE_FILE` | yes |
| `275d:0838` | `rtlink_stub_return_null_farptr` | `ddata` PUBDEF `$$RTLOVL_DELETE_SAVE_FILE` | yes |
| `210d:12ec`, `13be`, `1402`, `26a0`, `3260` | `rtlink_*` | no symbol | no |

The last five split one routine at a jump target where NEBULAR's carving starts a
function. Neither VICEROY's bytes nor the vendor's symbols support a function start there,
so no analyzer makes one; they stay viceroy's curation choice.

Beyond the three, 42 public entries get their vendor names: `vmnuc`'s `$$VM_*` and `$$VM*`
entries, `_vm_setjmp`/`_vm_longjmp` and the six `_rtvm_*` section calls, and the `$$RTL*`
entries of `rtcommon`, `ddata`, `pathsrch`, `rtalloc`, `cacheenv` and the rest. The ~150
`rtlink_*` names in VICEROY are viceroy's own and stay so. Two things the library showed
about the carving: `$$RTL_TERM_PSP` names the PSP segment *word* at `275d:065e` (which
`$$RTL_REGISTER` loads into ES), not the routine at `0660`; and `$$VMFLUSHALL` is public at
`210d:1ab6`, behind a flag test VICEROY's variant puts in front of it at `1aae`, where its
callers call.

## Source: the user's library, never ours

The extension ships no vendor bytes, hashes or symbol tables. The analysis option
`Vendor library` names the user's `RTLUTILS.LIB`, or another RTLink/Plus OMF library or
object. `OmfLibrary` reads it with the JDK only, from the OMF-86 record layout: per module
the segments' bytes (`LEDATA`/`LIDATA`), the bytes fixups patch (`FIXUPP`, all location
types), and the public symbols (`PUBDEF`).

## Matching

A body is the bytes from one public to the next in its segment. Bytes a fixup patches, or
no data record gives, are never compared.

1. **Module whole.** A segment that matches contiguously, at exactly one place in the
   program's resident code, places all its publics (`ddata`: 13 bytes, three bodies, two
   with aliases).
2. **Public by public otherwise.** VICEROY's `vmnuc` matches none of the nine reference
   variants whole, and a body (which runs to the next public, taking in internal routines)
   rarely matches either. What stays the same is an entry's *opening*: its first
   instructions, decoded from the vendor bytes, up to 12, 24, 48 or 96 compared bytes,
   stopping at the first instruction without a fall-through (what follows a `RETF` may be
   a variable, as at VICEROY's `$$VM_RET`). Relative branch displacements are masked as well:
   variants move code, so a `JNZ` keeps its opcode but not its distance.
3. An opening of at least 8 compared bytes matching at exactly one place is a candidate;
   where it matches more than once, a longer opening is tried. The candidates in the block
   holding most of them, and of those the longest run in vendor order, are kept.
4. The remaining publics are placed beside a kept neighbour: at the module's distance from
   it where the opening matches there, or else at the one place between the two kept
   neighbours that the opening matches, lengthened until only one is left. That places the
   4-byte `$$VMCOMMIT`/`$$VMRELEASE` and the shared prologues of `$$VM_CALL`/`$$VM_JMP`.

Of modules placing the same name (the nine `vmnuc` variants), the one placing most publics
wins, counted by address: aliases sharing one offset count once, so a variant is not
favoured for naming the same routine twice. `$$VMGETPAGE` stays unnamed in VICEROY: its variant inserts an `AND AX,3FFF` as the
second instruction, so no opening matches.

## What it writes

- Whether a placed public is code is read from what the program's own analysis has made of
  it: an instruction starts there, or the bytes are undefined, their first word is not zero,
  an instruction decodes there, and nothing reads or writes them as data. The nucleus keeps
  its variables in its code segment (`$$VMFLAGS`), RTLUTILS its messages
  (`$$RTLCOMMON_MESSAGES`), and the OMF segment classes are just the segment names, so the
  class cannot tell.
- Code gets a function, disassembled first when needed — never inside another function's
  body: the program's partition stands, and the name goes on as a label.
- The first name goes on a default-named function as `IMPORTED`; every other name, and any
  name where a user's already is, becomes a label beside it. Nothing is cleared.
- One audit line per placement in the log.

## Where it runs

Last: BYTE, `LOW_PRIORITY.after().after()`, after `RTLinkFlowRepairAnalyzer`. The code that
marks a public as a variable can itself be buried code that pass recovers (RTLUTILS'
messages are read only from a routine nothing calls), and code-or-data is decided from the
program's state.

## Testing

- `LibrarySignaturesTest`, on libraries `OmfTestLibrary` writes (our bytes, Apache-2.0):
  the parse and its fixup masks, a module matched whole with an alias and a differing
  fixed-up word, a module matched public by public past an inserted byte with a short body
  placed beside its neighbour, a body that matches twice (refused), and a user's name
  kept.
- `smokeTest` is unchanged: the option is empty there, so the analyzer is inert.
- `viceroyTest` passes the library through `RTLinkLibraryOptionScript` (a pre-script) when
  `-PrtlinkLibrary` (default `~/dosbox/RTLINK/RTLUTILS.LIB`) exists, and then expects
  `1cce`, `0834` and `0838` as functions and checks a sample of vendor names;
  `-PrtlinkLibrary=none` runs it without.

## Rejected: Ghidra Function ID

FID hashes whole function bodies of functions that already exist. It cannot create a
function at undisassembled bytes, which is what the three need, and a body that a variant
changes anywhere, even in a neighbour's fixup, no longer hashes the same.
