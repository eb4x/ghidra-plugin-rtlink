# RTLink/Plus — overlay format and runtime

The authoritative reference for the RTLink/Plus overlay mechanisms as implemented by
this extension's analyzers. It supersedes the project's earlier working document (private
reverse-engineering notes, not part of this repo), which recorded how the format was
worked out but contained errors corrected here (see
[Corrections to the archived document](#corrections-to-the-archived-document)).

**Linker:** `.RTLink(R)/Plus` version 6.10, Pocket Soft Inc., 1993-05-24. The full
distribution — including the overlay manager's assembly source, the manuals, and the
vendor's own example programs with their link scripts — was recovered during this work
and is the source behind the V-* evidence tiers below (it is copyrighted vendor material
and is not redistributed here). Around the real linker we scripted a build-to-order DOS
harness (MSC 6.00 + RTLink 6.10 under DOSBox), which backs the CONSTR tier; its attempt
log is referred to below as the harness log.

## Provenance of the claims below

Everything here is tagged with where it comes from. In descending order of authority:

| Tier | Source | What it settles |
|---|---|---|
| **V-SRC** | Vendor assembly source: `OVLMGR.ASM` (3399 lines), `OVLMGR.INC`, `OVLMGR_M.ASM` | The **overlay-sections** manager, exactly: structs, vector layout, relocation delta, eviction, caching |
| **V-BIN** | Vendor binary with symbols: the VM manager ships only as OMF modules named `vmnuc.asm` inside `RTLUTILS.LIB`. Decoding its `FIXUPP` records recovers symbolic names for the runtime's `cs:[...]` operands | `$$VMTAB` and friends in the VM manager |
| **V-DOC** | Vendor manuals: `READ.ME`, `RTLINK.HLP`, `END-USER.DOC`, `VMEXAMPL.DOC`, `VML-EASE.DOC`, `EXAMPLE.DOC` + the `VMEX*.LNK` scripts | Product model, terminology, link-time controls, runtime env vars |
| **RE** | Disassembly of the VM manager as it sits in a shipped binary. Legitimate because the manager is a byte-identical blob (see [Fingerprint](#fingerprint)), so a trace in VICEROY holds for every VM binary | VM dispatcher, fixup call sites, stub decode |
| **CONSTR** | Built to order with RTLink 6.10 in the DOSBox harness | List-2 emission; list-3 non-emission |
| **CORPUS** | Measured across the binaries in the [corpus](#corpus) | Field ranges, counts, what actually occurs |

Where a claim is only CORPUS, it says so — a value observed in every binary to hand is
still not a guarantee about the format. That distinction is not pedantry: three separate
struct bugs in this project came from treating "zero in VICEROY" as "zero in the format".

## Two mechanisms, not two versions

RTLink/Plus offers **three** independent code-packing features (V-DOC). Two of them shape
the executable:

- **Virtual pages (VML — "Virtual Memory Linking")**. Code is split into *pages* swapped
  through a page frame by the VM manager. `VMBEGINPAGES … VMENDPAGES` / `VML` in the link
  script. Pages may execute *in place in EMS* — the reason the docs prefer EMS over XMS
  (`END-USER.DOC:56`). **This is what our analyzers support**, and what all four games use.
- **Overlay sections**. Sections at *fixed* addresses, loaded on demand and evicted when
  their address ranges intersect. `BEGINAREA … ENDAREA`. Its manager is `OVLMGR.ASM`,
  whose source ships. Unsupported by our analyzers (they decline cleanly).
- **Dynamic-data saving** (`SAVE*` commands) — swappable *data*, orthogonal to both.

They coexist in one linker and in one executable: Pocket Soft's own `VMEX4.LNK` and
`VMEX5.LNK` use `VMBEGINPAGES` and `BEGINAREA` together. So the "V1/V2/V3" numbering used
by earlier drafts and by dreammaster's tool describes **which features a program uses**,
not which linker built it.

Official vocabulary worth internalizing (V-DOC), because it explains the binary:

- **Vector** — the dispatch stub. Every reference from the root into a page is *vectored*:
  the linker emits a resident thunk (`<sym>_@@@_RTLVMFAR_VECTOR`) and points callers at it,
  because when root code runs the page may not be resident. This is why the stub table
  exists at all, and why a resident site almost never holds a raw page segment.
- **Locality** (`AUTOLOCAL`, `LOCSYM`, `LOCALON/OFF/UNKNOWN`) — a *local* reference is one
  the linker knows is safe to emit **direct**, without a vector, because the target's page
  is already present. `LOCALON` is what produces a statically encoded intra-page far call —
  and therefore a [list-2 relocation](#the-three-relocation-lists).
- **Reload** (`RELOAD`, `VMRELOAD`) — the return path. A vectored call from a page that then
  gets evicted must be re-made-resident before returning into it; the reload stack records
  who to bring back.
- **Root / resident** — the always-present load image. `VMALWAYS`/`ALWAYS` force a symbol
  resident.

## Identification

**The string** `Internal error in .RTLink(R)/Plus run-time code.` marks a binary as RTLink
at all. (Use `grep -a` or `strings -a`: GNU grep silently suppresses matches in binary
files and will tell you the string is absent when it is not.)

<a name="fingerprint"></a>**The fingerprint** for the *VM* manager specifically — the
relocation fixup loop, a byte-identical blob the linker stamps into every VM program:

```
e3 19 06 57 d1 e6 d1 e6 ad 8b f8 ad 03 c3 8e c0 26 01 15 e2 f3 d1 ee d1 ee 5f 07 c3
```

| Binary | offset of the loop |
|---|---|
| VICEROY.EXE | 0x16329 |
| NEBULAR.EXE | 0xa9c6 |
| SPHERE.EXE | 0xd49d |
| ROE2MAIN.EXE | 0x186fd |
| VMEX1/2/3.EXE | 0x4cad / 0x4b27 / 0x410d |
| VMEX4/5.EXE | 0x6687 (present — they *do* have pages, see [limits](#what-the-analyzers-do-not-support)) |
| OVTEST1/2/3.EXE | **absent** (sections only) |
| XANTH.EXE | **absent** (sections only) |

This is the load-bearing fact behind everything in [VM runtime](#vm-runtime): a trace of the
manager in one binary is a trace of the manager in all of them.

**`$$RTOVEXEOFFSET`** (V-DOC, `READ.ME` 5.02 changelog) is a public 4-byte signed integer in
the runtime, added to every computed file position before the overlay area is read. It is
the vendor's official hook for EXE compressors and copy-protection wrappers to *relocate the
overlay area within the file*. We have not met a binary that uses it, but a parser that
assumes "overlay area == image end" is assuming this field is zero.

## VM pages — the on-disk format

The overlay area begins at the **first paragraph boundary past the MZ image end**
(`e_cp`/`e_cblp`), unless `$$RTOVEXEOFFSET` moved it. From there, *records* are chained
head-to-tail: each record's header gives its total size, so record *n+1* starts at
`record_n + total_paragraphs*16`. The chain runs to EOF.

**Every record with code is a code page. There is no separate "global table" record** — see
[record 0](#record-0-is-a-code-page).

### Record header — 16 bytes, eight words

```c
struct rtlink_page_header {   /* ALL FIELDS ARE WORDS */
    uint16 total_paragraphs;     /* whole record: header + relocs + padding + code   */
    uint16 overhead_paragraphs;  /* header + relocs + padding; code starts here       */
    uint16 frame_size;           /* page frame size in paragraphs (VICEROY 700)       */
    uint16 reloc_start_index;    /* entry index list 1 starts at (0 in every binary)  */
    uint16 reloc_count;          /* entries in list 1                                 */
    uint16 reloc_count_2;        /* entries in list 2                                 */
    uint16 reloc_count_3;        /* entries in list 3 (0 in every binary; see below)  */
    uint16 codeview_word;        /* nonzero iff linked with CODEVIEW; meaning unknown */
};
```

Implemented in `src/main/java/ebbex/rtlink/RTLinkPageHeader.java`, pinned by
`RTLinkPageHeaderTest`.

> **Three fields in this header were each, at some point, mis-declared as 32-bit or
> "reserved", and each bug read correctly on VICEROY.** `reloc_count` as a dword swallows
> `reloc_count_2` — on NEBULAR that turns count 94 into 131166, header validation rejects
> the page, the walk stops before it starts, and the binary imports with *zero* overlay
> blocks. `frame_size` as a dword swallows `reloc_start_index`. And `codeview_word` was
> called "reserved" and *validated as zero* — until Pocket Soft's `VMEX2.EXE` (the same
> program as `VMEX1`, plus the one directive `CODEVIEW`) turned up carrying `0x091C` there
> on all five of its pages, and the zero check rejected the whole executable.
>
> The moral, learned three times: **check a constant against a second executable before
> believing it is part of the format.** VMEX1/2/3 are ideal — 35–42 KB, shipped with their
> C source and link scripts.

### Relocation entries and the list layout

Each entry is 4 bytes: `uint16 offset; uint16 seg_index`. The **site** it patches is at
page-linear `seg_index*16 + offset` — i.e. `(base + seg_index):offset` at runtime. The word
found there is a segment, and the fixup adds a delta to it.

Lists are addressed by **entry index**, not byte offset, and the runtime rounds the index up
to a multiple of 4 between list 1 and list 2 (which is *why* list 2 lands on a paragraph
boundary — 4 entries × 4 bytes = 16). List 3 follows list 2 with no rounding:

```
list1_off = 16 + reloc_start_index * 4
list2_off = 16 + round_up_to_multiple_of_4(reloc_start_index + reloc_count) * 4
list3_off = list2_off + reloc_count_2 * 4
```

Derive the offsets that way rather than re-deriving the alignment from the bytes; the file
and the runtime agree, and that agreement is the strongest confirmation available.

<a name="the-three-relocation-lists"></a>
### The three relocation lists

All three feed one primitive — `*(BX + seg_index):offset += DX` — and differ only in **what
the patched word points at**, hence in the base and delta they take:

| list | site lives | word at the site is | base `BX` | delta `DX` | applied when | analyzer |
|---|---|---|---|---|---|---|
| 1 | in the page | a **resident-image** segment | page frame | image load base | once, at page load | **applied** |
| 2 | in the page | a **page-relative paragraph** | page frame | `frame − prev_frame` | on every page **move** | **applied** |
| 3 | in the **resident image** | a segment pointing **into** the page | image base | `frame − prev_frame` | on every page **move** | parsed, never applied |

Lists 1 and 2 patch sites *inside* the page; list 3 patches sites *outside* it.

**List 1** is the ordinary "this page calls resident code" case: 8471 sites in VICEROY.

**List 2 is the intra-page far call.** Every site observed is the segment word of a
statically encoded `CALLF module:offset` between two modules of the *same* page — exactly
what `LOCALON` makes the linker emit instead of a vector. Established three ways:

- CORPUS: 211 of 211 list-2 sites across NEBULAR, ROE2MAIN and SPHERE hold a value below
  their own page's paragraph count; list-1 sites essentially never do.
- CONSTR: a program built with `LOCALON` in the harness emits one.
- RE: the runtime's list-2 caller (VICEROY `210d:233f`, byte-identical in NEBULAR and
  SPHERE) reads the count from header +0xA, rounds the start index up to a 4-entry group
  exactly as the struct above models, and adds `currentFrame − previousFrame` on every move.
  Invariant: **site word = file word + current frame**.

Statically, a page's frame *is* its overlay block's base segment, so that is the delta we
add. VICEROY has **no list 2 at all** — none of its overlay code takes a far pointer into
its own page; everything goes through the resident stub table. NEBULAR has 90 sites across
15 pages, SPHERE 67 across 12.

**List 3's semantics are known even though no binary has one.** The runtime spells them out:
its list-3 fixup call takes the base from `$$VMTAB[0]` — the *resident image's* load segment
— not from the page frame (see [the two calls, side by side](#vm-runtime)). So a list-3 site
is a word **in the resident image** pointing *into* the page, re-fixed by the page's movement
delta.

**And list 3 is empty in every binary, which is structural, not luck.** Such a site would
have to hold a raw page segment — which the vectoring rule (above) means normal code never
produces. Better: RTLink 6.10 **cannot emit one**. Its
resident-site patch path is advertised and not implemented — it prints "page-base relocation
will be performed when the page comes in" and then writes nothing, producing a binary that
is verifiably broken at runtime (CONSTR; fourteen harness attempts). We parse the
count and never apply the list, which is correct for a stated reason rather than caution.

<a name="record-0-is-a-code-page"></a>
### Record 0 is a code page

The archived document called record 0 a "global overlay table" — "header + 527 function
directory entries + a ~15 KB code block", with the first *code* page therefore at descriptor
index 2. **That reading is wrong, in a way worth understanding, because the same trap is
still open for other records.**

The "527 uint32 function directory entries" are record 0's **relocation list 1**:
`reloc_count = 0x20F = 527`, and the entries are the ordinary 4-byte `offset/seg_index`
pairs, misread as 32-bit pointers. The "~15 KB code block" is the record's **code** —
15,632 bytes of it, entered at textbook function prologues (`ENTER`, `PUSH BP`), reached by
**47 dispatch stubs** carrying `page_id = 1`, and containing a 44-entry `JMPF` table of its
own. It is a page like any other, and the "header" the archive quoted (`total=1112`,
`overhead=135`, `frame=700`, "val3"=527) is a perfectly standard page header.

Consequently:

```
page_id N  ->  overlay record N - 1        (page_id 1 = record 0)
```

Pocket Soft's own examples confirm it independently: `VMEX1.EXE` has five records, and its
stub table opens with `CALLF <dispatcher>; JMPF 0000:017e; dw 0x0001` — page_id 1, resolving
into record 0, which holds real code with eight callers. There is no global-table record in
the vendor's own VM output either.

The cost of the old reading was 47 stubs silently dropped in VICEROY (they failed a bounds
check and left no log line), plus a stub↔block naming skew that derailed a whole
investigation.

### The segment list — an authoritative page table

Besides the record chain, the linker leaves a table of the pages (CORPUS; VICEROY file
`0x192f0`): **31 records of 32 bytes**, one per overlay record.

```
+0   flags          word    bit 6 (0x40) set => the record contains more than one module
+8   header_offset  dword   file offset of the record's 16-byte header
+14  segment_number word    incrementing
```

Two uses: a cheap oracle to cross-check a page catalog you derived by walking the chain, and
— via the 0x40 flag — the only *independent* witness to multi-module pages, including
modules that neither the relocation table nor a naive stub scan names. Locating it: scan for
a 32-byte-stride run of records whose `header_offset` dwords point at valid page headers.
(dreammaster's heuristic — find a relocation with offset 0, look 48 bytes in for segment
numbers 2 and 3 — works on NEBULAR and fails on VICEROY.)

We do not currently read this table; the analyzers walk the chain and union the module bases
from relocations and stubs, which agrees with the 0x40 flag.

### Modules within a page

A page contains one or more **modules**, each with its own segment base (a paragraph offset
within the page). Code in a module runs with `CS = frame + module_base`, so **every
CS-relative absolute offset inside module code is module-relative, not page-relative**. This
is what makes overlay switch tables tricky, and it is why `RTLinkSwitchTableAnalyzer` exists.

A module's base can be learned from two places, and **neither alone is complete**:

- the distinct nonzero `seg_index` values of the page's relocations — but a module with no
  segment fixups of its own is invisible there;
- the `module_word` of the 14-byte stubs that call into it.

Union them (`mergeStubModuleBases`). The segment list's 0x40 flag agrees with the union, not
with either source alone. VICEROY has 2 stub-only modules; NEBULAR 28 across 15 pages;
SPHERE 30 across 21.

**And then treat what you have as *anchors*, not boundaries.** The union tells you where
modules *start*; it does not tell you where one ends, because the values are harvested from
relocation `seg_index` fields and stub module words, and a page holds paragraphs that are
neither. Real module content crosses them in both directions we have looked: a case target
past the next anchor (NEBULAR OVERLAY_78 — a case at `0x356` with the dispatch anchored at
`0x30`), and a jump table whose last entries sit past it (NEBULAR OVERLAY_26 — table
`0xa1a`–`0xa25`, anchor `0xa2` = `0xa20`, so the anchor lands *inside* the table). Using "the
next anchor" as a hard end has cost us the same way twice: the table is rejected,
`DecompilerSwitchAnalyzer` claims the dispatch instead, and its cases land in other segments
entirely. Anchor a displacement with them; bound nothing with them.

## VM runtime

Everything in this section is RE against the fingerprinted manager (offsets quoted from
VICEROY's copy at segment `210d`), corroborated by V-BIN symbol recovery where noted.

### Tables and state

- **`$$VMTAB`** (V-BIN, recovered from the `FIXUPP` records of `vmnuc.asm` in
  `RTLUTILS.LIB`) — VICEROY's anonymous `cs:[0x3999]`. `$$VMTAB[0]` is the **resident
  image's load segment**; the runtime elsewhere does `sub bx,VMTAB[0]; cmp bx,VMTAB[0x16]`,
  an "is this segment inside the resident image" range check. In the object, `$$VMTAB`
  (like `$$VMSTK` and `$$VMNAME`) is a **zero-length segment RTLink fills at link time** —
  it is the section table, not a code-pointer table, and the nucleus references it through
  exactly one `seg16` fixup in its data area (`$$VMNUC+0x2f3d`; VICEROY `210d:3999` →
  `0x26eb`, NEBULAR `1731:2bdf` → `0x1be5`). There are no per-offset code pointers in it
  to seed function starts from.
- **Descriptor table** — base segment in `cs:[0x399b]`, **2 paragraphs per descriptor**.
  Lookup (`210d:0eba`): `MOV AX,[SI+5]` (the stub's page_id) → `AND AX,0x3fff` → `DEC AX` →
  `SHL AX,1` → `ADD AX,CS:[0x399b]` → `MOV ES,AX`. The `DEC` is the `page_id − 1` above.
  `TEST ES:[0],0x8000` asks "is this page already resident?".
- **Page frame** — `cs:[0x397b]`. The page control block (`[bp+8]` in the fixup callers)
  carries `cb[0x02]` = current frame and `cb[0x12]` = the frame the in-page values are
  currently based on. On a disk reload the runtime **zeroes `cb[0x12]` but leaves
  `cb[0x02]`** — which is exactly what tells list-2 sites (inside the page; a fresh image
  resets them to raw page-relative values, so the delta is the full frame) apart from
  list-3 sites (outside; they survive holding the last-patched value, so the delta must be
  measured from where the page last was).
- **Fixup primitive** — `210d:2e59`, the fingerprint loop, a reusable
  `(DS:SI list, CX count, BX base, DX delta)` routine:

  ```asm
  jcxz  done             ; CX = entry count
  shl si,1 / shl si,1    ; SI is an ENTRY INDEX -> byte offset (x4)
  loop: lodsw            ;   DI = offset word
        mov di,ax
        lodsw            ;   AX = seg_index word
        add ax,bx        ;   ES = BX + seg_index
        mov es,ax
        add es:[di],dx   ;   *(BX + seg_index):offset += DX
        loop
  ```

  **Its three call sites are the whole story of the three lists**, and the page-move path
  (`210d:2318`…) spells out lists 2 and 3 back to back:

  ```asm
  ; ---- list 2 ----
  mov  cx, es:[0x0a]     ; count  <- header +0xA  = reloc_count_2
  mov  bx, dx            ; base   <- the page frame
  mov  es, [bp+8]
  sub  dx, es:[0x12]     ; delta  <- frame - cb[0x12]
  call 0x2e59            ; 210d:233f
  ; ---- list 3 ----
  mov  cx, es:[0x0c]     ; count  <- header +0xC  = reloc_count_3
  mov  es, cs:[0x3999]   ;        $$VMTAB
  mov  bx, es:[0x00]     ; base   <- VMTAB[0] = the RESIDENT IMAGE's load segment
  mov  dx, [bp+0]
  sub  dx, es:[0x02]     ; delta  <- frame - cb[0x02]
  call 0x2e59            ; 210d:2363
  ```

  Read off directly: list 2's sites are addressed **from the page frame** and list 3's
  **from the resident image** — which is the entire "inside the page / outside the page"
  distinction, in the vendor's own code. `210d:22a5` is the third caller: list 1, at page
  load, with the image load base as the delta.

### Dispatch stubs

Two dispatchers, discovered rather than hardcoded (any `CALLF` target shared by ≥4
`CALLF`+`JMPF` pairs — `MIN_DISPATCHER_STUB_COUNT`):

**Overlay dispatch stub** (VICEROY `210d:0dab`), 12 or 14 bytes:

```
+0   9A oo oo ss ss   CALLF dispatcher
+5   EA oo oo 00 00   JMPF 0000:offset    ; segment 0 = unrelocated placeholder
+10  pp pp            page_id             ; bits 0-13 = record + 1
+12  mm mm            module_word         ; 14-byte form only
```

The target is `record = (page_id & 0x3FFF) − 1`, at in-page offset
`JMPF_offset + module_word*16`. The 12-byte form targets module 0, so the JMPF offset is the
in-page offset directly.

**Nothing in `page_id` flags the stub length** (bits 14–15 are always clear), so the two
forms must be told apart *structurally*: if the bytes at +12 begin another dispatcher
`CALLF`, the stub is 12 bytes; otherwise a word at +12 below the page's paragraph count is a
`module_word`. Implemented in `scanForJmpfStubs`.

**Resident-target trampoline** (VICEROY `210d:0d91`), 10 bytes: `CALLF dispatcher` +
`JMPF realseg:off` with a *relocated* segment landing in resident memory. RTLink routes far
calls from movable overlay code into resident code through these, so the manager can
re-vector the caller's far return address if its page moves. Told apart from a dispatch stub
by the JMPF segment: stubs carry the unrelocated `0000`, trampolines a real segment. We
convert each into a thunk of its target; left as plain functions they wreck decompilation at
every call site (a stub has no `RET`).

**INT 3Fh stubs** (`CD 3F` + overlay id + offset) are the older Microsoft-style form.
`scanForInt3fStubs` handles them; no binary in the corpus uses them.

### Smart vectoring — the return-address resolver

The dispatcher does not simply load a page and jump. It pops the caller's far return
address, and `FUN_210d_2fd2` walks a chain of classifiers over the **machine code around
that return address** to work out how the call was made — so the call site can be patched
and the return re-vectored if the page moves. The classifiers (VICEROY) test for:

| routine | recognizes |
|---|---|
| `210d:302e` | `9A` — far `CALL` (checks `[DI-5] == 0x9A`) |
| `210d:3018` | `E8` — near `CALL`, and that `[DI-2] + DI == 0` |
| `210d:3094` | `FF /r` indirect calls, walking back 2–4 bytes over the ModRM forms |
| `210d:3046` | `CC` / `CE` — `INT 3` / `INTO` |
| `210d:3367` | `CB`-terminated `PUSH`/`PUSH`+`RETF` idioms |
| `210d:3322` | `1F`/`5F`/`9F`-family pops (segment-restoring epilogues) |

This is what the vendor docs mean by supporting "calls through function pointers": the
runtime *reads the caller's instruction* rather than assuming a call shape. For our purposes
it matters mainly because it explains why the resident stub table is reached from so many
different code shapes.

### Why an intra-page far call exists at all

A far call inside one page looks redundant — until you remember modules. Two modules in the
same page have different `CS` values, so a call between them *must* be far. It cannot be
vectored (the page is present by definition when its own code runs), so with `LOCALON` the
linker emits it **direct** — and a direct far call needs its segment word fixed up whenever
the page moves. That is list 2, and that is the entire reason the second list exists.

### The nucleus's own entries — `$$VM_INITW` and the constant-pair dispatch

Two structures reach VM-nucleus code only *through data*, so auto-analysis never
disassembles their targets; `seedVmRuntimeEntryPoints` recognizes both and seeds function
starts (names beyond the two below are left to FID against the vendor `vmnuc` objects —
the nucleus ships in at least nine build variants with shifting offsets, so only body
hashes identify the rest).

**The MZ entry point is RTLink's own 10-byte stub**, the object's public `$$VM_INITW`:
`CALLF <vm init body> ; JMPF <startup>`, both segments MZ-relocated, the init body
directly after the stub (obj `$$VMNUC+0x05c6`; NEBULAR `1731:05c6`, VICEROY file entry
`20fe:071d`). The `JMPF` target is the CRT startup — labeled `__astart`, MSC's entry
symbol (the corpus toolchain; on a non-MSC RTLink binary the function start would still be
right and only the name conventional). The tail-jump never makes the startup a function on
its own, and nothing but the stub reaches the init body at all.

**Each of `$$VM_UNK`'s two arms ends in a constant-pair dispatch** (byte-identical in the
reference objects and the VICEROY variant):

```
B8 ii ii            MOV  AX, imm16     ; vendor entry: $$VM_CALL / $$VM_JMP
BA ii ii            MOV  DX, imm16     ; inner entry, past that routine's prologue
2E F6 06 aa aa FF   TEST byte CS:[flag], 0xFF
74 06               JE   +6
B8 ii ii            MOV  AX, imm16     ; flag-set pair: $$VM_CALLR / $$VM_JMPR
BA ii ii            MOV  DX, imm16
89 44 FC            MOV  [SI-4], AX    ; the return-slot patch
FF E2               JMP  DX
```

`AX` is written into the caller's far-return offset slot, so both `AX` immediates are
function entries — they are exactly the `$$VM_*` PUBDEF symbols in the vendor object
(VICEROY sites `210d:0d18`/`0d36`, AX1 of the second = `0e52` = its `$$VM_CALL`). The `DX`
immediates land a few dozen bytes inside those routines, past the busy-wait prologue, and
are seeded as flow only, never as functions. All four immediates resolve against the
**stub-declared dispatcher segment** (the CS the stubs' `CALLF` operands carry) — *not*
the site's canonical segment and not the CS page base, which is why the stock constant
analyzer's same-block resolution of this very shape stays bogus (and stays deleted by
`RTLinkDispatcherJumpAnalyzer` — a seeded function entry is precisely the independent
evidence its clearing pass respects) while this one is exact. A target must land in the
dispatcher's own block and decode as an instruction, so a wrong segment fails closed.

Vendor `vmnuc.asm` PUBDEF offsets, for cross-checking (`$$VM_INITW` 05c6, `$$VM_UNKR`
0b42, `$$VM_UNK` 0b5c, `$$VM_CALL` 0c03, `$$VM_JMP` 0e21, `$$VM_CALLR` 0f01, `$$VM_JMPR`
1013, `$$VM_RET` 10ec, …, `$$VMGETPAGE` 18e8, `$$VMCHANGE` 1d45): NEBULAR runs 0x24 below
these up to `$$VM_JMP`'s tail and 0x5a below after it (omitted diagnostic blocks); bodies
stay byte-identical. VICEROY matches no reference build as a whole, but its individual
bodies do. **`$$VMCOMMIT`/`$$VMRELEASE` are one 4-byte body** — `B8 FF FF CB`
(`MOV AX,0xFFFF; RETF`) at obj 15f0, both PUBDEFs on the same address — a reliable
build-variant fingerprint (found by NEBULAR's naming agent).

## Overlay sections — the other mechanism

Documented from `OVLMGR.ASM`/`OVLMGR.INC` (V-SRC — the vendor's own source, so these are
their names, not our guesses). Our analyzers do **not** support this mechanism; this section
exists so it is recognizable and so nobody tries to force the page walker onto it.

**Descriptor table `$$OVLINFO`**: an `info_header`, then one `info_section` per section, then
one `info_data_section` per data-saving section. `$$OVLPBLOCK` is a small
version-independent index into it for debuggers.

```
info_section  (18 bytes)                      info_header (0x10 bytes + optional tail)
+0   is_address      word   load paragraph    +0   ih_flags       word
+2   is_fname        word   -> filename       +2   ih_tmp_stack   word
+4   is_fpos         3 byte file pos (paras)  +4   ih_basic_71_lo dword
+7   is_flags        byte   01 preload        +8   ih_basic_71_hi dword
                           02 in memory       +C   ih_num_sect    word
                           04 cache           +E   ih_num_data_sect word
                           08 data saving
                           10 committed       info_data_section (32 bytes)
+8   is_memsize      word   size in MEMORY    +0  ids_fname, +2 ids_secname, +4 ids_flags,
+10  is_num_relocs   word                     +6  ids_sec_ptr, +8 ids_alias,
+12  is_father       word   parent (-1=none)  +A  ids_ref_count, +C..+17 water marks,
+14  is_section_num  word   0-based           +18 ids_disk_pos ...
+16  is_filesize     word   size in FILE
```

Key differences from VM pages:

- **Sections have fixed load addresses** (`is_address`, assigned at link time). Nothing
  moves. Loading a section evicts every resident section whose `[is_address, +is_memsize)`
  range *intersects* it (the `INTERSECT` macro). There is no page frame and no LRU of pages
  — the LRU in the docs is the *cache* of evicted section bodies (conventional/EMS/XMS).
- **One relocation list per section**, 4 bytes per entry, applied once at load, delta
  `psp + 0x10` (the image load base). Same primitive, same entry shape as VM list 1 — the
  two mechanisms share their fixup DNA.
- **The vector is 10 bytes and has no page word:**
  ```
  +0  E8 rel16          ; near CALL $$OVLLOADIL   (make the section resident)
  +3  EA off16 seg16    ; far JMP to the real target — NOT patched at runtime
  +8  dw section_number ; 0-based index into $$OVLINFO
  ```
  Proven by the vendor's own validator (`chkvec_validate`, OVLMGR.ASM:1540-1568, used in
  `OVMURPHY` integrity mode), and decoded in `$$OVLLOADIL` as `mov ax,[bx+5]`. Because
  sections never move, the far JMP target is written once by the linker.
- **Sections form a tree** (`is_father`), and each names its own **file** (`is_fname`) — so
  some sections can live in the EXE and others in a `.OVL` written by `SECTION = "x" INTO
  file`. In XANTH, 70 of 71 sections live in `XANTH.OVL`.
- Return re-vectoring is a **reload stack** of `{section, ret_off, ret_seg}` triples pushed
  on the way in — not a code-byte classifier like the VM manager's.

**Telling the two apart in a binary:** VM pages have the fixup-loop fingerprint and a valid
page-header chain past the image end. Sections have neither; they have an 18-byte
`info_section` list (find it by the incrementing `is_section_num` at +14). A binary may have
both.

## How our analyzers model this

Six analyzers, each pinned to a different slot in the auto-analysis pipeline (an analyzer
registers exactly one `AnalyzerType` + `AnalysisPriority`, which is why this is six classes
and not one). All live in `src/main/java/ebbex/rtlink/`.

| Analyzer | Type / priority | Does |
|---|---|---|
| `RTLinkOverlayAnalyzer` | BYTE, `FORMAT_ANALYSIS.after()` | Detects the overlay area, parses records, creates the overlay blocks, applies relocations, discovers dispatchers, resolves stubs and trampolines into thunks, disassembles overlay code, seeds the VM runtime's data-reached entry points (`$$VM_INITW`/`__astart` and the constant-pair dispatch targets — see above), assumes DS=DGROUP |
| `RTLinkSwitchTableAnalyzer` | INSTRUCTION, `CODE_ANALYSIS.before()` | Recovers CS-/module-relative switch tables **and DS-relative ones** (see below), and their *references*. Must beat `DecompilerSwitchAnalyzer`, which skips computed branches that already have computed refs — winning that race is what keeps bogus targets out of other segments |
| `RTLinkSwitchOverrideAnalyzer` | INSTRUCTION, `FUNCTION_ANALYSIS.after()` | Writes decompiler jump-table overrides for those tables (shares `recoverTable()`). Cannot merge with the above: override symbols need a defined `FunctionDB` to hang a namespace off, which does not exist that early |
| `RTLinkXrefAnalyzer` | INSTRUCTION, `REFERENCE_ANALYSIS.after()` | The DS-relative data references, overlay far call/jump xrefs, and address-of immediates that Ghidra's own passes decline to make on 16-bit segmented programs |
| `RTLinkFlowRepairAnalyzer` | BYTE, `LOW_PRIORITY.after()` | Recovers buried code once every other pass has planted its flows and every conflict is bookmarked — see [Buried code](#buried-code-and-why-nothing-may-be-left-undisassembled) |
| `RTLinkDispatcherJumpAnalyzer` | BYTE, `DATA_ANALYSIS.before()` | Neutralizes the bogus current-segment computed jump the stock constant-reference pass plants on the overlay VM dispatcher trampoline: deletes only the same-block refs and the junk they caused, and leaves the `JMP` honestly unresolved so the string pass reclaims the text it destroyed |

### Modeling decisions worth knowing

- **One block per record, named by record index.** `OVERLAY_00`…, width-padded to the
  program's largest index (SPHERE has 105 records, so `OVERLAY_009` < `OVERLAY_010`). Labels
  agree: `OVLSTUB_NN_OOOO` on the stub, `OVLNN_OOOO` on the target, `RTLINK_HDR_NN` on the
  header. There is no skew between any of these numbers and the record index — an earlier
  scheme had blocks at record−1 and cost us dearly.
- **Blocks are based above the image end**, at the first 0x100-paragraph boundary past the
  highest resident block, *not* at a fixed low segment. Overlay address spaces must not
  shadow the resident image: a list-1-relocated far call from overlay code into a low
  resident segment would otherwise be bound by the disassembler back into the overlay's own
  space, planting garbage over real page bytes. (List-2 far calls *do* land inside their own
  block, which is where overlay binding is correct.)
- **The static frame is the block's base segment.** That is the delta list 2 gets. List 1
  gets the image load base (`0x1000`, where `MzLoader` puts the image; it never sets the
  program image base, so `getImageBase()` would return 0 — do not use it here).
- **Stubs and trampolines become thunks** of their targets, and stale "Bad Instruction"
  bookmarks on stubs we resolve are cleared (they are fossils of the disassembler walking a
  `JMPF 0000:xxxx` before we got there).
- **Everything is re-runnable.** All of them set `setSupportsOneTimeAnalysis()`; the overlay
  analyzer's `repairStubThunks` path rebuilds its state from existing blocks, and tolerates
  the legacy `OVERLAY_(record−1)` naming of programs imported before the fix.
- **Report counts with `Msg.info`, never `log.appendMsg`** — any content in the analysis
  `MessageLog` makes `AutoAnalysisPlugin` pop a "warnings/errors issued during analysis"
  dialog, so the `MessageLog` is for genuine failures only.

Tests: `RTLinkPageHeaderTest` (header shapes incl. VMEX2's CODEVIEW word),
`RTLinkOverlayRelocationTest` (pins both deltas hermetically),
`RTLinkAddressOfXrefTest`, `RTLinkRuntimeDataSegmentTest`, `RTLinkVmRuntimeSeedTest`
(the entry stub and the constant-pair dispatch in miniature, plus the refusals).

### The runtime owns DS — the assumption does not reach it

`RTLinkOverlayAnalyzer` detects DGROUP from the C startup and assumes `DS = DGROUP`, which is
what makes DS-relative globals resolve at all. **That assumption is a property of
compiler-generated code, and the RTLink runtime is not compiler-generated.** The runtime
manages DS itself:

- The **VM manager** (VICEROY `210d`) reloads DS constantly from its own saved-segment slots
  — `MOV DS,word ptr CS:[0x3999]`, `CS:[0x39a1]`, `CS:[0x39a5]` — and does `MOV DS,CS` in its
  error paths, e.g. at `210d:4454`:

  ```
  mov dx,cs
  mov ds,dx           ; DS = CS = 210d, not DGROUP
  mov bx,0x44a7       ; -> 210d:44a7, its own message text
  ```

- The **support code** (VICEROY `275d`) is entirely CS-relative (`cs:0x65e`, `cs:[bx]`,
  `cs:0x713`) and never loads DS at all.

This matters beyond decompiler cosmetics, because `RTLinkXrefAnalyzer` keys **both** its
DS-relative pass and its address-of-immediate pass off this context: with DGROUP asserted
over the runtime, the `MOV BX,0x44a7` above resolves to `DGROUP:44a7` and materialises a data
reference there — a label on an unrelated game global, from an instruction that never touched
DGROUP. The noise is worst where it is least visible: such a label landing inside a real
array (the savegame unit array at `2b5a:3144`) reads as evidence that the array ends there.

So the DS assumption **skips the runtime's code blocks** and leaves DS unset in them. That is
the honest state — we do not know what DS holds at an arbitrary point in the runtime — and it
is what makes both xref passes decline it outright, since each is gated on a present DS value.
Both halves are located by signatures this document already relies on: the VM manager by the
[fixup-loop fingerprint](#fingerprint), the support code by the RTLink error text from
[Identification](#identification), which is present even in section-only binaries — they have
no VM manager, and so no fingerprint. DGROUP's own block is never disowned, however those
signatures fall.

On VICEROY: DS assumed over 134 blocks, 2 runtime blocks skipped. Scoping it this way is what
keeps 103 references over 19 DGROUP globals — every one of them originating in the runtime —
from being invented; the globals the *program* really uses are untouched (`colony_count` 62
xrefs, the unit array 155, the player array 29), as are the switch tables (38 + 1 → 39
overrides: no DGROUP-table dispatch lives in the runtime).

Note that the assumption is recorded as a register context over memory, and the
`RTLink Data Segment Assumed` flag makes it idempotent. Neither is retroactive: a program
analyzed by an older build keeps whatever context that build wrote, so re-import rather than
re-run if its runtime blocks decompile with phantom DGROUP globals.

### The DS-relative jump table

Not an RTLink construct at all — a compiler one — but it has to be recovered here for the
same reason the CS-relative tables do: whatever we leave unresolved, `DecompilerSwitchAnalyzer`
resolves *wrongly*. The table lives in **DGROUP data**, not after the code, and is reached
through a pointer rather than a `CS:` displacement (ROE2MAIN.EXE `122e:5280`):

```
MOV DI,0xb26a          ; table base — a DS offset
XOR CX,CX
MOV CL,[BX + SI + 5]   ; index, straight out of a struct field — already scaled
ADD DI,CX
JMP word ptr [DI]      ; FF /4, mod=00
```

Nothing bounds it: there is no `CMP` guard, because the index is a byte the program trusts.
So the entries themselves have to say where the table ends — read words until one is not a
plausible case target — and "plausible" has to be sharp, because ROE2MAIN's four entries
(`52ae, 5282, 528a, 52a3`) are followed immediately by unrelated variables whose first word,
`0x0078`, *is* a valid instruction address in the same block, just inside a different
function. Two bounds that look right and are not:

- **The function's body** — the case targets are reachable only *through* the table, so they
  are precisely what a flow-derived body leaves out. Bounding by it asks the switch to be
  resolved before it can be resolved.
- **The `FunctionManager` at all** — `FunctionAnalyzer` ("Create Function") sits at the *same*
  `CODE_ANALYSIS.before()` priority as this analyzer, and equal priorities run
  first-queued-first, so whether the dispatching function exists when we look is not ours to
  decide. In ROE2MAIN it does not.

What does exist by then is the disassembler's own **call references**, and a function begins
where something calls it — which is what `FunctionAnalyzer` keys on too. So the range runs
from the nearest call target at or below the dispatch to the nearest one above it, and a
target outside that range ends the table. `0x0078` is outside; the four real entries are not.

Recovering this one dispatch is worth a paragraph because of what it cost while unresolved:
`DecompilerSwitchAnalyzer` "resolved" it into **134 targets across five segments**, which is
where ROE2MAIN's ~60 `DecompileCallback` p-code errors came from (flows into `0000:`,
`9000:`, `f000:`) and most of its analysis time. Recovering it takes **Decompiler Switch
Analysis from 118.6 s to 4.7 s** (total analysis 162 s → 35 s), removes the p-code errors
entirely, and takes the ERROR bookmarks from 19 to 4.

One knock-on, worth knowing because it is the kind of ordering bug that hides: the case at
`122e:528a` sits inside the *clear window* of an emulated-float call two bytes into the case
before it. `EmulatedFloatPatcher` clears that window and re-disassembles **by flow**, which
never reaches a jump target — so the case came back as raw `CD 35` bytes. It now restarts
disassembly at every flow-reference destination inside the window as well, which is exactly
the reference this analyzer had just added.

### Buried code, and why nothing may be left undisassembled

Code that no pass ever disassembles is invisible: it is not wrong, it is *absent*, and
nothing in the listing says so. Three mechanisms produced it in this corpus, and
`RTLinkFlowRepairAnalyzer` (BYTE, `LOW_PRIORITY.after()` — dead last, once every flow has
been planted and every conflict bookmarked) exists to make all three impossible.

**A relocated word behind a call.** Each binary's C startup exits through a vector —
`MOV AX,0xFF; PUSH AX; PUSH CS; CALL word ptr [__exit]` (VICEROY `1d1d:0241`, NEBULAR
`1417:00fd`, SPHERE `160f:0109`, ROE2MAIN `122e:011c`) — whose callee reaches `INT 21h/4C`
and never comes back. The bytes at the call's fall-through are an *inline relocated segment
word*, and the disassembler decodes them as code. The invariant that settles it: **an
address carrying a loader relocation can never be the first byte of an instruction** — MZ
relocations patch operand words. So the call cannot return there whatever its callee does;
the analyzer marks it `CALL_RETURN`, clears the junk, and **seals the word as data** so no
later pass can decode it again. In NEBULAR that junk was burying a real routine
(`1417:0104`, called from `1417:00b1`) — 197 bytes of function that simply did not exist.

**Junk winning a conflict.** When a flow target is already covered by junk, the disassembler
stamps `Failed to disassemble at X due to conflicting instruction` *at the blocked address*
and moves on — the junk keeps the bytes. The analyzer arbitrates by evidence: the blocked
address must have a flow reference or a fall-through from evidenced code, and every
conflicting instruction must have none. Then, and only then, the junk is cleared
(`ClearFlowAndRepairCmd`, which prunes anything with outside evidence) and the real code
disassembled. Evidence on *both* sides is declined with a warning — that is not ours to
decide — and evidence on *neither* side is left strictly alone, which is what keeps the
analyzer off the unreferenced disassembly islands over zeroed C-library data.

**Routines nothing reaches.** ROE2MAIN's `122e:51a0` is a function whose entry nothing
references (its siblings are called through pointers), whose bytes were cleared out from
under the pattern seeders by the emulated-float rewrite, and which flow-based recovery
therefore never reaches: an undefined 11-byte hole holding `PUSH BP; MOV BP,SP; SUB SP,0x12`
— byte-for-byte the prologue of its sibling `FUN_122e_5177` — with its epilogue stranded four
bytes further on (`122e:51be`, `MOV SP,BP; POP BP; RETF`; the disassembler's fossil bookmark
there names the page-segment alias `1000:749e`, the same flat byte). The analyzer claims such
a gap only when the bytes account for themselves *exactly* — every instruction decodes and
the run ends precisely on the boundary of the code that follows, one byte over or under and
the decode is out of phase — **and** the gap looks like a routine: a frame prologue, a
stranded epilogue where the next function begins, or a straight fall-through from above. A
run of one repeated byte is padding by definition and is never claimed. A gap whose decode
flows into memory that does not exist is never claimed either: that is RTLink's own dispatch
stub (`CALLF dispatcher; JMPF 0000:offset`, segment unrelocated until the overlay manager
patches it), and it belongs to `RTLinkOverlayAnalyzer`.

**Filler is not code.** The DGROUP segment is mapped executable — there is code down there
among the data — so its zeroed regions are fair game for anything that disassembles at an
address it never checked, and something does: a switch's *default* case is disassembled
**without a reference to it** (`DecompilerSwitchAnalysisCmd`), so a garbage default target
leaves behind a run of instructions that nothing points at and nothing reaches. NEBULAR carried
two such islands and SPHERE three — dozens of `ADD [BX+SI],AL` apiece, which is what `00 00`
decodes to — each running until the disassembler's repeated-byte limiter gave up, leaving the
ERROR mark that was the only visible trace of any of it. (NEBULAR's first island had been
decoded *twice*, one byte out of phase; the phase break is the "conflicting instruction" that
was bookmarked, and it sits in the one-byte hole between the two chains, on no instruction at
all — which is why the marks are swept over the span the junk covered, not over its
instructions.)

**The test is on the bytes in memory, never on the instruction**, and the corpus itself
insists on the distinction: `00 00` is a perfectly real instruction, and SPHERE has one inside
`OVL023_03D4` (`MOV SI,[BP-0x3e]; ADD [BX+SI],AL; JMP ...` — a byte store), sitting between
`76 c4` and `eb c2`. What condemns an island is that it lies inside a run of at least sixteen
zero bytes, which no instruction stream is; and even then it is only deleted if nothing claims
it — no instruction in it referenced, none a function entry, and none fallen into from outside
(that last is what keeps this off the handler table behind a non-returning call, which is the
previous section's business). Instructions that merely *straddle* the edge are left alone:
`MOV AX,0` is `b8 00 00`, and two of its three bytes are zero. Only zero is claimed as filler —
a run of `0x90` is a NOP sled, which is real code.

This makes the two halves exact mirrors: **the gap filler will not create code over filler, and
this will not keep it.**

**Flows through a vector in the code segment.** Ghidra does not follow an indirect far flow,
so what sits behind one is never disassembled — and, having no reference, is never found by
anything else either. Every binary here links a vendor driver that reaches its **fatal error
handler only through `JMPF CS:[0x656]`**, and the vector is a plain far pointer sitting
initialized in the image (VICEROY `275d:0656` → `275d:0660`). Behind it: 83 bytes of real
code — redirect stdout onto stderr (`INT 21h/46h`), print the message, wait for a key,
`MOV AX,0x4C01; INT 21h` — that no pass had ever decoded. The analyzer follows such a vector
whenever its four bytes are initialized and point into mapped executable memory (a zero or
unrelocated vector is a runtime-patched stub, and is left alone).

That handler is also what explains the one ERROR bookmark each binary used to carry
(VICEROY `275d:0778` and its twins). The driver's routine registers cleanup handlers in a
twelve-entry table at `CS:0x758` — six bytes each, bounded by the `CMP BX,0x7a0` three
instructions before the abort — and hooks the PSP's INT 22h termination vector the first time
it is used. When the table is full it aborts: `PUSH CS; CALL 07a4`, which tail-jumps through
that vector into the handler, which **terminates the process**. So the call never returns, and
what follows it is not code at all but the handler table itself — sixty-odd zero bytes the
disassembler decoded until its repeated-byte limiter gave up. Once the vector is resolved the
whole chain is provable, and the analyzer proves rather than assumes it: a routine is
non-returning only if it contains no return instruction and each of its terminal paths is
either the DOS exit idiom (`INT 21h` with `AH = 4Ch`) or a tail-jump into another routine
already known to terminate — a fixpoint, so a chain of tail-jumps is followed. Calls to such
a routine lose their fall-through, and the junk decoded from it is cleared.

Two things about that chain are worth keeping in mind, because both cost a debugging cycle.
**Ghidra is told that a DOS exit ends the routine** (`FlowOverride.RETURN` on the
`INT 21h/4Ch`): left unmarked it is just an instruction with a fall-through, and the bytes
after it get absorbed into the routine that exits — which is how ROE2MAIN's handler came to
swallow the routine below it (a body of 123 bytes where VICEROY's, whose successor was
already a function, is 83) and thereby to contain a `RETF` that made it look like it returns.
And **a tail jump is recognized by the instruction, not by its flow type**: Ghidra's
shared-return pass rewrites a tail `JMP`/`JMPF` into a call, after which the flow type
describes what Ghidra made of it rather than what the code does, and the jump's flow list is
empty — so destinations are taken from the references instead.

<a name="what-the-analyzers-do-not-support"></a>
### What the analyzers do not support

| Not supported | Why / what happens |
|---|---|
| **Overlay sections** (OVTEST1–3, XANTH) | No page-header chain at the image end ⇒ no overlay blocks created. Declines cleanly; the resident image still analyzes fine. Would need `info_section` discovery + a second `FileBytes` for the sibling `.OVL` — a loader-level change |
| **Mixed section+page binaries** (VMEX4, VMEX5) | The section area comes first, so the chain is not at the image end and discovery finds nothing — even though the pages are there (the fingerprint is). Supporting them means locating the page table properly instead of assuming the chain starts at the image end |
| **`$$RTOVEXEOFFSET` ≠ 0** | Same root cause: we assume the area starts at the image end |
| **List 3** | Parsed, never applied. Correct: RTLink 6.10 cannot emit one |
| **`.RTL` / RTLINKST programs** | No specimen |

### The XLAT state machine, and the Sleigh bug behind it

> **Resolved (2026-07-13).** Both halves are fixed, in the order the investigation
> prescribed: the formatter FSM's dispatch is bounded by
> `RTLinkSwitchTableAnalyzer.recoverFormatterFsmTable`, and the XLAT segment bug in the
> stock x86 Sleigh spec is fixed in `ia.sinc` — submitted upstream as
> [ghidra#9391](https://github.com/NationalSecurityAgency/ghidra/pull/9391) and carried
> meanwhile on the `dailydriver` branch of [eb4x/ghidra](https://github.com/eb4x/ghidra).
> The claim this section used to repeat — "nothing in the instruction stream bounds the
> table" — was a placeholder for work not done, and is retracted below.

Each binary's C library carries the MSC `_output` formatter — an `XLAT`-driven FSM,
byte-identical across the corpus modulo addresses (VICEROY `1d1d:199c`, NEBULAR
`1417:0d92`, ROE2MAIN `122e:1026`, SPHERE `160f:0c86`):

```
1417:0d92  MOV BX,0x4f36        ; combined class/transition table — a DGROUP offset
1417:0d9b  XLAT                 ; AL = DS:[BX+AL]   low nibble = character class
   ...
1417:0da9  XLAT                 ; same BX           high nibble = next state
1417:0dab  INC CL
1417:0dad  SHR AL,CL            ; state = table[class*8 + current] >> 4
   ...
1417:0db6  JMP word ptr CS:[BX + 0xd54]
```

No `CMP` bounds the final index — but the bound is in the FSM's own data. The table is
MSC's dual-purpose `__lookuptable`: the low nibble of `table[c-' ']` classifies the
character, the high nibble of `table[class*8 + state]` is the next state, and the two
regions deliberately share the same bytes. A fixpoint over the reachable
`(class, state)` pairs yields the exact jump-table entry count — **8 states** in all four
binaries (same library). `recoverFormatterFsmTable` matches the prologue
instruction-for-instruction (the `MOV CL,3`/`INC CL` pair proves both shift widths, hence
both the `class*8` layout and the 16-state `SHR AL,4` ceiling), reads the table via the
DS program context, and validates every jump-table word against the dispatching
function's range before claiming anything. It feeds the shared `recoverTable`, so the
reference pass and the decompiler override both get it. Each binary recovers exactly one
more switch table (39/83/124/59) and the FSMs decompile as real 8-case state machines.
`RTLinkFsmSwitchTableTest` covers the recognizer with the transcribed corpus bytes.

**The Sleigh bug, now fixed:** `XLAT` was the only memory access in the whole x86 spec
that ignored its segment — `ia.sinc` gave the 16-bit form `ptr2(tmp, BX+zext(AL))`, a
flat zero-extension, where every other 16-bit operand (`Mem16`, `moffs`, the string ops)
goes through `segment(seg16, offset)`. The constructor even parses and prints the segment
(`XLAT CS:BX` and `XLAT SS:BX` both occur in this corpus) and then threw it away. In real
mode every translate table was therefore read from physical `0000:offset` — the interrupt
vector table — which is where the one benign-looking warning each binary used to leave
(`Unable to read bytes at ram:0000:4f36` etc.) came from; and CS:/SS: overrides were
silently decompiled as DS: reads. The fix is the obvious one-liner
(`segment(seg16, BX+zext(AL))`), but **order mattered**: taken alone (tried once,
reverted) it let the decompiler read the class table and then resolve the FSM dispatch
*unboundedly* — its range analysis honors only `INT_AND` masks, not the `SHR AL,4` — so
it fabricated cases and planted `halt_baddata` flows (ROE2MAIN 4 → 6 ERROR bookmarks,
SPHERE 5 → 6). With the FSM bounded first, the fix measures clean on fresh imports of all
four binaries: warnings gone, ERROR bookmarks unchanged (1/5/5/4), switch tables
unchanged, and the `XLAT SS:BX` sites in NEBULAR/SPHERE overlay code (a translate loop
through a caller-passed stack table) decompile correctly instead of silently reading DS.

**The runtime `XLAT CS:BX` sites are not dispatches.** Every binary has the same four
sites in its runtime segment (VICEROY `210d:3151`/`3188`/`33c4`/`33d5`, ROE2MAIN/SPHERE
at `+0x2703`/`+0x273a`/`+0x28e1`/`+0x28f2`, NEBULAR shifted): they are the VM nucleus's
modrm **reg-field decoder** — `AND AL,7; XLAT CS:BX; CBW; MOV SI,AX; MOV AX,[BP+SI]`
translates an instruction's 3-bit register field through an 8-byte table of
saved-register frame offsets (x86 register order AX,CX,DX,BX,SP,BP,SI,DI; `FF` = SP,
not on the frame, sign-checked via the `CBW`) to fetch that register's saved value
during instruction-fault operand recovery. Ground truth is the compiled OMF module
`vmnuc` (segment `$$VMNUC`, nine build variants) in the vendor distribution's `RTLUTILS.LIB`; no
vendor assembly source exists for it — `OVLMGR.ASM` is the unrelated *disk* overlay
manager. These tables also exposed an xref bug, since fixed: the address-of pass used to
give the `MOV BX,imm` table pointers DS-relative DGROUP references
(`DAT_2b5a_3171`-style), which the decompiler then consumed as rendering hints;
`RTLinkXrefAnalyzer.xlatOverrideSegment` now retargets them to the code segment.

<a name="corpus"></a>
## Corpus

Games (measured with the current analyzers, fresh imports):

| Binary | records | stubs | trampolines | switch tables | list-2 sites | ERROR bookmarks |
|---|---|---|---|---|---|---|
| VICEROY.EXE | 31 | 658 | 371 | 39 | 0 | 1 |
| NEBULAR.EXE | 79 | 831 | 22 | 83 | 90 | 5 |
| SPHERE.EXE | 105 | 869 | 65 | 124 | 67 | 5 |
| ROE2MAIN.EXE | 171 | 1997 | 136 | 59 | 54 | 4 |
| XANTH.EXE | — (sections) | — | — | — | — | — |

(All measured from fresh Ghidra imports. XANTH imports with **no** overlay blocks — see
below.)

**ROE2MAIN is the stress case**: 171 records, 671 KB of overlay code, and 1997 stubs — three
times VICEROY's. Stub and trampoline recovery matched a file-level census exactly on the
first run (1997/1997, 136/136). It also taught us that **the switch-dispatch idiom is a
property of the compiler, not of RTLink**: ROE2MAIN doubles the switch index with
`ADD AX,AX` where the other four games use `SHL AX,1`, and it uses `SHL` at *none* of its 60
table dispatches — so before the matcher accepted both forms, it recovered **zero** tables,
and Ghidra's own switch analyzer filled the vacuum by reading a *string table* as a jump
table and chasing ASCII pairs (`"AN"`, `"AR"`, `"BO"`) into unmapped segment `4000`. It is
also the only binary in the corpus with a **DS-relative** jump table (above). Its last
declined dispatch class — the `XLAT`-indexed formatter FSM — is now recovered too, bounded
by the FSM's own state table (see the XLAT section above).

**ROE2MAIN also needed a non-RTLink fix**, worth knowing about because it will recur in any
float-heavy DOS binary. Its floating point is compiled for the **emulator**: each x87
instruction `ESC(D8+n) modrm…` is emitted as `INT (34h+n) modrm…`, and when a coprocessor is
present the runtime rewrites `CD 3n` in place to `9B D8+n` (WAIT + ESC) — which is why the
encoding is exactly two bytes. Ghidra's real-mode Sleigh reads `CD 3n` as a plain two-byte
`INT` and then disassembles the operand bytes as code, so every one of ROE2MAIN's ~1000
calls derailed the instruction stream. `EmulatedFloatAnalyzer` (new) performs the same
rewrite the runtime does, and its float code now reads as x87 — `WAIT; FSTP ST0; FSTSW AX;
SAHF; JNZ`, the compare idiom, previously garbage. That is what took ROE2MAIN's ERROR
bookmarks from 74 to 19 (and the DS-relative switch above took them from 19 to 4). It is
gated on emulator-call density, so the four games (1–8 stray `CD 3n` byte pairs each, all
coincidence) are untouched.

Three interrupts carry more than the `ESC n` in their number:

| call | is | patch |
|---|---|---|
| `INT 34h`–`INT 3Bh` | `ESC 0`–`ESC 7` (`D8`–`DF`), modrm follows | `9B D8+n` |
| `INT 3Ch` | an ESC with a **segment override**; bit 7 of the next byte picks it — set (`D8`–`DF`) = `ES:`, clear (`58`–`5F`) = `SS:` and the ESC is that byte with bit 7 restored | `9B 26` / `9B 36` (+ restore the opcode) |
| `INT 3Dh` | `FWAIT` — no operand bytes | `9B 90` |

Neither segment form is a guess. Every `ES:` site is preceded by `LES SI,[BP+8]` or
`MOV ES,[..]` — a far pointer being dereferenced. Every one of the 154 `SS:` sites has modrm
`rm=7`, i.e. **`[BX]`**, preceded by `SUB SP,8; MOV BX,SP` — and `[BX]` defaults to `DS`, so
addressing that stack temp *requires* `SS:`. Restored they read `FLD/FST/FSTP qword ptr
SS:[BX]`: a double being passed by value. Only `INT 3Eh` (2 sites) is still unknown, and is
left as an `INT`.

Two lessons are baked into it: the
rewrite must be driven by the *disassembler*, never a byte scan (a byte scan destroyed the
dispatch stub whose `JMPF` offset is `0x34CD`), and the clear before re-disassembly must
reach *past* the call, because the mis-decode leaves the following instructions out of
phase and they would otherwise block the corrected flow.

The remaining ERROR bookmarks are genuine binary quirks, not analyzer defects: fallthrough
into an ISR module's own zeroed vector table (VICEROY `275d:0778`), zero-run fragments in
DGROUP code tails, and a Borland RTL call one byte into a patched instruction (NEBULAR
`1417:0104`). SPHERE's `160f:010d` is an emulator call too sparse to trip the density gate.

Vendor examples, imported into our Ghidra project (they are small, have C source and
link scripts, and are the best regression material we have):

| Binary | link script demonstrates | records | stubs | tramp. | notes |
|---|---|---|---|---|---|
| VMEX1.EXE | `VML` (virtualize everything automatically) | 5 | 9 | 17 | record 0 has code; one straddling stub |
| VMEX2.EXE | + `AUTOLOCAL`, `LOCSYM`, **`CODEVIEW`** | 5 | 9 | 17 | `codeview_word = 0x091C` on every page |
| VMEX3.EXE | `VMBEGINPAGES` + `SEPARATE` (partial virtualization) | 4 | 7 | 17 | cleanest specimen |
| VMEX4.EXE | pages **and** sections, explicit `SECTION`s | (5) | — | — | mixed: page chain not at image end ⇒ declined |
| VMEX5.EXE | + per-module `LOCALON/LOCALOFF/LOCALUNKNOWN`, `CVON/CVOFF` | (?) | — | — | mixed: declined |
| OVTEST1–3.EXE | sections only | — | — | — | no fingerprint, no chain ⇒ declined |

Every VMEX page carries `frame_size = 0x262`, `reloc_count_2 = 0`, `reloc_count_3 = 0`.

**Declining is not automatic — the header validator earns it.** A naive chain-walk of
XANTH.EXE (sections only) *does* parse one plausible-looking record at the image end, with
nonsense counts (14515 list-2 entries, 22096 list-3). `RTLinkPageHeader.isValid()` rejects
it, so XANTH imports as a plain MZ with no overlay blocks and no damage — as do OVTEST1–3
and the two mixed VMEX binaries. Verified by import, not assumed.

### Stubs may straddle a block boundary

Importing VMEX1 turned up a real bug, since fixed. **A stub or trampoline can begin in one
MZ segment block and end in the next.** VMEX1's jump table starts at flat `0x18fb0`, but the
preceding segment block (`17fe:0000`–`17fe:0fd1`) runs two bytes *into* it — so the first
stub's `CALLF` lives in one block and its `JMPF` and page_id in the next.

The scans iterate blocks, and each one range-checked its candidate against **the block it
happened to be iterating**, so a straddling stub failed `block.contains(callfAddr)` and was
dropped without a word. Range-checking against *memory* instead (`isCodeMemory`) fixes all
seven scan guards at once. This was not cosmetic and not VMEX-only:

| | before | after |
|---|---|---|
| VMEX1 stubs | 8 (+1 ERROR bookmark) | **9**, no ERROR |
| VICEROY trampolines | 370 | **371** (one at `2b1f:000a`, crossing its block end by 4 bytes) |
| SPHERE trampolines | 64 | **65** |

Stub counts and ERROR bookmarks in the games are otherwise unchanged, so the extra
trampolines are recovered code, not false positives.

## Prior art

dreammaster's `rtlink_decode` (<https://github.com/dreammaster/tools>, branch
`rtlink_decode`) flattens RTLink executables for IDA. Where we overlap we agree — the 4-byte
relocation shape, the page-linear site semantics, the 1-based page selector, the 14-byte
module-word stub form — which is useful mutual validation. It never disassembles, so the
dispatcher-by-consensus discovery, the descriptor mechanism, modules-as-CS-bases and hence
the switch tables, the decompiler overrides, and the DS/DGROUP xrefs are outside its scope.
Its DGROUP location is a hack worth *not* copying (scan for the `"MS Run-Time"` string,
subtract 8); we trace the startup's actual DS load.

> **Licence.** `rtlink_decode` is **GPL-2** (it pulls in ScummVM's `common/`). This
> extension is **Apache-2.0** ([LICENSE](../LICENSE)), so GPL code cannot be mixed in.
> Read it to corroborate findings; **do not lift code or verbatim structure into the
> analyzer.** Everything here is independent derivation and must stay that way.

## Corrections to the archived document

The archived working document (the project's earlier private RE notes) was substantially
right and is where most of this came from. What changed:

| Archive said | Actually |
|---|---|
| Record 0 is a "global overlay table": 527 uint32 function-directory entries + a code block that "appears to be" resident stubs. First code page = descriptor index 2 | Record 0 is a **code page**. The "527 entries" are its relocation list 1; the "code block" is its code. `page_id 1` = record 0 |
| Blocks are `OVERLAY_(page_word−2)`, stubs `OVLSTUB_(page_word−1)` | Both are the **record index**, and width-padded past 99 records |
| Overlay blocks based at flat `0x1_0000` | Based **above the image end**; the old base let overlay spaces shadow resident code |
| List 2: "page-relative paragraph (0 = page base, or a module base)" | Right, and more specifically: the segment word of a **statically encoded intra-page far call**, which is what `LOCALON` emits. Runtime caller validated |
| "365 direct stubs" in VICEROY | 370 resident-target trampolines |
| Page counts 30 / 78 / 104 / 170 | 31 / 79 / 105 / 171 records — the old counts excluded record 0 |
| Open item: stub `281f:0668` "lands mid-instruction, likely dead" | Resolves correctly once its `module_word` is applied |
| "reloc_count_3 is always zero (7 attempts to force one failed)" | Stronger: RTLink 6.10 **cannot** emit one — its resident-site patch path is advertised but unimplemented (harness attempts 8–14) |

Still true and carried over: the fingerprint, the two-mechanisms framing, the header's eight
words and their three historical misreads, the list semantics table, `$$VMTAB`, the
descriptor lookup, the segment list, module bases from the union of relocations and stub
words, the `info_section` struct, the build-harness recipe and its `LOCALON` gotchas, the
Clipper dead end (Clipper 5.0's OEM RTLink has no VM runtime; 5.3 bundles Blinker instead),
and the dreammaster comparison.
