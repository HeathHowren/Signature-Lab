# Signature Lab design

Signature Lab is an x64dbg plugin that turns a selected instruction into a byte
signature: the bytes of the instruction and its neighbours, with the bytes that
change between builds replaced by wildcards, grown until the pattern matches
exactly once in its module. It is the automated form of the manual recipe in
*The Game Hacker's Handbook*, chapter 14, and it emits the pattern in the forms
that chapter and Pointer Lab's auto-assembler consume.

## What it does that the existing tools do not

Four signature makers were surveyed before this design was written (A200K's
IDA-Pro-SigMaker, kweatherman's sigmakerex, Nukem9's SwissArmyKnife and
u16rogue's x64dbg-sigmaker). Their issue trackers agree on what is missing:

- **Operand-aware wildcards with a reason per byte.** Two of the four mask by
  operand type but cannot say why a byte was masked; the other two mask the
  rightmost N bytes of an instruction, which keeps RIP-relative displacements
  and masks real immediates. Signature Lab decodes with Zydis and labels each
  byte: opcode, branch target (rel8 or rel32), RIP-relative displacement,
  absolute address, pointer-valued immediate, struct offset, immediate.
  Every class is a toggle, because the trackers show users wanting opposite
  defaults (A200K #29 wants `imm8` kept; sigmakerex #25 wants struct offsets
  masked).
- **A real uniqueness check.** The x64dbg tools either check only the region
  before the target or read a single memory region. Signature Lab snapshots the
  whole module page by page, marks unreadable pages, and counts matches across
  all of it.
- **Reference signatures inside x64dbg.** When the bytes at the target are
  generic, the signature that works is one at a `call` or `lea` that refers to
  it, plus the rule for turning the match back into the target. Only the IDA
  plugins offer this today.
- **Every output form.** x64dbg `??`, IDA `?`, code-style pattern and mask, a
  C++ array with mask, and a Pointer Lab `aobscanmodule(...)` line.

## Architecture

```
src/core     siglab_core    static library, depends on Zydis only, fully unit-tested
src/plugin   SignatureLab   .dp64 / .dp32, the x64dbg glue: menus, commands, dialog, clipboard
tests        siglab_tests   Catch2, runs against a fake memory view built from hand-encoded bytes
```

The core never includes an x64dbg header. It sees the debuggee through one
interface, `siglab::MemoryView`, which reports the target's bitness, the module
containing an address, page-safe reads, and whether a value points at readable
memory. The plugin implements it over the bridge; the tests implement it over a
byte vector. Everything that can be wrong about a signature is therefore
testable without a debugger running.

### Core types

- `Pattern` is a byte vector plus a mask vector (`0xFF` compare, `0x00` skip,
  nibble masks `0xF0`/`0x0F` for x64dbg's `4?` form) plus a parallel vector of
  `ByteReason` so the UI can explain each wildcard. `parse()` auto-detects any
  of the emitted forms; `format(Format, moduleName)` emits one.
- `Decoder` wraps a Zydis decoder for one bitness and returns a `Decoded`
  instruction with its length, text, and the raw operand layout the wildcarder
  needs: displacement offset and size, immediate offsets and sizes, base
  register, branch type.
- `Wildcarder` classifies each byte of a decoded instruction and a
  `WildcardPolicy` decides which classes become wildcards. Rules, in order:
  1. A relative immediate is a branch target: rel8 (`BranchRel8`, kept by
     default) or rel32 (`BranchRel32`, masked by default).
  2. A memory operand with `RIP` as base is `RipRelative` (masked).
  3. A memory operand with no base and no index is `AbsoluteAddress` (masked).
     This is the x86 `mov eax, [00501234]` case and the `moffs` encodings.
  4. A memory operand with a base register and a displacement is
     `StructOffset` (kept). Stack offsets fall here too, and so do
     segment-based operands such as `fs:[18]` and `gs:[60]`, which are
     offsets into the TEB rather than addresses.
  5. A non-relative immediate of 32 or 64 bits whose value points at readable
     memory is `PointerImmediate` (masked). `push offset string` and
     `mov eax, offset global` in x86 code are this case.
  6. Any other immediate of 32 bits or wider is `LargeImmediate` (kept; a
     toggle masks it). Narrower immediates are `Immediate` and always kept.
  7. Bytes Zydis cannot decode are `Undecodable` (kept, and the builder notes it).
- `ModuleImage` is a snapshot of one module: bytes, a per-page readable bitmap,
  and a 256-entry byte histogram. `count(pattern, cap)` anchors on the
  rarest non-wildcard byte in the pattern, `memchr`s for it, and verifies
  around each hit. Matches that touch an unreadable page are discarded.
- `Builder` produces a `Signature` from an anchor:
  - **Forward**: append whole instructions from the anchor until the pattern is
    unique and has at least `minFixedBytes` (5) fixed bytes, or `maxBytes` is
    reached. The floor exists because a three-byte `48 89 35` can be unique
    today and match a new function tomorrow; it never pushes growth past a
    function end, and a signature left under it gets a note. Trailing
    wildcards are trimmed.
  - **Shortest**: forward growth, then a binary search on the byte length for
    the shortest unique prefix (match count is monotone in prefix length).
  - **Selection**: exactly the selected range, masked, with its match count.
  - **Reference**: find code that refers to the anchor, build a forward
    signature at each reference site, and return the best few together with
    the resolution rule (`target = match + length + rel32`, or
    `target = match + length + disp32`, or `target = *(uint32*)(match + k)`).
    A reference signature always keeps the whole referring instruction, so
    the field the rule reads is inside the pattern. Ranking: one that stays
    inside its function first, then one that meets the fixed-byte floor, then
    the shortest, then the fewest wildcards.
  The result records the match count, whether a `ret`, `int3` or
  unconditional `jmp` was crossed, and each byte's reason.
- `Builder::findReferences` scans a `ModuleImage` for references to an address. It uses an
  arithmetic prefilter (for each offset `i`, does `base + i + 4 + int32(i)`
  equal the target, or does `int32(i)` equal the target) and then confirms each
  candidate by decoding backwards to find an instruction whose displacement or
  immediate sits at exactly that offset.

### Plugin surface

The names below are pinned for the 1.x series so the book can quote them.

Disassembly view context menu, submenu **Signature Lab**:

| Entry | Hotkey | Effect |
|---|---|---|
| Make signature | Alt+Shift+S | Forward growth from the selected instruction, copies the result in the default format, logs all formats |
| Make shortest signature | Ctrl+Alt+Shift+S | Shortest mode |
| Make signature from selection | | Selection mode over the selected range |
| Make reference signature | Alt+Shift+R | Reference mode |
| Signature Lab... | | The dialog: options, generate, test, copy, save as defaults |

Dump view context menu, submenu **Signature Lab**: **Make reference signature**
(a data address has no code of its own, so the reference form is the only one
that makes sense there).

Plugins menu, **Signature Lab**: **Signature Lab...**, **Test signature from
clipboard**, **About**.

Commands, for scripts and the command bar (arguments are comma-separated, as in
every x64dbg command):

| Command | Result |
|---|---|
| `sigmake addr[, mode[, end]]` | Builds and logs a signature; `mode` is `forward`, `shortest`, `selection` (needs `end`) or `reference`; `$result` is the match count |
| `sigtest pattern` | Counts matches of an any-format pattern in the module at the current selection; lists them in the References view; `$result` is the match count |
| `sigxref addr` | Reference signatures for `addr`; `$result` is how many were built |

Every command sets `$result` to 0 before it starts, so a failed command never
leaves the previous one's value for a script to misread.

Settings persist in x64dbg's own ini under `[Signature Lab]` through
`BridgeSettingGet`/`BridgeSettingSet`, so there is no file of our own.

## Build

CMake 3.28, MSVC 2022, C++20, `/W4 /permissive- /WX`, static CRT. Dependencies
are fetched and pinned: Zydis v4.1.1 by commit, Catch2 v3.5.2 by tag, and the
x64dbg plugin SDK by the SHA-256 of `x64dbg-pluginsdk.zip` from the
`2026.05.27` release, the snapshot the book installs. One configure of the
source tree with `-A x64` builds the `.dp64`, the tests, and, through
`ExternalProject_Add` with `CMAKE_GENERATOR_PLATFORM Win32`, the `.dp32`. CPack
produces a zip laid out as `release/x64/plugins/SignatureLab.dp64` and
`release/x32/plugins/SignatureLab.dp32`, so it extracts straight over an x64dbg
folder.

## Out of scope for 1.0

Backward growth from the anchor (needs reliable reverse instruction boundaries;
select the range instead), Qt widgets (the dialog is Win32 so the plugin has no
Qt build dependency), ARM.
