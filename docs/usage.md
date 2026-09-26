# Using Signature Lab

Signature Lab turns an instruction you have found in x64dbg into a byte
signature: a pattern that finds the same code again after the program is
rebuilt, patched or loaded at a different address. This guide covers every
menu entry, command and setting. The examples were made against
`PointerLabTutorial.exe`, the practice target that ships with
[Pointer Lab](https://github.com/HeathHowren/Pointer-Lab), so you can
reproduce them.

## Install

1. Download `SignatureLab-v1.0.0.zip` from the
   [Releases page](https://github.com/HeathHowren/Signature-Lab/releases).
2. Extract it into your x64dbg folder, the one that contains `release`. The two
   plugins land where x64dbg looks for them:

   ```
   release\x64\plugins\SignatureLab.dp64    used by x64dbg.exe (64-bit targets)
   release\x32\plugins\SignatureLab.dp32    used by x32dbg.exe (32-bit targets)
   SignatureLab\                            licence, notices and these docs
   ```

3. Start x64dbg or x32dbg. The Log tab shows:

   ```
   [Signature Lab] 1.0.0 loaded. Right-click an instruction, Signature Lab, or press Alt+Shift+S.
   ```

Signature Lab is built against, and tested with, the x64dbg snapshot of
2026.05.27. It has no other dependencies: the C runtime is linked statically.

## Make a signature

Select an instruction in the CPU view, right-click it and choose
**Signature Lab > Make signature**, or press **Alt+Shift+S**. Signature Lab
reads the whole module, grows a pattern from the selected instruction until it
matches exactly once, writes a report to the Log tab and copies the pattern to
the clipboard.

```
[Signature Lab] pointerlabtutorial.exe+0x1670 (7FF7C43E1670)  forward  20 bytes, 4 wildcards, unique
  x64dbg       48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B D9
  IDA          48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ? ? ? ? 48 8B D9
  code+mask    "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\xD9"
               "xxxxxxxxxxxxx????xxx"
  C++ array    const unsigned char sig[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD9 };
               const char mask[] = "xxxxxxxxxxxxx????xxx";
  Pointer Lab  aobscanmodule(INJECT, pointerlabtutorial.exe, 48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B D9)
  wildcards    bytes 13-16 RIP-relative displacement
  instructions
    7FF7C43E1670  mov [rsp+08], rbx
    7FF7C43E1675  push rdi
    7FF7C43E1676  sub rsp, 20
    7FF7C43E167A  mov rax, [00007FF7C440DBF0]
    7FF7C43E1681  mov rbx, rcx
  copied       x64dbg form to the clipboard
```

How to read it:

- **The first line** says where the signature starts, as a module offset and
  as an address, which mode made it, how long it is, how many bytes are
  wildcards, and whether it is unique. "unique" means exactly one match in the
  whole module, every readable page of it.
- **The next five lines** are the same pattern in each output form. The
  clipboard gets the form chosen under *Copy as* in the dialog (x64dbg by
  default).
- **wildcards** names every masked byte and why it was masked. Bytes are
  numbered from 0. Here the four bytes of the `mov rax, [rip+...]`
  displacement are masked because they change whenever the code or the global
  moves.
- **caution** appears when the pattern runs past a `ret`, an `int3` or an
  unconditional `jmp`. The bytes after those belong to whatever the linker put
  next, and a rebuild is free to change them.
- **instructions** lists what the pattern covers.
- **copied** or **not copied** says what happened to the clipboard. A
  signature that is not unique is not copied, because pasting it would find the
  wrong code.

## The four modes

| Mode | Menu entry | Hotkey | Command |
|---|---|---|---|
| Forward | Make signature | Alt+Shift+S | `sigmake addr` |
| Shortest | Make shortest signature | Ctrl+Alt+Shift+S | `sigmake addr, shortest` |
| Selection | Make signature from selection | | `sigmake start, selection, end` |
| Reference | Make reference signature | Alt+Shift+R | `sigxref addr` |

**Forward** adds whole instructions from the selected one until the pattern is
unique and has at least five bytes that are not wildcards. The five-byte floor
is there because a pattern such as `48 89 35` can be unique today and match a
new function tomorrow. The floor never pushes the pattern past the end of a
function; a signature left under it gets a note saying so. Forward stops at 64
bytes, a limit you can change.

**Shortest** makes the forward signature and then cuts it to the shortest
prefix that is still unique, even part-way through an instruction. Use it when
space matters more than robustness. A result under five fixed bytes carries a
note.

**Selection** signs exactly the bytes you selected, with the usual wildcards,
and reports how many times they match. It is the mode for when you already know
which bytes you want, or for checking how common a sequence is. A selection
that ends part-way through an instruction is cut there, and the report says
which instruction was cut.

**Reference** is for code that is not unique and for data. It finds the
instructions that refer to the selected address, by a `call` or `jmp`, a
RIP-relative operand or an absolute address, and signs those instead. See the
next section.

## Reference signatures

Some code has no unique signature: a small function that the compiler repeats,
or a thunk that is a single `jmp`. Data has no code of its own at all. What is
usually unique is a place that uses it. Right-click the address and choose
**Make reference signature** (Alt+Shift+R), or select it in a dump view and use
the same entry there. Signature Lab signs up to three referring sites, best
first:

```
[Signature Lab] pointerlabtutorial.exe+0x2ADB (7FF7C43E2ADB)  reference #1 for pointerlabtutorial.exe+0x2DBF0  9 bytes, 4 wildcards, unique
  x64dbg       48 8B 0D ?? ?? ?? ?? 33 D2
  ...
  wildcards    bytes 3-6 RIP-relative displacement
  resolve      target = match + 7 + *reinterpret_cast<const std::int32_t*>(match + 3)
  instructions
    7FF7C43E2ADB  mov rcx, [00007FF7C440DBF0]
    7FF7C43E2AE2  xor edx, edx
```

The **resolve** line is the part that matters. Your scanner finds the
`mov rcx, [rip+...]`; the resolve rule turns that match back into the address
you asked for. It is written as C++ so you can paste it:

```cpp
const std::uint8_t* match = /* where your scanner found the pattern */;
const std::uint8_t* target = match + 7 + *reinterpret_cast<const std::int32_t*>(match + 3);
```

The rule depends on how the site refers to the target:

| Site | Resolve rule |
|---|---|
| `call` or `jmp` rel32 | `match + end + rel32`, where `end` is the instruction's length |
| RIP-relative operand | `match + end + disp32` |
| Absolute address (32-bit code, `push offset x`, `mov eax, [x]`) | `*(uint32_t*)(match + k)` |
| `mov r64, imm64` | `*(uint64_t*)(match + k)` |

A reference signature always includes the whole referring instruction, so the
bytes the rule reads are inside the pattern. Sites are ranked so that one which
stays inside its function comes first, then one with at least five fixed bytes,
then the shortest, then the one with fewest wildcards.

## What gets wildcarded

Every instruction is decoded with Zydis, so each byte is known to be part of
the opcode, a displacement, an immediate or a branch offset. Each class below
is a checkbox in the dialog and a key in the settings.

| Class | Example | Default | Why |
|---|---|---|---|
| Branch targets (rel32) | `E8 xx xx xx xx` | masked | Changes whenever code between the call and its target changes |
| Short branch targets (rel8) | `74 xx` | kept | Changes only when the function itself changes |
| RIP-relative displacements | `48 8B 05 xx xx xx xx` | masked | Changes whenever the code or the data moves |
| Absolute addresses | `A1 xx xx xx xx`, `[table+eax*4]` | masked | Changes with the image base and every relocation |
| Pointer immediates | `68 xx xx xx xx` (push offset) | masked | An immediate whose value is a readable address is an address |
| Struct and stack offsets | `89 86 xx xx xx xx`, `fs:[18]` | kept | Usually the most stable part of the code; mask them when a struct changes layout between versions |
| Large immediates | `B8 xx xx xx xx` | kept | Constants of 32 bits or more; mask them when a version number or key changes between builds |

Opcodes, ModRM and SIB bytes, and immediates narrower than 32 bits are always
kept. Bytes Zydis cannot decode are kept and reported as undecodable.

## Output forms

| Form | Looks like | Use it in |
|---|---|---|
| x64dbg | `48 8B 05 ?? ?? ?? ?? 4?` | x64dbg's Find Pattern (Ctrl+B), `findallmem`, most C++ scanners |
| IDA | `48 8B 05 ? ? ? ? ?` | IDA's binary search and IDA-style scanners |
| code+mask | `"\x48\x8B\x05\x00\x00\x00\x00"` and `"xxx????"` | Scanners that take a byte string and a mask |
| C++ array | `const unsigned char sig[] = { 0x48, ... };` and a mask | Code that embeds the bytes directly |
| Pointer Lab | `aobscanmodule(INJECT, game.exe, 48 8B 05 ?? ...)` | Pointer Lab's auto-assembler scripts |

One difference catches people out. In x64dbg's own pattern syntax a single `?`
is **half a byte**, so an IDA-form pattern pasted into x64dbg's Find Pattern
matches nothing. Use the x64dbg form inside x64dbg. The IDA form cannot
express half a byte, so a pattern with a nibble wildcard such as `4?` is
widened to a whole-byte `?` there.

## Test a pattern

Signature Lab can count the matches of any pattern, including one you wrote by
hand or copied from a forum post or a book:

- **Plugins > Signature Lab > Test signature from clipboard** tests the text on
  the clipboard.
- The **Test** box at the bottom of the dialog tests what you type.
- The `sigtest` command tests its argument: `sigtest 48 8B 05 ?? ?? ?? ?? 48 8B D9`.

The search covers the module that contains the address selected in the CPU
view. The result goes to the Log tab, and every match is listed in the
References tab, where double-clicking one takes you there.

```
[Signature Lab] 48 8B 05 ?? ?? ?? ?? 48 8B D9
  6 matches in pointerlabtutorial.exe
    pointerlabtutorial.exe+0x134B
    pointerlabtutorial.exe+0x13CB
    pointerlabtutorial.exe+0x167A
    ...
```

The tester reads every form Signature Lab writes, and works out which one it
was given:

- hex with `??`, `?` or nibble wildcards, with or without spaces;
- a code-style `"\x48\x8B..."` string, followed by an `xx??` mask or not;
- a C array of `0x` bytes, followed by an `xx??` mask, a `0b0110` bitmask or
  neither;
- an `aobscan` or `aobscanmodule` line.

A mask has to be exactly as long as the pattern. A mask of the wrong length is
reported as an error instead of being ignored, because a scanner that quietly
compared every byte would report "not found" and give no hint why.

## The dialog

**Signature Lab...** in the right-click menu or the Plugins menu opens a
window with every option in one place. It generates a signature for the
selected instruction as it opens.

- **Address** and **End** take any x64dbg expression: an address, a label,
  `game.exe+29D1F` or a register. End is used by Selection mode only.
- **Mode** and **Max bytes** set how the signature is grown.
- **Wildcard** holds the seven checkboxes from the table above.
- **Copy as** picks the form that **Copy** puts on the clipboard. Changing it
  also changes the form the menu entries and hotkeys copy, once you save.
- **Save as defaults** stores the current options for the menu entries,
  hotkeys and commands. **Reset to defaults** puts back the defaults in this
  guide.

## Commands and scripts

The commands work in the command bar and in x64dbg scripts. Arguments are
separated by commas, as in every x64dbg command, and any x64dbg expression
works where an address is expected.

| Command | What it does | `$result` |
|---|---|---|
| `sigmake addr` | Forward signature at `addr` | Match count: 1 when unique |
| `sigmake addr, shortest` | Shortest signature | Match count |
| `sigmake start, selection, end` | Signs `start` to `end` inclusive | Match count |
| `sigmake addr, reference` | Same as `sigxref addr` | Number of signatures made |
| `sigxref addr` | Reference signatures for `addr` | Number of signatures made |
| `sigtest pattern` | Counts matches of `pattern` | Match count |

A failed command sets `$result` to 0, so a script never reads the previous
command's value by mistake. Arguments are evaluated before that happens, so
this works:

```
find mod.main(), "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 05"
sigmake $result
log "matches: {d:$result}"
```

`sigtest` puts back the commas that x64dbg splits on, so a C array can be
tested as it is written.

## Settings

Settings live in x64dbg's own settings file under `[Signature Lab]`, and the
dialog's **Save as defaults** writes them. Two of them have no control in the
dialog.

| Key | Default | Meaning |
|---|---|---|
| `WildcardBranchRel32` | 1 | Mask rel32 branch targets |
| `WildcardBranchRel8` | 0 | Mask rel8 branch targets |
| `WildcardRipRelative` | 1 | Mask RIP-relative displacements |
| `WildcardAbsoluteAddress` | 1 | Mask absolute addresses |
| `WildcardPointerImmediate` | 1 | Mask immediates that point at readable memory |
| `WildcardStructOffset` | 0 | Mask struct and stack offsets |
| `WildcardLargeImmediate` | 0 | Mask immediates of 32 bits or more |
| `MaxBytes` | 64 | Growth limit, 4 to 1024 |
| `MinFixedBytes` | 5 | Fixed-byte floor for Forward and Reference, 0 to 64 |
| `Format` | x64dbg | Clipboard form: `x64dbg`, `IDA`, `code+mask`, `C++ array` or `Pointer Lab` |
| `LogAllFormats` | 1 | Log every form, not just the clipboard one |
| `LogInstructions` | 1 | Log the instructions a signature covers |

## When it says no

| Message | What to do |
|---|---|
| `not inside a module` | A signature is searched for within one module. Heap memory and JIT code have none; sign the code that writes the address instead. |
| `not unique within 64 bytes` | The code is repeated in the module. Make a reference signature, or raise Max bytes. |
| `only N fixed bytes` | The signature works, but little of it is fixed. Prefer a reference signature if the target has one. |
| `nothing in game.exe refers to ...` | No `call`, `jmp`, RIP-relative operand or absolute address in the module's code points there. The address may be reached through a register or a vtable. |
| `none is unique within 64 bytes` | Every referring site is repeated code. Try one of the functions that calls those sites. |
| `stopped after 32 references` | A heavily used address. The three shown are the best of the first 32 found. |
| `every selected byte is a wildcard` | Select more, or clear some wildcard classes. |
| `caution  runs past the end of the function` | The pattern includes bytes after a `ret`, `int3` or `jmp`. Prefer another site, or select the range by hand. |
