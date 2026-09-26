<p align="center">
  <img src="docs/logo.svg" width="96" alt="Signature Lab logo">
</p>

# Signature Lab

A byte-signature maker for x64dbg and x32dbg.

[![CI](https://github.com/HeathHowren/Signature-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/HeathHowren/Signature-Lab/actions/workflows/ci.yml)

Select an instruction, press **Alt+Shift+S**, and Signature Lab writes a
pattern that finds the same code again after the program is rebuilt or loaded
at a different address. It decodes every instruction, so it knows which bytes
are addresses that will move and which are code that will not. It checks the
result against the whole module, and it tells you why each byte was masked.

Signature Lab is written by Heath Howren (Cyborg Elf) of
[Game Reversal Club](https://gamereversal.club) as a companion tool to
*The Game Hacker's Handbook*, whose chapter on signature scanning it automates.

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

*Real output from x64dbg, signing a function in the Pointer Lab tutorial.*

## What it does

- **Wildcards by operand, with a reason for each.** Every instruction is
  decoded with [Zydis](https://github.com/zyantific/zydis). Call and jump
  targets, RIP-relative displacements, absolute addresses and immediates that
  point into the module are masked. Opcodes and struct offsets are kept. The
  report names every masked byte and its class, and each class is a toggle.
- **Uniqueness across the whole module.** The module is read page by page and
  every match is counted, so "unique" means unique, not unique in the next few
  kilobytes.
- **Signatures that survive a rebuild.** Growth continues past uniqueness until
  at least five bytes are fixed. A signature that runs past a `ret`, an `int3`
  or a tail `jmp` into whatever the linker put next is flagged.
- **Reference signatures.** When the code at an address is not unique, or the
  address is data, Signature Lab signs the instructions that refer to it and
  prints the C++ expression that turns a match back into the address.
- **Every common form.** x64dbg, IDA, code-style bytes and mask, a C++ array,
  and a Pointer Lab `aobscanmodule(...)` line, all logged at once.
- **A tester for any pattern.** Paste a pattern from anywhere, in any of those
  forms, and see every match in the References tab. A mask whose length does
  not match its pattern is reported, not silently ignored.
- **32-bit and 64-bit.** One zip holds both plugins.

## Download

Get the latest zip from
[Releases](https://github.com/HeathHowren/Signature-Lab/releases) and extract
it into your x64dbg folder, the one that contains `release`:

```
release\x64\plugins\SignatureLab.dp64    for x64dbg
release\x32\plugins\SignatureLab.dp32    for x32dbg
SignatureLab\                            licence, notices and the usage guide
```

Restart x64dbg. The log shows
`[Signature Lab] 1.0.0 loaded.` when it is ready. Signature Lab is built
against, and tested with, the x64dbg snapshot of 2026.05.27, and needs nothing
else installed.

The binaries are unsigned. Antivirus software may flag a debugger plugin that
reads process memory; build from source if you would rather not take a binary
on trust.

## Quick start

In the CPU view, right-click an instruction and open the **Signature Lab**
submenu:

| Entry | Hotkey | What it makes |
|---|---|---|
| Make signature | Alt+Shift+S | Grows from the instruction until unique |
| Make shortest signature | Ctrl+Alt+Shift+S | The shortest unique prefix |
| Make signature from selection | | Exactly the selected bytes, with their match count |
| Make reference signature | Alt+Shift+R | Signatures at the code that refers to the address |
| Signature Lab... | | A dialog with every option |

The dump view has **Make reference signature** too, for data. The Plugins menu
has the dialog, **Test signature from clipboard**, and **About**.

The same work is available as commands for the command bar and scripts:

```
sigmake addr[, forward|shortest|selection|reference[, end]]
sigxref addr
sigtest pattern
```

Each sets `$result`: the match count, or the number of reference signatures.

One thing to know before pasting patterns around: in x64dbg's own pattern
syntax a single `?` is half a byte, so an IDA-style pattern such as
`48 8B 05 ? ? ? ?` finds nothing in x64dbg's Find Pattern. Use the x64dbg form,
with `??`, inside x64dbg. Signature Lab's own tester reads both.

The [usage guide](docs/usage.md) covers every mode, wildcard class, output
form, command and setting, and what to do when a signature cannot be made.

## What will not change within a major version

*The Game Hacker's Handbook* quotes Signature Lab by name, so these are pinned
for the whole 1.x series:

- the menu entry labels and their hotkeys;
- the command names `sigmake`, `sigxref` and `sigtest`, their arguments, and
  what they put in `$result`;
- the settings keys under `[Signature Lab]`;
- the text of the five output forms.

A change to any of them is a 2.0, recorded in the [changelog](CHANGELOG.md).

## Intended use

Signature Lab is for studying software **you own or are authorised to
analyse**: your own programs, single-player games, CTF binaries, and the
Handbook's lab targets.

Using a debugger against online or competitive games will very likely trip
anti-cheat software and get the account banned. Modifying software you do not
have permission to modify may be illegal where you live. That decision is
yours; this tool does not make it for you.

## Building from source

**Requirements:** Visual Studio 2022 with the C++ workload (MSVC v143) and
CMake 3.28 or newer. The CMake that ships with Visual Studio is recent enough.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

One configure builds both plugins: the `.dp64` directly, and the `.dp32`
through a nested 32-bit build of the same source tree. The first configure
downloads Zydis, the x64dbg plugin SDK and Catch2, each pinned by commit, tag
or SHA-256. The tests run the core against hand-encoded x86 and x64 code, in
both a 64-bit and a 32-bit test binary, with no debugger needed.

To produce the release zip:

```powershell
cpack --config build/CPackConfig.cmake -C Release -B build/package
```

The [design notes](docs/design.md) describe the architecture and how the
wildcarder, uniqueness check and reference finder work.

## License

MIT; see [LICENSE](LICENSE). Signature Lab statically links Zydis and Zycore,
both MIT. x64dbg's licence explicitly lets plugins choose their own. Details
are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
