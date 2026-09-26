# Changelog

All notable changes to Signature Lab are recorded here. This project follows
[Semantic Versioning](https://semver.org/). Menu labels, hotkeys, command names
and settings keys are pinned for the whole 1.x series, because *The Game
Hacker's Handbook* quotes them; a change to any of them is a 2.0.

## [1.0.0] - 2026-09-25

The first release.

### Added

- **Four ways to make a signature.** Forward grows whole instructions until the
  pattern is unique and has at least five fixed bytes. Shortest cuts that to
  the shortest unique prefix. Selection signs exactly the selected bytes.
  Reference signs the code that refers to an address, and prints the C++
  expression that turns a match back into that address.
- **Operand-aware wildcards.** Every instruction is decoded with Zydis, and
  each masked byte is reported with its reason: rel32 or rel8 branch target,
  RIP-relative displacement, absolute address, pointer immediate, struct or
  stack offset, or large immediate. Each class is a toggle.
- **A whole-module uniqueness check.** The module is read page by page, pages
  that cannot be read are excluded, and matches are counted across all of it.
- **Function-end warnings.** A signature that runs past a `ret`, an `int3` or
  an unconditional `jmp` is flagged, and reference results that stay inside
  their function are ranked first.
- **Five output forms:** x64dbg (`??`), IDA (`?`), code-style bytes and mask,
  a C++ array with mask, and a Pointer Lab `aobscanmodule(...)` line. The log
  shows all five; the clipboard gets the one you choose.
- **A pattern tester** that reads any of those forms, lists every match in the
  References tab, and refuses a mask whose length does not match its pattern.
- **Menus and hotkeys** in the CPU view (Alt+Shift+S, Ctrl+Alt+Shift+S,
  Alt+Shift+R) and the dump view, a Plugins menu entry, and a dialog with
  every option.
- **Script commands** `sigmake`, `sigxref` and `sigtest`, each of which sets
  `$result`.
- 64-bit (`.dp64`) and 32-bit (`.dp32`) builds in one zip, with the C runtime
  linked statically.
