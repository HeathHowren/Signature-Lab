#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace siglab {

// Why a byte is, or is not, a wildcard. The mask says whether a byte is
// compared; the reason says what the byte encodes, so the UI can explain a
// signature instead of just printing it. Kept separate from the mask because
// the policy that turns reasons into wildcards is a user setting, and changing
// a setting should not require decoding the instruction again.
enum class ByteReason : std::uint8_t {
    Opcode,           // prefix, opcode, ModRM, SIB: the shape of the instruction, always kept
    Immediate,        // an 8- or 16-bit immediate, always kept
    LargeImmediate,   // a 32- or 64-bit immediate that does not point at readable memory
    StructOffset,     // a displacement off a base register: [esi+F8], [rsp+28]
    BranchRel8,       // the target of a short jump
    BranchRel32,      // the target of a near call or jump
    RipRelative,      // a displacement off RIP (x64 only)
    AbsoluteAddress,  // a displacement with no base register: [00501234], moffs
    PointerImmediate, // an immediate whose value points at readable memory
    Undecodable,      // Zydis could not decode this byte; kept as data
};

[[nodiscard]] const char* reasonName(ByteReason reason);

// The output forms. The x64dbg and IDA forms differ only in how a wildcard is
// spelled: x64dbg's Find Pattern treats a lone '?' as one nibble, so a whole
// wildcard byte has to be '??' there, whereas IDA and most cheat forums write
// a single '?'. Getting this wrong is the most common reason a signature
// copied from one tool "does not match" in another.
enum class Format : std::uint8_t {
    X64dbg,     // 48 8B 05 ?? ?? ?? ??
    Ida,        // 48 8B 05 ? ? ? ?
    CodeMask,   // "\x48\x8B\x05\x00\x00\x00\x00" and "xxx????"
    CppArray,   // const unsigned char sig[] = { ... }; const char mask[] = "...";
    PointerLab, // aobscanmodule(INJECT, module.exe, 48 8B 05 ?? ?? ?? ??)
};

[[nodiscard]] const char* formatName(Format format);
[[nodiscard]] std::optional<Format> formatFromName(std::string_view name);
inline constexpr Format kAllFormats[] = {Format::X64dbg, Format::Ida, Format::CodeMask, Format::CppArray, Format::PointerLab};

struct Pattern {
    std::vector<std::uint8_t> bytes;
    // 0xFF: compare the whole byte. 0x00: wildcard. 0xF0 / 0x0F: compare one
    // nibble, which is how x64dbg spells "4?" and "?4". Any other value is a
    // bit mask and is honoured by the matcher, but never produced.
    std::vector<std::uint8_t> mask;
    // Parallel to bytes. Empty when the pattern was parsed from text rather
    // than built from instructions.
    std::vector<ByteReason> reasons;

    [[nodiscard]] std::size_t size() const { return bytes.size(); }
    [[nodiscard]] bool empty() const { return bytes.empty(); }
    [[nodiscard]] bool isWildcard(std::size_t i) const { return mask[i] == 0; }
    [[nodiscard]] bool hasReasons() const { return reasons.size() == bytes.size(); }
    [[nodiscard]] std::size_t wildcardCount() const;
    [[nodiscard]] std::size_t fixedCount() const { return size() - wildcardCount(); }
    [[nodiscard]] bool hasNibbleMask() const;
    [[nodiscard]] Pattern prefix(std::size_t count) const;

    void append(std::uint8_t byte, std::uint8_t maskByte, ByteReason reason);
    void append(const Pattern& other);
    void trimTrailingWildcards();
    void clear();
};

// Renders a pattern in one form. `moduleName` and `symbol` are used by the
// Pointer Lab form only; a missing module name renders as "module.exe" so the
// line is still syntactically complete and obviously needs editing.
[[nodiscard]] std::string format(const Pattern& pattern, Format form, std::string_view moduleName = {},
                                 std::string_view symbol = "INJECT");

// Parses any of the forms format() produces, plus the common variations: a
// lone '?' or '??' per wildcard byte, '4?' nibble wildcards, no separators at
// all ("488B??24"), a code-style string with or without its mask on the next
// line, a C array with an "xxx????" mask or an A200K-style "0b1110000" bitmask.
// Returns nothing for text that is not a pattern (an odd hex digit, a stray
// character) rather than guessing.
[[nodiscard]] std::optional<Pattern> parse(std::string_view text);

// Formats bytes as "48 8B 05".
[[nodiscard]] std::string hexBytes(const std::uint8_t* data, std::size_t size);

} // namespace siglab
