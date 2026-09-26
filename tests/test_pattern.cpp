#include "core/Pattern.h"

#include <catch2/catch_test_macros.hpp>

using namespace siglab;

namespace {

// The worked example from the Handbook's chapter 14: mov [esi+F8], eax
// followed by mov ecx, [abs32] and the first byte of the next instruction.
Pattern bookExample() {
    auto p = parse("89 86 F8 00 00 00 8B 0D ? ? ? ? 89");
    REQUIRE(p);
    return *p;
}

} // namespace

TEST_CASE("the book's IDA-style example parses to 13 bytes with 4 wildcards", "[pattern]") {
    const Pattern p = bookExample();
    REQUIRE(p.size() == 13);
    CHECK(p.wildcardCount() == 4);
    CHECK(p.isWildcard(8));
    CHECK(p.isWildcard(11));
    CHECK_FALSE(p.isWildcard(12));
    CHECK_FALSE(p.hasReasons());
}

TEST_CASE("each form spells a wildcard the way its consumer expects", "[pattern]") {
    const Pattern p = bookExample();
    CHECK(format(p, Format::X64dbg) == "89 86 F8 00 00 00 8B 0D ?? ?? ?? ?? 89");
    CHECK(format(p, Format::Ida) == "89 86 F8 00 00 00 8B 0D ? ? ? ? 89");
    CHECK(format(p, Format::CodeMask) == "\"\\x89\\x86\\xF8\\x00\\x00\\x00\\x8B\\x0D\\x00\\x00\\x00\\x00\\x89\"\n\"xxxxxxxx????x\"");
    CHECK(format(p, Format::CppArray) ==
          "const unsigned char sig[] = { 0x89, 0x86, 0xF8, 0x00, 0x00, 0x00, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x89 };\n"
          "const char mask[] = \"xxxxxxxx????x\";");
    CHECK(format(p, Format::PointerLab, "ac_client.exe") ==
          "aobscanmodule(INJECT, ac_client.exe, 89 86 F8 00 00 00 8B 0D ?? ?? ?? ?? 89)");
    CHECK(format(p, Format::PointerLab) == "aobscanmodule(INJECT, module.exe, 89 86 F8 00 00 00 8B 0D ?? ?? ?? ?? 89)");
}

TEST_CASE("every form parses back to the pattern it was made from", "[pattern]") {
    const Pattern p = bookExample();
    for (Format form : kAllFormats) {
        INFO(formatName(form));
        const auto back = parse(format(p, form, "ac_client.exe"));
        REQUIRE(back);
        CHECK(back->mask == p.mask);
        for (std::size_t i = 0; i < p.size(); ++i) {
            if (!p.isWildcard(i)) {
                CHECK(back->bytes[i] == p.bytes[i]);
            }
        }
    }
}

TEST_CASE("x64dbg-style text with no separators parses byte by byte", "[pattern]") {
    const auto p = parse("488B??24");
    REQUIRE(p);
    REQUIRE(p->size() == 4);
    CHECK(p->mask == std::vector<std::uint8_t>{0xFF, 0xFF, 0x00, 0xFF});
    CHECK(p->bytes[3] == 0x24);
}

TEST_CASE("nibble wildcards survive in the x64dbg form and widen in the IDA form", "[pattern]") {
    const auto p = parse("4? ?B C3");
    REQUIRE(p);
    CHECK(p->mask == std::vector<std::uint8_t>{0xF0, 0x0F, 0xFF});
    CHECK(p->hasNibbleMask());
    CHECK(format(*p, Format::X64dbg) == "4? ?B C3");
    CHECK(format(*p, Format::Ida) == "? ? C3");
}

TEST_CASE("text that is not a pattern is refused rather than guessed at", "[pattern]") {
    CHECK_FALSE(parse(""));
    CHECK_FALSE(parse("   "));
    CHECK_FALSE(parse("48 8G"));
    CHECK_FALSE(parse("4"));
    CHECK_FALSE(parse("48 8B 5"));
    CHECK_FALSE(parse("{ 0x123 }"));
}

TEST_CASE("a code-style string takes its mask from the next line", "[pattern]") {
    const auto p = parse("\"\\xE8\\x00\\x00\\x00\\x00\\x85\\xC0\"  \"x????xx\"");
    REQUIRE(p);
    REQUIRE(p->size() == 7);
    CHECK(p->wildcardCount() == 4);
    CHECK(p->bytes[5] == 0x85);
}

TEST_CASE("a code-style string without a mask compares every byte", "[pattern]") {
    const auto p = parse("\\x48\\x8B\\x05");
    REQUIRE(p);
    CHECK(p->wildcardCount() == 0);
}

TEST_CASE("a mask whose length does not fit the bytes is an error", "[pattern]") {
    // The mask chapter 14 printed under its 13-byte example: 15 characters
    // with two stray spaces. Comparing every byte instead would make the
    // scanner report "not found" and leave the reader to guess why.
    const char* text = "\"\\x89\\x86\\xF8\\x00\\x00\\x00\\x8B\\x0D\\x00\\x00\\x00\\x00\\x89\"\n\"xxxxxx  xx????x\"";
    CHECK_FALSE(parse(text));
    CHECK(parse("\"\\x89\\x86\\xF8\\x00\\x00\\x00\\x8B\\x0D\\x00\\x00\\x00\\x00\\x89\"\n\"xxxxxxxx????x\""));
}

TEST_CASE("a C array takes an xxx mask or a bitmask", "[pattern]") {
    const auto withMask = parse("const unsigned char sig[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 }; const char mask[] = \"x????\";");
    REQUIRE(withMask);
    CHECK(withMask->mask == std::vector<std::uint8_t>{0xFF, 0, 0, 0, 0});

    const auto withBits = parse("{ 0xE8, 0x00, 0x00, 0x00, 0x00 } 0b10000");
    REQUIRE(withBits);
    CHECK(withBits->mask == std::vector<std::uint8_t>{0xFF, 0, 0, 0, 0});
}

TEST_CASE("a Pointer Lab line yields the pattern inside it", "[pattern]") {
    const auto p = parse("aobscanmodule(INJECT, ac_client.exe, 29 8E F8 00 00 00)");
    REQUIRE(p);
    CHECK(format(*p, Format::X64dbg) == "29 8E F8 00 00 00");
}

TEST_CASE("prefix and trim keep bytes, masks and reasons in step", "[pattern]") {
    Pattern p;
    p.append(0xE8, 0xFF, ByteReason::Opcode);
    for (int i = 0; i < 4; ++i) {
        p.append(0x11, 0x00, ByteReason::BranchRel32);
    }
    Pattern head = p.prefix(3);
    CHECK(head.size() == 3);
    CHECK(head.hasReasons());
    p.trimTrailingWildcards();
    CHECK(p.size() == 1);
    CHECK(p.hasReasons());
}

TEST_CASE("format names round-trip and accept the obvious aliases", "[pattern]") {
    for (Format form : kAllFormats) {
        CHECK(formatFromName(formatName(form)) == form);
    }
    CHECK(formatFromName("x32dbg") == Format::X64dbg);
    CHECK(formatFromName("aob") == Format::PointerLab);
    CHECK_FALSE(formatFromName("ghidra"));
}
