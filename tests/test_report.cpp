#include "Fixtures.h"

#include "core/Report.h"

#include <catch2/catch_test_macros.hpp>

using namespace siglab;
using test::X64Fixture;
using test::X86Fixture;

namespace {

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("module offsets read like x64dbg's", "[report]") {
    CHECK(moduleOffset("game.exe", 0x400000, 0x401000) == "game.exe+0x1000");
    CHECK(moduleOffset("", 0x400000, 0x401000) == "401000");
    CHECK(moduleOffset("game.exe", 0x400000, 0x300000) == "300000");
}

TEST_CASE("the report leads with where, how long and whether it is unique", "[report]") {
    X86Fixture f;
    const auto result = f.builder().forward(X86Fixture::kA, {});
    const std::string text = describe(result, {});
    CHECK(text.rfind("game.exe+0x1000 (401000)  forward  15 bytes, 4 wildcards, unique\n", 0) == 0);
    CHECK(contains(text, "  x64dbg       55 8B EC 8B 0D ?? ?? ?? ?? 89 86 F8 00 00 00\n"));
    CHECK(contains(text, "  IDA          55 8B EC 8B 0D ? ? ? ? 89 86 F8 00 00 00\n"));
    CHECK(contains(text, "  Pointer Lab  aobscanmodule(INJECT, game.exe, 55 8B EC 8B 0D ?? ?? ?? ?? 89 86 F8 00 00 00)\n"));
    CHECK(contains(text, "  wildcards    bytes 5-8 absolute address\n"));
    CHECK(contains(text, "    401009  mov [esi+F8], eax\n"));
}

TEST_CASE("two-line forms hang under their label", "[report]") {
    X86Fixture f;
    const auto result = f.builder().forward(X86Fixture::kA, {});
    const std::string text = describe(result, {});
    CHECK(contains(text, "  code+mask    \"\\x55\\x8B\\xEC\\x8B\\x0D\\x00\\x00\\x00\\x00\\x89\\x86\\xF8\\x00\\x00\\x00\"\n"
                         "               \"xxxxx????xxxxxx\"\n"));
}

TEST_CASE("only the primary form when asked", "[report]") {
    X86Fixture f;
    const auto result = f.builder().forward(X86Fixture::kA, {});
    ReportOptions options;
    options.primary = Format::Ida;
    options.allFormats = false;
    options.instructions = false;
    const std::string text = describe(result, options);
    CHECK(contains(text, "  IDA          55 8B EC"));
    CHECK_FALSE(contains(text, "x64dbg "));
    CHECK_FALSE(contains(text, "instructions"));
}

TEST_CASE("reference signatures carry their resolution rule", "[report]") {
    X64Fixture f;
    const auto result = f.builder().references(X64Fixture::kFunc, {});
    REQUIRE(result.ok());
    const std::string text = describe(result, {});
    CHECK(contains(text, "reference #1 for game64.exe+0x1000"));
    CHECK(contains(text, "  resolve      target = match + 5 + *reinterpret_cast<const std::int32_t*>(match + 1)\n"));
}

TEST_CASE("errors and notes are reported", "[report]") {
    BuildResult result;
    result.error = "the address 0x10 is not readable";
    result.notes.push_back("something to know");
    const std::string text = describe(result, {});
    CHECK(text.rfind("the address 0x10 is not readable\n", 0) == 0);
    CHECK(contains(text, "  note: something to know\n"));
}

TEST_CASE("the clipboard gets one form of one signature", "[report]") {
    X86Fixture f;
    const auto result = f.builder().forward(X86Fixture::kA, {});
    const Signature& s = result.signatures.front();
    CHECK(clipboardText(s, Format::X64dbg) == "55 8B EC 8B 0D ?? ?? ?? ?? 89 86 F8 00 00 00");
    CHECK(clipboardText(s, Format::PointerLab) == "aobscanmodule(INJECT, game.exe, 55 8B EC 8B 0D ?? ?? ?? ?? 89 86 F8 00 00 00)");
}
