#include "Fixtures.h"

#include "core/Report.h"

#include <catch2/catch_test_macros.hpp>

using namespace siglab;
using test::X86Fixture;

TEST_CASE("forward growth stops at the first instruction that makes it unique", "[builder]") {
    X86Fixture f;
    const auto result = f.builder().forward(X86Fixture::kA, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.unique());
    CHECK(s.address == X86Fixture::kA);
    // The shared prologue matches A and B; the F8 in the fourth instruction is
    // what tells them apart, and the global's address is wildcarded.
    CHECK(format(s.pattern, Format::X64dbg) == "55 8B EC 8B 0D ?? ?? ?? ?? 89 86 F8 00 00 00");
    CHECK(s.instructions.size() == 4);
    CHECK(s.instructions[3].text == "mov [esi+F8], eax");
    CHECK_FALSE(s.crossesFunctionEnd);
    CHECK(s.wildcardSummary() == "bytes 5-8 absolute address");
}

TEST_CASE("shortest cuts the forward signature to the shortest unique prefix", "[builder]") {
    X86Fixture f;
    const auto result = f.builder().shortest(X86Fixture::kA, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.unique());
    CHECK(s.mode == Mode::Shortest);
    CHECK(format(s.pattern, Format::X64dbg) == "55 8B EC 8B 0D ?? ?? ?? ?? 89 86 F8");
}

TEST_CASE("a signature that cannot be made unique in the budget says so", "[builder]") {
    X86Fixture f;
    BuildOptions options;
    options.maxBytes = 8;
    const auto result = f.builder().forward(X86Fixture::kA, options);
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK_FALSE(s.unique());
    CHECK(s.matches == 2);
    REQUIRE_FALSE(result.notes.empty());
    CHECK(result.notes.front().find("not unique within 8 bytes") != std::string::npos);
}

TEST_CASE("masking struct offsets makes A and B indistinguishable", "[builder]") {
    // The two functions differ only in the offset they write, so a policy
    // that wildcards struct offsets has to grow past the ret to tell them
    // apart, and says that it did.
    X86Fixture f;
    BuildOptions options;
    options.policy.structOffset = true;
    const auto result = f.builder().forward(X86Fixture::kA, options);
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.unique());
    CHECK(s.crossesFunctionEnd);
    CHECK(s.pattern.size() > 17);
}

TEST_CASE("selection signs exactly the selected bytes and counts every match", "[builder]") {
    X86Fixture f;
    const auto result = f.builder().selection(X86Fixture::kA, X86Fixture::kA + 2, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(format(s.pattern, Format::X64dbg) == "55 8B EC");
    CHECK(s.matches >= 2);
    CHECK_FALSE(result.notes.empty());
}

TEST_CASE("a selection that ends mid-instruction is cut there and noted", "[builder]") {
    X86Fixture f;
    const auto result = f.builder().selection(X86Fixture::kA, X86Fixture::kA + 4, {});
    REQUIRE(result.ok());
    CHECK(format(result.signatures.front().pattern, Format::X64dbg) == "55 8B EC 8B 0D");
    bool noted = false;
    for (const auto& note : result.notes) {
        noted = noted || note.find("part-way through") != std::string::npos;
    }
    CHECK(noted);
}

TEST_CASE("an address outside any module is refused with a reason", "[builder]") {
    X86Fixture f;
    const auto result = build(f.memory, 0x10000000, Mode::Forward, {});
    CHECK_FALSE(result.ok());
    CHECK(result.error.find("not inside a module") != std::string::npos);
}

TEST_CASE("build() captures the module and dispatches on mode", "[builder]") {
    X86Fixture f;
    const auto forward = build(f.memory, X86Fixture::kA, Mode::Forward, {});
    REQUIRE(forward.ok());
    CHECK(forward.signatures.front().moduleName == "game.exe");
    CHECK(forward.signatures.front().moduleBase == X86Fixture::kBase);

    const auto selection = build(f.memory, X86Fixture::kA, Mode::Selection, {}, X86Fixture::kA + 2);
    REQUIRE(selection.ok());
    CHECK(selection.signatures.front().pattern.size() == 3);
}

TEST_CASE("mode names round-trip", "[builder]") {
    for (Mode mode : {Mode::Forward, Mode::Shortest, Mode::Selection, Mode::Reference}) {
        CHECK(modeFromName(modeName(mode)) == mode);
    }
    CHECK(modeFromName("xref") == Mode::Reference);
    CHECK(modeFromName("") == Mode::Forward);
    CHECK_FALSE(modeFromName("backwards"));
}

TEST_CASE("a signature that runs past a tail jump is flagged", "[builder]") {
    // call f; jmp g; push ebp. The shape of an MSVC entry point: the push
    // belongs to whatever function the linker placed next.
    test::FakeMemory memory(Bitness::X86, 0x400000, 0x2000);
    memory.addSection(0x401000, 0x1000, ".text", true);
    constexpr std::uint64_t kEntry = 0x401100;
    memory.write(kEntry, {0xE8});
    memory.write32(kEntry + 1, test::rel32(kEntry, 5, 0x401500));
    memory.write(kEntry + 5, {0xE9});
    memory.write32(kEntry + 6, test::rel32(kEntry + 5, 5, 0x401600));
    memory.write(kEntry + 10, {0x55, 0x8B, 0xEC});
    // Make "E8 ?? ?? ?? ?? E9" appear twice so growth has to reach the push.
    memory.write(0x401200, {0xE8, 0x11, 0x11, 0x11, 0x11, 0xE9, 0x22, 0x22, 0x22, 0x22, 0xC3});

    const auto result = build(memory, kEntry, Mode::Forward, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.unique());
    CHECK(s.crossesFunctionEnd);
    CHECK(format(s.pattern, Format::X64dbg) == "E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 55");
    CHECK(describe(result, {}).find("  caution      runs past the end of the function") != std::string::npos);
}

TEST_CASE("reference signatures that stay inside their function rank first", "[references]") {
    // Two calls to the same target. The first site is followed by a tail
    // jump into padding; the second by ordinary code. The second must rank
    // first even though the first is shorter.
    test::FakeMemory memory(Bitness::X86, 0x400000, 0x2000);
    memory.addSection(0x401000, 0x1000, ".text", true);
    constexpr std::uint64_t kTarget = 0x401800;
    constexpr std::uint64_t kTail = 0x401100;
    constexpr std::uint64_t kInline = 0x401300;
    memory.write(kTail, {0xE8});
    memory.write32(kTail + 1, test::rel32(kTail, 5, kTarget));
    memory.write(kTail + 5, {0xEB, 0x7F, 0xCC, 0xCC});
    memory.write(kInline, {0xE8});
    memory.write32(kInline + 1, test::rel32(kInline, 5, kTarget));
    memory.write(kInline + 5, {0x85, 0xC0, 0x74, 0x09, 0x8B, 0x45, 0x08, 0x89, 0x46, 0x10});
    // Decoys: the same code calling somewhere else. The tail site now has to
    // grow into the int3 padding to be unique (8 bytes), and the inline site
    // has to grow to its third instruction (12 bytes). Shorter alone would
    // pick the tail site.
    memory.write(0x401500, {0xE8, 0x11, 0x11, 0x11, 0x11, 0xEB, 0x7F, 0x90, 0x90});
    memory.write(0x401600, {0xE8, 0x22, 0x22, 0x22, 0x22, 0x85, 0xC0, 0x74, 0x09, 0x90, 0x90});

    const auto result = build(memory, kTarget, Mode::Reference, {});
    REQUIRE(result.ok());
    REQUIRE(result.signatures.size() == 2);
    CHECK(result.signatures[0].address == kInline);
    CHECK_FALSE(result.signatures[0].crossesFunctionEnd);
    CHECK(result.signatures[1].address == kTail);
    CHECK(result.signatures[1].crossesFunctionEnd);
}

TEST_CASE("forward growth continues past uniqueness to five fixed bytes", "[builder]") {
    // mov [rip+x], rsi is unique on its own here, but "48 89 35" is three
    // fixed bytes: any new store of rsi to a global would match it.
    test::FakeMemory memory(Bitness::X64, 0x140000000, 0x3000);
    memory.addSection(0x140001000, 0x1000, ".text", true);
    constexpr std::uint64_t kSite = 0x140001100;
    memory.write(kSite, {0x48, 0x89, 0x35});
    memory.write32(kSite + 3, test::rel32(kSite, 7, 0x140002000));
    memory.write(kSite + 7, {0x48, 0x8B, 0xC8, 0x48, 0x83, 0xC4, 0x20});
    // A decoy so that "48 89" alone is not unique: mov [rcx], rdx; ret.
    memory.write(0x140001500, {0x48, 0x89, 0x11, 0xC3});

    const auto result = build(memory, kSite, Mode::Forward, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.unique());
    CHECK(format(s.pattern, Format::X64dbg) == "48 89 35 ?? ?? ?? ?? 48 8B C8");
    CHECK(result.notes.empty());

    // Shortest still cuts to the minimum, and says what that costs.
    const auto shortest = build(memory, kSite, Mode::Shortest, {});
    REQUIRE(shortest.ok());
    CHECK(format(shortest.signatures.front().pattern, Format::X64dbg) == "48 89 35");
    REQUIRE(shortest.notes.size() == 1);
    CHECK(shortest.notes.front().rfind("only 3 fixed bytes", 0) == 0);
}

TEST_CASE("the fixed-byte floor never pushes growth past a function end", "[builder]") {
    test::FakeMemory memory(Bitness::X64, 0x140000000, 0x3000);
    memory.addSection(0x140001000, 0x1000, ".text", true);
    constexpr std::uint64_t kSite = 0x140001100;
    memory.write(kSite, {0x48, 0x89, 0x35});
    memory.write32(kSite + 3, test::rel32(kSite, 7, 0x140002000));
    memory.write(kSite + 7, {0xC3, 0xCC, 0xCC, 0xCC});

    const auto result = build(memory, kSite, Mode::Forward, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.unique());
    CHECK_FALSE(s.crossesFunctionEnd);
    CHECK(format(s.pattern, Format::X64dbg) == "48 89 35 ?? ?? ?? ?? C3");
    REQUIRE(result.notes.size() == 1);
    CHECK(result.notes.front().rfind("only 4 fixed bytes", 0) == 0);
}
