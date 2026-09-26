#include "Fixtures.h"

#include <catch2/catch_test_macros.hpp>

#include <tuple>

#include <algorithm>

using namespace siglab;
using test::X64Fixture;
using test::X86Fixture;

namespace {

const Builder::Reference* at(const std::vector<Builder::Reference>& refs, std::uint64_t site) {
    const auto it = std::find_if(refs.begin(), refs.end(), [&](const Builder::Reference& r) { return r.site == site; });
    return it == refs.end() ? nullptr : &*it;
}

} // namespace

TEST_CASE("x86: a function is referenced by its call and by a pushed pointer", "[references]") {
    X86Fixture f;
    const auto refs = f.builder().findReferences(X86Fixture::kA, 32);
    REQUIRE(refs.size() == 2);

    const auto* call = at(refs, X86Fixture::kCaller);
    REQUIRE(call);
    CHECK(call->kind == ReferenceKind::Relative);
    CHECK(call->fieldOffset == 1);
    CHECK(call->length == 5);

    const auto* push = at(refs, X86Fixture::kCaller + 12);
    REQUIRE(push);
    CHECK(push->kind == ReferenceKind::Absolute32);
    CHECK(push->fieldOffset == 1);
}

TEST_CASE("x86: a global is referenced by the absolute operand in both functions", "[references]") {
    X86Fixture f;
    const auto refs = f.builder().findReferences(X86Fixture::kGlobal, 32);
    REQUIRE(refs.size() == 2);
    for (const auto& r : refs) {
        CHECK(r.kind == ReferenceKind::Absolute32);
        CHECK(r.fieldOffset == 2);
        CHECK(r.length == 6);
    }
    CHECK(at(refs, X86Fixture::kA + 3));
    CHECK(at(refs, X86Fixture::kB + 3));
}

TEST_CASE("x86: every reference signature is unique and resolves back to the target", "[references]") {
    X86Fixture f;
    const Builder builder = f.builder();
    for (std::uint64_t target : {X86Fixture::kA, X86Fixture::kGlobal}) {
        const auto result = builder.references(target, {});
        REQUIRE(result.ok());
        for (const Signature& s : result.signatures) {
            INFO(format(s.pattern, Format::X64dbg));
            CHECK(s.unique());
            CHECK(s.mode == Mode::Reference);
            CHECK(s.target == target);
            const auto matches = builder.image().find(s.pattern, 2);
            REQUIRE(matches.size() == 1);
            CHECK(test::resolve(f.memory, s, matches.front()) == target);
        }
    }
}

TEST_CASE("x64: RIP-relative references are found, including one with a trailing immediate", "[references]") {
    X64Fixture f;
    const auto refs = f.builder().findReferences(X64Fixture::kGlobal, 32);
    REQUIRE(refs.size() == 3);

    const auto* mov = at(refs, X64Fixture::kFunc);
    REQUIRE(mov);
    CHECK(mov->kind == ReferenceKind::RipRelative);
    CHECK(mov->fieldOffset == 3);
    CHECK(mov->length == 7);

    const auto* cmp = at(refs, X64Fixture::kCmp);
    REQUIRE(cmp);
    CHECK(cmp->fieldOffset == 2);
    CHECK(cmp->length == 7);

    // 8D 0D disp32 is also a valid instruction (lea ecx, [rip+x]) with the
    // same field and target. The finder must report the REX-prefixed one the
    // compiler emitted, starting at the 48.
    const auto* lea = at(refs, X64Fixture::kLea);
    REQUIRE(lea);
    CHECK(lea->text == "lea rcx, [0000000140003000]");
    CHECK_FALSE(at(refs, X64Fixture::kLea + 1));
}

TEST_CASE("x64: a call is a reference to the function it calls", "[references]") {
    X64Fixture f;
    const auto refs = f.builder().findReferences(X64Fixture::kFunc, 32);
    REQUIRE(refs.size() == 1);
    CHECK(refs.front().site == X64Fixture::kCall);
    CHECK(refs.front().kind == ReferenceKind::Relative);
}

TEST_CASE("x64: reference signatures resolve back to the global", "[references]") {
    X64Fixture f;
    const Builder builder = f.builder();
    const auto result = builder.references(X64Fixture::kGlobal, {});
    REQUIRE(result.ok());
    REQUIRE(result.signatures.size() == 3);
    // Ranked by: stays inside its function, has enough fixed bytes, length.
    const auto key = [](const Signature& s) {
        return std::tuple(s.crossesFunctionEnd, s.pattern.fixedCount() < BuildOptions{}.minFixedBytes, s.pattern.size());
    };
    for (std::size_t i = 1; i < result.signatures.size(); ++i) {
        CHECK(key(result.signatures[i - 1]) <= key(result.signatures[i]));
    }
    for (const Signature& s : result.signatures) {
        const auto matches = builder.image().find(s.pattern, 2);
        REQUIRE(matches.size() == 1);
        CHECK(test::resolve(f.memory, s, matches.front()) == X64Fixture::kGlobal);
    }
}

TEST_CASE("reference results are capped and the resolution is printable", "[references]") {
    X64Fixture f;
    BuildOptions options;
    options.maxReferenceResults = 1;
    const auto result = f.builder().references(X64Fixture::kGlobal, options);
    REQUIRE(result.signatures.size() == 1);
    const Signature& s = result.signatures.front();
    CHECK(s.resolution() == "match + 7 + *reinterpret_cast<const std::int32_t*>(match + " + std::to_string(s.fieldOffset) + ")");
}

TEST_CASE("an address nothing refers to is an error, not an empty success", "[references]") {
    X64Fixture f;
    const auto result = f.builder().references(X64Fixture::kGlobal + 0x800, {});
    CHECK_FALSE(result.ok());
    CHECK(result.error.find("nothing in game64.exe refers to") != std::string::npos);
}

TEST_CASE("a reference signature keeps the whole referring instruction", "[references]") {
    // jmp [target]: a tail jump through an import-style slot. "FF 25" is
    // unique and the jmp ends the function, so growth stops there; the
    // trimmed pattern would stop before the field the resolve rule reads.
    test::FakeMemory memory(Bitness::X86, 0x400000, 0x2000);
    memory.addSection(0x401000, 0x1000, ".text", true);
    constexpr std::uint64_t kSlot = 0x401800;
    constexpr std::uint64_t kSite = 0x401100;
    memory.write(kSite, {0xFF, 0x25});
    memory.write32(kSite + 2, static_cast<std::uint32_t>(kSlot));
    memory.write(kSite + 6, {0xCC, 0xCC});

    const auto result = build(memory, kSlot, Mode::Reference, {});
    REQUIRE(result.ok());
    const Signature& s = result.signatures.front();
    CHECK(s.address == kSite);
    CHECK(s.referenceKind == ReferenceKind::Absolute32);
    REQUIRE(s.pattern.size() >= 6);
    CHECK(format(s.pattern.prefix(6), Format::X64dbg) == "FF 25 ?? ?? ?? ??");
}
