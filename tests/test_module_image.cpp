#include "FakeMemory.h"

#include "core/ModuleImage.h"

#include <catch2/catch_test_macros.hpp>

using namespace siglab;
using test::FakeMemory;

namespace {

ModuleImage image(std::vector<std::uint8_t> bytes) {
    ModuleInfo module;
    module.base = 0x1000;
    module.name = "t.dll";
    return ModuleImage::fromBytes(module, std::move(bytes));
}

Pattern pattern(const char* text) {
    auto p = parse(text);
    REQUIRE(p);
    return *p;
}

} // namespace

TEST_CASE("overlapping matches all count", "[image]") {
    const auto m = image({0x90, 0x90, 0x90, 0xCC});
    const auto hits = m.find(pattern("90 90"), 10);
    REQUIRE(hits.size() == 2);
    CHECK(hits[0] == 0x1000);
    CHECK(hits[1] == 0x1001);
}

TEST_CASE("find stops at the cap", "[image]") {
    const auto m = image(std::vector<std::uint8_t>(100, 0xCC));
    CHECK(m.count(pattern("CC"), 2) == 2);
    CHECK(m.count(pattern("CC CC"), 1000) == 99);
}

TEST_CASE("a match at the very end of the module is found", "[image]") {
    const auto m = image({0x00, 0x11, 0x22, 0x33});
    const auto hits = m.find(pattern("22 33"), 10);
    REQUIRE(hits.size() == 1);
    CHECK(hits[0] == 0x1002);
    CHECK(m.count(pattern("33 44"), 10) == 0);
}

TEST_CASE("wildcards and nibbles match anything in their place", "[image]") {
    const auto m = image({0x48, 0x8B, 0x05, 0x11, 0x48, 0x8D, 0x05, 0x22});
    CHECK(m.count(pattern("48 8? 05"), 10) == 2);
    CHECK(m.count(pattern("48 8B 05"), 10) == 1);
    CHECK(m.count(pattern("48 ?? 05"), 10) == 2);
    CHECK(m.count(pattern("?? ?? 05"), 10) == 2);
}

TEST_CASE("a match that touches an unreadable page is not a match", "[image]") {
    FakeMemory memory(Bitness::X86, 0x400000, 0x3000);
    memory.write(0x400800, {0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37});
    memory.write(0x401800, {0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37});
    memory.write(0x401FFD, {0xDE, 0xAD, 0xBE});
    memory.markUnreadable(0x401000, 0x1000);
    const auto m = ModuleImage::capture(memory, memory.module());
    REQUIRE(m);
    CHECK_FALSE(m->readable(0x401000, 1));
    CHECK(m->readable(0x402000, 0x1000));
    CHECK(m->count(pattern("DE AD BE EF 13 37"), 10) == 1);
    CHECK(m->count(pattern("DE AD BE"), 10) == 1);
}

TEST_CASE("capture fails cleanly when nothing can be read", "[image]") {
    FakeMemory memory(Bitness::X86, 0x400000, 0x2000);
    memory.markUnreadable(0x400000, 0x2000);
    std::string error;
    CHECK_FALSE(ModuleImage::capture(memory, memory.module(), &error));
    CHECK(error == "no page of the module could be read");
}

TEST_CASE("code ranges are the executable sections, or the whole module", "[image]") {
    FakeMemory memory(Bitness::X86, 0x400000, 0x3000);
    auto whole = ModuleImage::capture(memory, memory.module());
    REQUIRE(whole);
    REQUIRE(whole->codeRanges().size() == 1);
    CHECK(whole->codeRanges()[0] == std::pair<std::uint64_t, std::uint64_t>{0x400000, 0x403000});

    memory.addSection(0x401000, 0x1000, ".text", true);
    memory.addSection(0x402000, 0x1000, ".data", false);
    auto sectioned = ModuleImage::capture(memory, memory.module());
    REQUIRE(sectioned);
    REQUIRE(sectioned->codeRanges().size() == 1);
    CHECK(sectioned->codeRanges()[0] == std::pair<std::uint64_t, std::uint64_t>{0x401000, 0x402000});
}
