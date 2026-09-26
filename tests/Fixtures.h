#pragma once

#include "FakeMemory.h"

#include "core/Builder.h"

#include <cstring>

namespace siglab::test {

// A 32-bit module shaped like the code chapter 14 signs: two functions that
// share a prologue and differ only in the struct offset they write, a caller
// that calls both and pushes the address of one, and a global both read.
struct X86Fixture {
    static constexpr std::uint64_t kBase = 0x400000;
    static constexpr std::uint64_t kA = 0x401000;
    static constexpr std::uint64_t kB = 0x401020;
    static constexpr std::uint64_t kCaller = 0x401040;
    static constexpr std::uint64_t kGlobal = 0x402000;

    FakeMemory memory{Bitness::X86, kBase, 0x3000, "game.exe"};

    X86Fixture() {
        memory.addSection(0x401000, 0x1000, ".text", true);
        memory.addSection(0x402000, 0x1000, ".data", false);
        // A: push ebp; mov ebp, esp; mov ecx, [402000]; mov [esi+F8], eax; pop ebp; ret
        memory.write(kA, {0x55, 0x8B, 0xEC, 0x8B, 0x0D, 0x00, 0x20, 0x40, 0x00, 0x89, 0x86, 0xF8, 0x00, 0x00, 0x00, 0x5D, 0xC3});
        // B: the same, writing +FC instead of +F8
        memory.write(kB, {0x55, 0x8B, 0xEC, 0x8B, 0x0D, 0x00, 0x20, 0x40, 0x00, 0x89, 0x86, 0xFC, 0x00, 0x00, 0x00, 0x5D, 0xC3});
        // caller: call A; push 0; call B; push offset A; ret
        memory.write(kCaller, {0xE8});
        memory.write32(kCaller + 1, rel32(kCaller, 5, kA));
        memory.write(kCaller + 5, {0x6A, 0x00, 0xE8});
        memory.write32(kCaller + 8, rel32(kCaller + 7, 5, kB));
        memory.write(kCaller + 12, {0x68});
        memory.write32(kCaller + 13, static_cast<std::uint32_t>(kA));
        memory.write(kCaller + 17, {0xC3});
    }

    Builder builder() const {
        auto image = ModuleImage::capture(memory, memory.module());
        return Builder(memory, std::move(*image));
    }
};

// A 64-bit module with three RIP-relative references to one global and a
// call to the function that makes the first of them.
struct X64Fixture {
    static constexpr std::uint64_t kBase = 0x140000000;
    static constexpr std::uint64_t kFunc = 0x140001000;
    static constexpr std::uint64_t kCmp = 0x14000100C;
    static constexpr std::uint64_t kLea = 0x140001020;
    static constexpr std::uint64_t kCall = 0x140001030;
    static constexpr std::uint64_t kGlobal = 0x140003000;

    FakeMemory memory{Bitness::X64, kBase, 0x4000, "game64.exe"};

    X64Fixture() {
        memory.addSection(0x140001000, 0x1000, ".text", true);
        memory.addSection(0x140003000, 0x1000, ".data", false);
        // mov rax, [rip+global]; test rax, rax; je +5
        memory.write(kFunc, {0x48, 0x8B, 0x05});
        memory.write32(kFunc + 3, rel32(kFunc, 7, kGlobal));
        memory.write(kFunc + 7, {0x48, 0x85, 0xC0, 0x74, 0x05});
        // cmp dword ptr [rip+global], 5; ret
        memory.write(kCmp, {0x83, 0x3D});
        memory.write32(kCmp + 2, rel32(kCmp, 7, kGlobal));
        memory.write(kCmp + 6, {0x05, 0xC3});
        // lea rcx, [rip+global]; ret
        memory.write(kLea, {0x48, 0x8D, 0x0D});
        memory.write32(kLea + 3, rel32(kLea, 7, kGlobal));
        memory.write(kLea + 7, {0xC3});
        // call func; ret
        memory.write(kCall, {0xE8});
        memory.write32(kCall + 1, rel32(kCall, 5, kFunc));
        memory.write(kCall + 5, {0xC3});
    }

    Builder builder() const {
        auto image = ModuleImage::capture(memory, memory.module());
        return Builder(memory, std::move(*image));
    }
};

// Applies a reference signature's resolution rule to the bytes at its match,
// the way a reader's scanner would.
inline std::uint64_t resolve(const FakeMemory& memory, const Signature& s, std::uint64_t match) {
    const std::uint8_t* at = memory.bytes().data() + (match - memory.module().base);
    switch (s.referenceKind) {
    case ReferenceKind::Relative:
    case ReferenceKind::RipRelative: {
        std::int32_t rel;
        std::memcpy(&rel, at + s.fieldOffset, 4);
        return match + s.instructionLength + static_cast<std::uint64_t>(static_cast<std::int64_t>(rel));
    }
    case ReferenceKind::Absolute32: {
        std::uint32_t value;
        std::memcpy(&value, at + s.fieldOffset, 4);
        return value;
    }
    case ReferenceKind::Absolute64: {
        std::uint64_t value;
        std::memcpy(&value, at + s.fieldOffset, 8);
        return value;
    }
    case ReferenceKind::None:
        return match;
    }
    return 0;
}

} // namespace siglab::test
