#include "FakeMemory.h"

#include "core/Decoder.h"
#include "core/Wildcarder.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

using namespace siglab;
using test::FakeMemory;

namespace {

using R = ByteReason;

struct Classified {
    Decoded decoded;
    std::vector<ByteReason> reasons;
};

Classified classifyBytes(Bitness bitness, std::uint64_t address, const std::vector<std::uint8_t>& bytes, const MemoryView* view = nullptr) {
    const Decoder decoder(bitness);
    Classified c;
    c.decoded = decoder.decode(bytes.data(), bytes.size(), address);
    c.reasons = classify(c.decoded, view);
    return c;
}

std::vector<ByteReason> reasons(std::initializer_list<std::pair<ByteReason, int>> runs) {
    std::vector<ByteReason> out;
    for (const auto& [reason, count] : runs) {
        out.insert(out.end(), static_cast<std::size_t>(count), reason);
    }
    return out;
}

constexpr std::uint64_t kX86 = 0x401000;
constexpr std::uint64_t kX64 = 0x140001000;

} // namespace

TEST_CASE("x86: a struct offset is kept", "[decoder]") {
    // mov [esi+F8], eax
    const auto c = classifyBytes(Bitness::X86, kX86, {0x89, 0x86, 0xF8, 0x00, 0x00, 0x00});
    REQUIRE(c.decoded.valid);
    CHECK(c.decoded.length == 6);
    CHECK(c.decoded.memoryKind == Decoded::MemoryKind::BaseRelative);
    CHECK(c.reasons == reasons({{R::Opcode, 2}, {R::StructOffset, 4}}));
}

TEST_CASE("x86: an absolute address is masked, through ModRM and through moffs", "[decoder]") {
    // mov ecx, [12345678]
    const auto modrm = classifyBytes(Bitness::X86, kX86, {0x8B, 0x0D, 0x78, 0x56, 0x34, 0x12});
    CHECK(modrm.reasons == reasons({{R::Opcode, 2}, {R::AbsoluteAddress, 4}}));
    CHECK(modrm.decoded.memoryTarget == 0x12345678u);

    // mov eax, [12345678], the A1 moffs encoding with no ModRM byte
    const auto moffs = classifyBytes(Bitness::X86, kX86, {0xA1, 0x78, 0x56, 0x34, 0x12});
    CHECK(moffs.reasons == reasons({{R::Opcode, 1}, {R::AbsoluteAddress, 4}}));
    CHECK(moffs.decoded.memoryTarget == 0x12345678u);
}

TEST_CASE("x86: a jump table base with an index and no base register is an absolute address", "[decoder]") {
    // jmp [eax*4+00401000]
    const auto c = classifyBytes(Bitness::X86, kX86, {0xFF, 0x24, 0x85, 0x00, 0x10, 0x40, 0x00});
    CHECK(c.reasons == reasons({{R::Opcode, 3}, {R::AbsoluteAddress, 4}}));
}

TEST_CASE("x86: fs-relative TEB access is a constant, not an address", "[decoder]") {
    // mov eax, fs:[18]
    const auto c = classifyBytes(Bitness::X86, kX86, {0x64, 0xA1, 0x18, 0x00, 0x00, 0x00});
    CHECK(c.decoded.memoryKind == Decoded::MemoryKind::SegmentBased);
    CHECK(c.reasons == reasons({{R::Opcode, 2}, {R::StructOffset, 4}}));
}

TEST_CASE("x86: branch targets are labelled by width", "[decoder]") {
    const auto call = classifyBytes(Bitness::X86, kX86, {0xE8, 0xFB, 0x0F, 0x00, 0x00});
    CHECK(call.decoded.isCall);
    CHECK(call.decoded.branchTarget == kX86 + 5 + 0xFFB);
    CHECK(call.reasons == reasons({{R::Opcode, 1}, {R::BranchRel32, 4}}));

    const auto jcc = classifyBytes(Bitness::X86, kX86, {0x0F, 0x84, 0x10, 0x00, 0x00, 0x00});
    CHECK(jcc.reasons == reasons({{R::Opcode, 2}, {R::BranchRel32, 4}}));

    const auto shortJump = classifyBytes(Bitness::X86, kX86, {0xEB, 0x05});
    CHECK(shortJump.reasons == reasons({{R::Opcode, 1}, {R::BranchRel8, 1}}));
}

TEST_CASE("x86: an immediate that points at readable memory is a pointer", "[decoder]") {
    FakeMemory memory(Bitness::X86, 0x400000, 0x3000);
    // push 00402000, an address inside the module
    const auto pointer = classifyBytes(Bitness::X86, kX86, {0x68, 0x00, 0x20, 0x40, 0x00}, &memory);
    CHECK(pointer.reasons == reasons({{R::Opcode, 1}, {R::PointerImmediate, 4}}));

    // push 3E8: a count, not an address
    const auto value = classifyBytes(Bitness::X86, kX86, {0x68, 0xE8, 0x03, 0x00, 0x00}, &memory);
    CHECK(value.reasons == reasons({{R::Opcode, 1}, {R::LargeImmediate, 4}}));

    // push 5
    const auto small = classifyBytes(Bitness::X86, kX86, {0x6A, 0x05}, &memory);
    CHECK(small.reasons == reasons({{R::Opcode, 1}, {R::Immediate, 1}}));

    // cmp dword ptr [esi+8], 5
    const auto both = classifyBytes(Bitness::X86, kX86, {0x83, 0x7E, 0x08, 0x05}, &memory);
    CHECK(both.reasons == reasons({{R::Opcode, 2}, {R::StructOffset, 1}, {R::Immediate, 1}}));
}

TEST_CASE("x64: a RIP-relative displacement is masked and resolved", "[decoder]") {
    // mov rax, [rip+1000]
    const auto c = classifyBytes(Bitness::X64, kX64, {0x48, 0x8B, 0x05, 0x00, 0x10, 0x00, 0x00});
    CHECK(c.decoded.memoryKind == Decoded::MemoryKind::RipRelative);
    CHECK(c.decoded.memoryTarget == kX64 + 7 + 0x1000);
    CHECK(c.reasons == reasons({{R::Opcode, 3}, {R::RipRelative, 4}}));
}

TEST_CASE("x64: an immediate after a RIP-relative displacement is kept and moves the target", "[decoder]") {
    // cmp dword ptr [rip+1000], 5: the instruction ends after the 05, and
    // RIP-relative addressing counts from the end.
    const auto c = classifyBytes(Bitness::X64, kX64, {0x83, 0x3D, 0x00, 0x10, 0x00, 0x00, 0x05});
    CHECK(c.decoded.memoryTarget == kX64 + 7 + 0x1000);
    CHECK(c.reasons == reasons({{R::Opcode, 2}, {R::RipRelative, 4}, {R::Immediate, 1}}));
}

TEST_CASE("x64: gs-relative PEB access and stack offsets are kept", "[decoder]") {
    // mov rax, gs:[60]
    const auto peb = classifyBytes(Bitness::X64, kX64, {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});
    CHECK(peb.reasons == reasons({{R::Opcode, 5}, {R::StructOffset, 4}}));

    // mov rcx, [rsp+28]
    const auto stack = classifyBytes(Bitness::X64, kX64, {0x48, 0x8B, 0x4C, 0x24, 0x28});
    CHECK(stack.reasons == reasons({{R::Opcode, 4}, {R::StructOffset, 1}}));
}

TEST_CASE("x64: a 64-bit immediate that points at readable memory is a pointer", "[decoder]") {
    FakeMemory memory(Bitness::X64, 0x140000000, 0x4000);
    // mov rax, 140003000
    const auto c =
        classifyBytes(Bitness::X64, kX64, {0x48, 0xB8, 0x00, 0x30, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00}, &memory);
    CHECK(c.reasons == reasons({{R::Opcode, 2}, {R::PointerImmediate, 8}}));
}

TEST_CASE("an opcode that is invalid in the mode is one undecodable byte", "[decoder]") {
    // 06 is push es, which does not exist in 64-bit mode.
    const auto c = classifyBytes(Bitness::X64, kX64, {0x06, 0x90});
    CHECK_FALSE(c.decoded.valid);
    CHECK(c.decoded.length == 1);
    CHECK(c.reasons == reasons({{R::Undecodable, 1}}));
}

TEST_CASE("the same byte means different things in x86 and x64", "[decoder]") {
    // 40 is inc eax in x86 and a REX prefix in x64.
    const auto x86 = classifyBytes(Bitness::X86, kX86, {0x40, 0x90});
    CHECK(x86.decoded.length == 1);
    const auto x64 = classifyBytes(Bitness::X64, kX64, {0x40, 0x90});
    CHECK(x64.decoded.length == 2);
}

TEST_CASE("the default policy is chapter 14's rule", "[wildcarder]") {
    const WildcardPolicy policy;
    CHECK(policy.masks(R::BranchRel32));
    CHECK(policy.masks(R::RipRelative));
    CHECK(policy.masks(R::AbsoluteAddress));
    CHECK(policy.masks(R::PointerImmediate));
    CHECK_FALSE(policy.masks(R::BranchRel8));
    CHECK_FALSE(policy.masks(R::StructOffset));
    CHECK_FALSE(policy.masks(R::LargeImmediate));
    CHECK_FALSE(policy.masks(R::Immediate));
    CHECK_FALSE(policy.masks(R::Opcode));
    CHECK_FALSE(policy.masks(R::Undecodable));
}

TEST_CASE("instructionPattern applies the policy to the reasons", "[wildcarder]") {
    const std::vector<std::uint8_t> bytes = {0x89, 0x86, 0xF8, 0x00, 0x00, 0x00};
    const auto c = classifyBytes(Bitness::X86, kX86, bytes);

    WildcardPolicy keep;
    CHECK(instructionPattern(bytes.data(), c.decoded, c.reasons, keep).wildcardCount() == 0);

    WildcardPolicy patchProof;
    patchProof.structOffset = true;
    const Pattern masked = instructionPattern(bytes.data(), c.decoded, c.reasons, patchProof);
    CHECK(masked.wildcardCount() == 4);
    CHECK(format(masked, Format::X64dbg) == "89 86 ?? ?? ?? ??");
}
