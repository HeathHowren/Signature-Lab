#pragma once

#include "core/MemoryView.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace siglab {

// One decoded instruction, reduced to what the wildcarder and the reference
// finder need: where the variable fields sit inside the encoding and what
// they mean. The Zydis types stay inside Decoder.cpp.
struct Decoded {
    struct Immediate {
        std::uint8_t offset = 0; // byte offset within the instruction
        std::uint8_t size = 0;   // in bytes
        bool relative = false;   // a branch displacement rather than a value
        std::uint64_t value = 0; // zero-extended
        std::int64_t signedValue = 0;
    };

    enum class MemoryKind : std::uint8_t {
        None,         // no memory operand with an encoded displacement
        RipRelative,  // [rip+disp32]
        Absolute,     // [disp32] with no base or index, or a moffs form
        BaseRelative, // [reg+disp], the struct-offset and stack-offset case
        SegmentBased, // fs:[disp] or gs:[disp] with no base: the TEB and PEB, constants
    };

    std::uint64_t address = 0;
    bool valid = false;
    std::uint8_t length = 1;
    std::string text; // Intel syntax, or "db XX" when undecodable

    bool isCall = false;
    bool isBranch = false; // any relative branch, call included
    bool isRet = false;
    bool isUnconditionalJump = false; // jmp, direct or indirect: control never falls through
    bool isInt3 = false;
    bool isNop = false;
    // A prefix the CPU ignores for this opcode. Decoding one byte early often
    // yields a valid instruction with a stray prefix; the reference finder
    // uses this to reject those misaligned readings.
    bool hasIgnoredPrefix = false;

    std::vector<Immediate> immediates; // at most two

    bool hasDisplacement = false;
    std::uint8_t displacementOffset = 0;
    std::uint8_t displacementSize = 0; // in bytes
    std::int64_t displacementValue = 0;
    MemoryKind memoryKind = MemoryKind::None;

    // Resolved targets, when the instruction has one.
    std::optional<std::uint64_t> branchTarget;  // for relative branches
    std::optional<std::uint64_t> memoryTarget;  // for RipRelative and Absolute
};

class Decoder {
public:
    explicit Decoder(Bitness bitness);
    ~Decoder();
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;

    [[nodiscard]] Bitness bitness() const { return bitness_; }

    // Decodes the instruction at the start of `bytes`. `available` may be
    // shorter than an instruction, in which case decoding fails and the result
    // is a one-byte "db" so a caller stepping through memory always advances.
    [[nodiscard]] Decoded decode(const std::uint8_t* bytes, std::size_t available, std::uint64_t address) const;

    // The longest x86 instruction. Reads for decoding are sized to this.
    static constexpr std::size_t kMaxInstructionLength = 15;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    Bitness bitness_;
};

} // namespace siglab
