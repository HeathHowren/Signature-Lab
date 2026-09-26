#pragma once

#include "core/Decoder.h"
#include "core/MemoryView.h"
#include "core/Pattern.h"

#include <cstdint>
#include <vector>

namespace siglab {

// Which classes of byte become wildcards. The defaults are the rule from the
// Handbook's chapter 14: wildcard what the linker or loader fills in, keep
// what the compiler chose. Every class is a switch because the right answer
// depends on the job: a signature meant to survive a game patch wants struct
// offsets wildcarded too, and one meant only to survive ASLR wants the
// fewest wildcards possible.
struct WildcardPolicy {
    bool branchRel32 = true;      // call/jmp/jcc rel32
    bool branchRel8 = false;      // jmp short / jcc short
    bool ripRelative = true;      // [rip+disp32]
    bool absoluteAddress = true;  // [disp32], moffs, table bases
    bool pointerImmediate = true; // push offset string, mov eax, offset global
    bool structOffset = false;    // [esi+F8], [rsp+28]
    bool largeImmediate = false;  // cmp eax, 3E8

    [[nodiscard]] bool masks(ByteReason reason) const;
    bool operator==(const WildcardPolicy&) const = default;
};

// Labels every byte of one decoded instruction. `view` is consulted only to
// decide whether an immediate points at readable memory; pass nullptr to
// treat every large immediate as a plain value.
[[nodiscard]] std::vector<ByteReason> classify(const Decoded& instruction, const MemoryView* view);

// The pattern for one instruction: its bytes, masked by `policy`, with the
// reasons attached.
[[nodiscard]] Pattern instructionPattern(const std::uint8_t* bytes, const Decoded& instruction, const std::vector<ByteReason>& reasons,
                                         const WildcardPolicy& policy);

} // namespace siglab
