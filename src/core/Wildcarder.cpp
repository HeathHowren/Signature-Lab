#include "core/Wildcarder.h"

namespace siglab {

namespace {

// Nothing is ever mapped in the first 64 KiB of a Windows process, so a
// value below this is a count, a flag or a size, never a pointer. Without the
// floor, an immediate such as 0x1000 would be tested against a page the
// allocator happened to hand out and occasionally be called a pointer.
constexpr std::uint64_t kLowestPointer = 0x10000;

void label(std::vector<ByteReason>& reasons, std::size_t offset, std::size_t size, ByteReason reason) {
    for (std::size_t i = offset; i < offset + size && i < reasons.size(); ++i) {
        reasons[i] = reason;
    }
}

} // namespace

bool WildcardPolicy::masks(ByteReason reason) const {
    switch (reason) {
    case ByteReason::Opcode:
    case ByteReason::Immediate:
    case ByteReason::Undecodable:
        return false;
    case ByteReason::LargeImmediate:
        return largeImmediate;
    case ByteReason::StructOffset:
        return structOffset;
    case ByteReason::BranchRel8:
        return branchRel8;
    case ByteReason::BranchRel32:
        return branchRel32;
    case ByteReason::RipRelative:
        return ripRelative;
    case ByteReason::AbsoluteAddress:
        return absoluteAddress;
    case ByteReason::PointerImmediate:
        return pointerImmediate;
    }
    return false;
}

std::vector<ByteReason> classify(const Decoded& d, const MemoryView* view) {
    std::vector<ByteReason> reasons(d.length, d.valid ? ByteReason::Opcode : ByteReason::Undecodable);
    if (!d.valid) {
        return reasons;
    }

    if (d.hasDisplacement) {
        ByteReason reason = ByteReason::StructOffset;
        switch (d.memoryKind) {
        case Decoded::MemoryKind::RipRelative:
            reason = ByteReason::RipRelative;
            break;
        case Decoded::MemoryKind::Absolute:
            reason = ByteReason::AbsoluteAddress;
            break;
        case Decoded::MemoryKind::BaseRelative:
        case Decoded::MemoryKind::SegmentBased:
        case Decoded::MemoryKind::None:
            reason = ByteReason::StructOffset;
            break;
        }
        label(reasons, d.displacementOffset, d.displacementSize, reason);
    }

    for (const auto& imm : d.immediates) {
        ByteReason reason = ByteReason::Immediate;
        if (imm.relative) {
            reason = imm.size == 1 ? ByteReason::BranchRel8 : ByteReason::BranchRel32;
        } else if (imm.size >= 4) {
            // A 32-bit immediate in x64 code can only be a pointer into an
            // image loaded below 4 GiB, which is rare but real (large-address-
            // unaware executables); the readability test decides either way.
            std::uint64_t value = imm.value;
            if (imm.size == 4) {
                value &= 0xFFFFFFFFull;
            }
            const bool pointer = view != nullptr && value >= kLowestPointer && view->isReadable(value);
            reason = pointer ? ByteReason::PointerImmediate : ByteReason::LargeImmediate;
        }
        label(reasons, imm.offset, imm.size, reason);
    }
    return reasons;
}

Pattern instructionPattern(const std::uint8_t* bytes, const Decoded& d, const std::vector<ByteReason>& reasons, const WildcardPolicy& policy) {
    Pattern p;
    for (std::size_t i = 0; i < d.length; ++i) {
        const ByteReason reason = i < reasons.size() ? reasons[i] : ByteReason::Opcode;
        p.append(bytes[i], policy.masks(reason) ? std::uint8_t{0x00} : std::uint8_t{0xFF}, reason);
    }
    return p;
}

} // namespace siglab
