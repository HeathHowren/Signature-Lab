#include "core/Decoder.h"

#include "core/Pattern.h"

// Zydis is C and its headers are clean at /W4, but they are third-party, so
// keep the project's warnings-as-errors off them.
#pragma warning(push, 3)
#include <Zydis/Zydis.h>
#pragma warning(pop)

namespace siglab {

struct Decoder::Impl {
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};
};

Decoder::Decoder(Bitness bitness) : impl_(std::make_unique<Impl>()), bitness_(bitness) {
    if (bitness == Bitness::X64) {
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
    ZydisFormatterInit(&impl_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    // x64dbg prints hex without a 0x prefix and in upper case; match it so the
    // log reads like the disassembly view it sits next to.
    ZydisFormatterSetProperty(&impl_->formatter, ZYDIS_FORMATTER_PROP_HEX_PREFIX, ZyanUPointer{0});
    ZydisFormatterSetProperty(&impl_->formatter, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_TRUE);
}

Decoder::~Decoder() = default;

Decoded Decoder::decode(const std::uint8_t* bytes, std::size_t available, std::uint64_t address) const {
    Decoded d;
    d.address = address;

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (available == 0 || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&impl_->decoder, bytes, available, &instr, operands))) {
        d.valid = false;
        d.length = 1;
        d.text = available == 0 ? std::string("db ??") : "db " + hexBytes(bytes, 1);
        return d;
    }

    d.valid = true;
    d.length = instr.length;

    char text[256];
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&impl_->formatter, &instr, operands, instr.operand_count_visible, text,
                                                     sizeof(text), address, ZYAN_NULL))) {
        d.text = text;
    }

    d.isCall = instr.meta.category == ZYDIS_CATEGORY_CALL;
    d.isRet = instr.meta.category == ZYDIS_CATEGORY_RET;
    d.isUnconditionalJump = instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    d.isInt3 = instr.mnemonic == ZYDIS_MNEMONIC_INT3;
    d.isNop = instr.mnemonic == ZYDIS_MNEMONIC_NOP;
    for (ZyanU8 i = 0; i < instr.raw.prefix_count; ++i) {
        if (instr.raw.prefixes[i].type == ZYDIS_PREFIX_TYPE_IGNORED) {
            d.hasIgnoredPrefix = true;
        }
    }

    for (const auto& raw : instr.raw.imm) {
        if (raw.size == 0) {
            continue;
        }
        Decoded::Immediate imm;
        imm.offset = raw.offset;
        imm.size = static_cast<std::uint8_t>(raw.size / 8);
        imm.relative = raw.is_relative != 0;
        imm.value = raw.value.u;
        imm.signedValue = raw.value.s;
        if (imm.relative) {
            d.isBranch = true;
        }
        d.immediates.push_back(imm);
    }

    if (instr.raw.disp.size != 0) {
        d.hasDisplacement = true;
        d.displacementOffset = instr.raw.disp.offset;
        d.displacementSize = static_cast<std::uint8_t>(instr.raw.disp.size / 8);
        d.displacementValue = instr.raw.disp.value;
    }

    for (ZyanU8 i = 0; i < instr.operand_count; ++i) {
        const ZydisDecodedOperand& op = operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
            ZyanU64 target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &op, address, &target))) {
                d.branchTarget = target;
            }
            continue;
        }
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY || !d.hasDisplacement || d.memoryKind != Decoded::MemoryKind::None) {
            continue;
        }
        // Implicit memory operands ([rsi] for movs, [rsp] for push) carry no
        // encoded displacement and never reach here; the one memory operand
        // that owns the raw displacement is the one with has_displacement set.
        if (!op.mem.disp.has_displacement) {
            continue;
        }
        if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP) {
            d.memoryKind = Decoded::MemoryKind::RipRelative;
            ZyanU64 target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &op, address, &target))) {
                d.memoryTarget = target;
            }
        } else if (op.mem.base == ZYDIS_REGISTER_NONE &&
                   (op.mem.segment == ZYDIS_REGISTER_FS || op.mem.segment == ZYDIS_REGISTER_GS)) {
            // fs:[30] and gs:[60] reach the TEB and PEB. The displacement is
            // a fixed offset defined by Windows, not something the linker or
            // the loader moves, so it is kept like a struct offset.
            d.memoryKind = Decoded::MemoryKind::SegmentBased;
        } else if (op.mem.base == ZYDIS_REGISTER_NONE) {
            // No base register means the displacement is the address itself:
            // [00501234], or a table base in [eax*4+00401000]. Both relocate.
            d.memoryKind = Decoded::MemoryKind::Absolute;
            if (op.mem.index == ZYDIS_REGISTER_NONE) {
                std::uint64_t target = static_cast<std::uint64_t>(op.mem.disp.value);
                if (bitness_ == Bitness::X86) {
                    target &= 0xFFFFFFFFull;
                }
                d.memoryTarget = target;
            }
        } else {
            d.memoryKind = Decoded::MemoryKind::BaseRelative;
        }
    }

    return d;
}

} // namespace siglab
