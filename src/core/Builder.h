#pragma once

#include "core/Decoder.h"
#include "core/MemoryView.h"
#include "core/ModuleImage.h"
#include "core/Pattern.h"
#include "core/Wildcarder.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace siglab {

enum class Mode : std::uint8_t {
    Forward,   // grow whole instructions from the address until unique
    Shortest,  // as Forward, then cut to the shortest unique prefix
    Selection, // exactly the selected bytes, masked, with their match count
    Reference, // signatures at the code that refers to the address
};

[[nodiscard]] const char* modeName(Mode mode);
[[nodiscard]] std::optional<Mode> modeFromName(std::string_view name);

struct BuildOptions {
    WildcardPolicy policy;
    // Growth stops here. 64 bytes is past where a signature is still worth
    // pasting anywhere; a pattern that is not unique by then is at a spot
    // that should be signed from a reference instead.
    std::size_t maxBytes = 64;
    // Forward and reference growth continue past uniqueness until the
    // pattern has this many fixed bytes. "48 89 35" can be unique in a
    // module today, and one new store to any global breaks it tomorrow.
    // Growth never crosses a function end just to reach this floor.
    std::size_t minFixedBytes = 5;
    // Reference mode: how many reference sites to try, and how many of the
    // shortest unique results to keep.
    std::size_t maxReferenceSites = 32;
    std::size_t maxReferenceResults = 3;
};

struct InstructionInfo {
    std::uint64_t address = 0;
    std::uint8_t length = 0;
    std::string text;
};

// How to get from a reference signature's match back to the address it was
// made for.
enum class ReferenceKind : std::uint8_t {
    None,       // not a reference signature: the match is the address
    Relative,   // call/jmp/jcc rel32: target = match + end + rel32
    RipRelative, // [rip+disp32]: target = match + end + disp32
    Absolute32, // [disp32] or push/mov imm32: target = *(uint32*)(match + field)
    Absolute64, // mov r64, imm64: target = *(uint64*)(match + field)
};

struct Signature {
    Pattern pattern;
    std::uint64_t address = 0; // where the pattern starts
    std::uint64_t target = 0;  // the address the signature is for
    std::size_t matches = 0;   // capped; 1 means unique
    std::size_t matchCap = 2;
    Mode mode = Mode::Forward;
    std::string moduleName;
    std::uint64_t moduleBase = 0;
    std::vector<InstructionInfo> instructions;
    // Set when the pattern runs past a ret or into int3 padding: it is then
    // matching whatever the linker put after this function, which a rebuild
    // is free to change.
    bool crossesFunctionEnd = false;

    ReferenceKind referenceKind = ReferenceKind::None;
    std::uint8_t fieldOffset = 0;       // offset of the rel32/disp32/imm in the pattern
    std::uint8_t instructionLength = 0; // length of the referring instruction

    [[nodiscard]] bool unique() const { return matches == 1; }
    // The C++ expression that turns a match into the target, or an empty
    // string when the match is the target.
    [[nodiscard]] std::string resolution(std::string_view matchName = "match") const;
    // "bytes 8-11 absolute address; bytes 2-5 struct offset"
    [[nodiscard]] std::string wildcardSummary() const;
};

struct BuildResult {
    std::vector<Signature> signatures; // one, except in Reference mode
    std::string error;                 // set when no signature could be built
    std::vector<std::string> notes;    // warnings that do not stop the build

    [[nodiscard]] bool ok() const { return error.empty() && !signatures.empty(); }
};

// Builds signatures against one captured module. Construct one per
// operation: the image is a snapshot, and code the user patched a moment ago
// is not in it.
class Builder {
public:
    Builder(const MemoryView& view, ModuleImage image);

    [[nodiscard]] const ModuleImage& image() const { return image_; }

    [[nodiscard]] BuildResult forward(std::uint64_t address, const BuildOptions& options) const;
    [[nodiscard]] BuildResult shortest(std::uint64_t address, const BuildOptions& options) const;
    // [start, endInclusive], as x64dbg reports a selection.
    [[nodiscard]] BuildResult selection(std::uint64_t start, std::uint64_t endInclusive, const BuildOptions& options) const;
    [[nodiscard]] BuildResult references(std::uint64_t target, const BuildOptions& options) const;

    // One reference to the target found in code.
    struct Reference {
        std::uint64_t site = 0;  // start of the referring instruction
        std::uint8_t fieldOffset = 0;
        std::uint8_t length = 0;
        ReferenceKind kind = ReferenceKind::None;
        std::string text;
    };
    // Every instruction in the module's code that refers to `target` by a
    // rel32, a RIP-relative displacement or an absolute address, up to `cap`.
    [[nodiscard]] std::vector<Reference> findReferences(std::uint64_t target, std::size_t cap) const;

    // Decodes the instruction at `address` from the snapshot.
    [[nodiscard]] Decoded decodeAt(std::uint64_t address) const;

private:
    // Appends whole instructions from `address` until the pattern is unique
    // and has `minFixedBytes` fixed bytes, or `maxBytes` is reached. Trailing
    // wildcards are trimmed, but never below `keepAtLeast` bytes: a reference
    // signature keeps the field its resolve rule reads.
    [[nodiscard]] Signature grow(std::uint64_t address, const BuildOptions& options, std::size_t keepAtLeast = 0) const;
    void fill(Signature& signature) const;

    const MemoryView& view_;
    ModuleImage image_;
    Decoder decoder_;
};

// Convenience: capture the module containing `address` and run one mode.
// `selectionEnd` is used by Mode::Selection only.
[[nodiscard]] BuildResult build(const MemoryView& view, std::uint64_t address, Mode mode, const BuildOptions& options,
                                std::uint64_t selectionEnd = 0);

} // namespace siglab
