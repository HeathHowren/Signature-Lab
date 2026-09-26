#include "core/Builder.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <optional>

namespace siglab {

namespace {

std::string hex(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

// Control does not fall through any of these, so whatever follows is the
// next function, padding, or a jump table: bytes the linker is free to move.
// A tail call (jmp to another function) counts, and is the case that is easy
// to miss; MSVC ends __scrt_common_main and many thunks that way.
bool endsFunction(const Decoded& d) {
    return d.isRet || d.isInt3 || d.isUnconditionalJump;
}

// Reads a little-endian integer from the snapshot without alignment traps.
template <typename T>
T load(const std::uint8_t* at) {
    T value;
    std::memcpy(&value, at, sizeof(T));
    return value;
}

// A unique signature with fewer fixed bytes than the floor: growth stopped
// at a function end, or Shortest cut it there on purpose.
std::optional<std::string> fewFixedBytes(const Signature& s, const BuildOptions& options) {
    const std::size_t fixed = s.pattern.fixedCount();
    if (!s.unique() || fixed >= options.minFixedBytes) {
        return std::nullopt;
    }
    return "only " + std::to_string(fixed) + " fixed byte" + (fixed == 1 ? "" : "s") +
           ": unique today, but one new function in the next build could match it too.";
}

} // namespace

const char* modeName(Mode mode) {
    switch (mode) {
    case Mode::Forward:
        return "forward";
    case Mode::Shortest:
        return "shortest";
    case Mode::Selection:
        return "selection";
    case Mode::Reference:
        return "reference";
    }
    return "forward";
}

std::optional<Mode> modeFromName(std::string_view name) {
    std::string lower;
    for (char c : name) {
        if (c != ' ') {
            lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }
    if (lower.empty() || lower == "forward" || lower == "f") {
        return Mode::Forward;
    }
    if (lower == "shortest" || lower == "short" || lower == "s") {
        return Mode::Shortest;
    }
    if (lower == "selection" || lower == "sel") {
        return Mode::Selection;
    }
    if (lower == "reference" || lower == "ref" || lower == "xref" || lower == "r") {
        return Mode::Reference;
    }
    return std::nullopt;
}

std::string Signature::resolution(std::string_view m) const {
    const std::string match(m);
    const std::string field = match + " + " + std::to_string(fieldOffset);
    switch (referenceKind) {
    case ReferenceKind::None:
        return {};
    case ReferenceKind::Relative:
    case ReferenceKind::RipRelative:
        return match + " + " + std::to_string(instructionLength) + " + *reinterpret_cast<const std::int32_t*>(" + field + ")";
    case ReferenceKind::Absolute32:
        return "*reinterpret_cast<const std::uint32_t*>(" + field + ")";
    case ReferenceKind::Absolute64:
        return "*reinterpret_cast<const std::uint64_t*>(" + field + ")";
    }
    return {};
}

std::string Signature::wildcardSummary() const {
    if (!pattern.hasReasons()) {
        return {};
    }
    std::string out;
    std::size_t i = 0;
    while (i < pattern.size()) {
        if (!pattern.isWildcard(i)) {
            ++i;
            continue;
        }
        const ByteReason reason = pattern.reasons[i];
        std::size_t j = i;
        while (j + 1 < pattern.size() && pattern.isWildcard(j + 1) && pattern.reasons[j + 1] == reason) {
            ++j;
        }
        if (!out.empty()) {
            out += "; ";
        }
        out += i == j ? "byte " + std::to_string(i) : "bytes " + std::to_string(i) + "-" + std::to_string(j);
        out += ' ';
        out += reasonName(reason);
        i = j + 1;
    }
    return out;
}

Builder::Builder(const MemoryView& view, ModuleImage image) : view_(view), image_(std::move(image)), decoder_(view.bitness()) {}

Decoded Builder::decodeAt(std::uint64_t address) const {
    std::uint8_t buffer[Decoder::kMaxInstructionLength] = {};
    const std::size_t available = image_.read(address, buffer, sizeof(buffer));
    return decoder_.decode(buffer, available, address);
}

void Builder::fill(Signature& s) const {
    s.moduleName = image_.module().name;
    s.moduleBase = image_.base();
}

Signature Builder::grow(std::uint64_t address, const BuildOptions& options, std::size_t keepAtLeast) const {
    Signature s;
    s.address = address;
    s.target = address;
    fill(s);

    bool pastEnd = false;
    std::uint64_t cursor = address;
    while (s.pattern.size() < options.maxBytes && image_.readable(cursor, 1)) {
        std::uint8_t buffer[Decoder::kMaxInstructionLength] = {};
        const std::size_t available = image_.read(cursor, buffer, sizeof(buffer));
        const Decoded d = decoder_.decode(buffer, available, cursor);
        if (pastEnd) {
            s.crossesFunctionEnd = true;
        }
        const auto reasons = classify(d, &view_);
        s.pattern.append(instructionPattern(buffer, d, reasons, options.policy));
        s.instructions.push_back({cursor, d.length, d.text});
        if (endsFunction(d)) {
            pastEnd = true;
        }
        cursor += d.length;

        Pattern trimmed = s.pattern;
        trimmed.trimTrailingWildcards();
        if (trimmed.fixedCount() == 0) {
            continue;
        }
        s.matches = image_.count(trimmed, s.matchCap);
        if (s.matches == 1 && (trimmed.fixedCount() >= options.minFixedBytes || pastEnd)) {
            break;
        }
    }
    // The last instruction may take the pattern past maxBytes; a signature
    // that is unique at 66 bytes is still more use than a refusal at 64.
    const Pattern full = s.pattern;
    s.pattern.trimTrailingWildcards();
    if (s.pattern.size() < keepAtLeast) {
        s.pattern = full.prefix(std::min(keepAtLeast, full.size()));
    }
    if (s.pattern.fixedCount() > 0) {
        s.matches = image_.count(s.pattern, s.matchCap);
    }
    return s;
}

BuildResult Builder::forward(std::uint64_t address, const BuildOptions& options) const {
    BuildResult result;
    if (!image_.readable(address, 1)) {
        result.error = "the address " + hex(address) + " is not readable";
        return result;
    }
    Signature s = grow(address, options);
    s.mode = Mode::Forward;
    if (s.matches == 0) {
        result.error = "the bytes at " + hex(address) + " do not match themselves; the snapshot changed under us";
        return result;
    }
    if (!s.unique()) {
        result.notes.push_back("not unique within " + std::to_string(options.maxBytes) +
                               " bytes; this code is repeated in the module. Try a reference signature.");
    } else if (auto note = fewFixedBytes(s, options)) {
        result.notes.push_back(std::move(*note));
    }
    result.signatures.push_back(std::move(s));
    return result;
}

BuildResult Builder::shortest(std::uint64_t address, const BuildOptions& options) const {
    BuildResult result = forward(address, options);
    if (!result.ok() || !result.signatures.front().unique()) {
        if (result.ok()) {
            result.signatures.front().mode = Mode::Shortest;
        }
        return result;
    }
    Signature& s = result.signatures.front();
    s.mode = Mode::Shortest;
    // Forward's floor note describes forward's pattern; this one is re-judged below.
    result.notes.clear();

    // Match count only falls as a prefix grows (every match of a longer
    // prefix is a match of the shorter one), so the shortest unique prefix
    // can be found by bisection.
    std::size_t low = 1;
    std::size_t high = s.pattern.size();
    while (low < high) {
        const std::size_t mid = low + (high - low) / 2;
        Pattern candidate = s.pattern.prefix(mid);
        candidate.trimTrailingWildcards();
        const bool unique = candidate.fixedCount() > 0 && image_.count(candidate, 2) == 1;
        if (unique) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    s.pattern = s.pattern.prefix(high);
    s.pattern.trimTrailingWildcards();
    s.matches = image_.count(s.pattern, s.matchCap);

    const std::uint64_t end = s.address + s.pattern.size();
    s.crossesFunctionEnd = false;
    bool pastEnd = false;
    std::vector<InstructionInfo> kept;
    for (const auto& instruction : s.instructions) {
        if (instruction.address >= end) {
            break;
        }
        if (pastEnd) {
            s.crossesFunctionEnd = true;
        }
        kept.push_back(instruction);
        const Decoded d = decodeAt(instruction.address);
        if (endsFunction(d)) {
            pastEnd = true;
        }
    }
    s.instructions = std::move(kept);
    if (auto note = fewFixedBytes(s, options)) {
        result.notes.push_back(std::move(*note));
    }
    return result;
}

BuildResult Builder::selection(std::uint64_t start, std::uint64_t endInclusive, const BuildOptions& options) const {
    BuildResult result;
    if (endInclusive < start) {
        std::swap(start, endInclusive);
    }
    if (!image_.readable(start, static_cast<std::size_t>(endInclusive - start + 1))) {
        result.error = "the selection " + hex(start) + "-" + hex(endInclusive) + " is not entirely inside one readable module";
        return result;
    }
    Signature s;
    s.mode = Mode::Selection;
    s.address = start;
    s.target = start;
    s.matchCap = 1000;
    fill(s);

    const std::uint64_t end = endInclusive + 1;
    std::uint64_t cursor = start;
    bool pastEnd = false;
    while (cursor < end) {
        std::uint8_t buffer[Decoder::kMaxInstructionLength] = {};
        const std::size_t available = image_.read(cursor, buffer, sizeof(buffer));
        const Decoded d = decoder_.decode(buffer, available, cursor);
        if (pastEnd) {
            s.crossesFunctionEnd = true;
        }
        const auto reasons = classify(d, &view_);
        Pattern piece = instructionPattern(buffer, d, reasons, options.policy);
        const std::uint64_t remaining = end - cursor;
        if (piece.size() > remaining) {
            piece = piece.prefix(static_cast<std::size_t>(remaining));
            result.notes.push_back("the selection ends part-way through " + d.text + ".");
        }
        s.pattern.append(piece);
        s.instructions.push_back({cursor, d.length, d.text});
        if (endsFunction(d)) {
            pastEnd = true;
        }
        cursor += d.length;
    }
    s.pattern.trimTrailingWildcards();
    if (s.pattern.fixedCount() == 0) {
        result.error = "every selected byte is a wildcard under the current settings";
        return result;
    }
    s.matches = image_.count(s.pattern, s.matchCap);
    if (s.matches > 1) {
        result.notes.push_back(std::to_string(s.matches) + (s.matches >= s.matchCap ? "+" : "") +
                               " matches: extend the selection or use Make signature.");
    }
    result.signatures.push_back(std::move(s));
    return result;
}

std::vector<Builder::Reference> Builder::findReferences(std::uint64_t target, std::size_t cap) const {
    std::vector<Reference> found;
    const bool x64 = view_.bitness() == Bitness::X64;
    const std::uint8_t* data = image_.data();
    const std::uint64_t base = image_.base();

    // Confirms a candidate field at `fieldAddress` by finding an instruction
    // that starts at most 14 bytes before it, carries a displacement or
    // immediate at exactly that address, and resolves to the target. Of the
    // readings that do, the one with no ignored prefix that starts earliest
    // is kept: "48 8D 05 disp32" also decodes from the 8D as a 32-bit lea
    // with the same field and target, and only the longer reading is the
    // instruction the compiler emitted.
    auto confirm = [&](std::uint64_t fieldAddress) -> std::optional<Reference> {
        std::optional<Reference> best;
        for (std::uint64_t back = 1; back < Decoder::kMaxInstructionLength; ++back) {
            if (fieldAddress < base + back) {
                break;
            }
            const std::uint64_t start = fieldAddress - back;
            const Decoded d = decodeAt(start);
            if (!d.valid || d.hasIgnoredPrefix || start + d.length <= fieldAddress) {
                continue;
            }
            const auto offset = static_cast<std::uint8_t>(back);
            ReferenceKind kind = ReferenceKind::None;
            if (d.hasDisplacement && d.displacementOffset == offset && d.displacementSize == 4 && d.memoryTarget == target) {
                kind = d.memoryKind == Decoded::MemoryKind::RipRelative ? ReferenceKind::RipRelative : ReferenceKind::Absolute32;
            }
            for (const auto& imm : d.immediates) {
                if (imm.offset != offset) {
                    continue;
                }
                if (imm.relative && imm.size == 4 && d.branchTarget == target) {
                    kind = ReferenceKind::Relative;
                } else if (!imm.relative && imm.size == 4 && (imm.value & 0xFFFFFFFFull) == target) {
                    kind = ReferenceKind::Absolute32;
                } else if (!imm.relative && imm.size == 8 && imm.value == target) {
                    kind = ReferenceKind::Absolute64;
                }
            }
            if (kind == ReferenceKind::None) {
                continue;
            }
            best = Reference{start, offset, d.length, kind, d.text};
        }
        return best;
    };

    for (const auto& [rangeStart, rangeEnd] : image_.codeRanges()) {
        const std::uint64_t first = rangeStart - base;
        const std::uint64_t stop = rangeEnd - base;
        for (std::uint64_t i = first; i + 4 <= stop && found.size() < cap; ++i) {
            const auto rel = static_cast<std::int64_t>(load<std::int32_t>(data + i));
            const std::uint64_t fieldAddress = base + i;
            bool candidate = false;
            // rel32 and RIP-relative: target = end + field, where the
            // instruction ends right after the field or after an immediate
            // of 1, 2 or 4 bytes that follows it ("cmp dword ptr [rip+x], 5").
            for (std::uint64_t tail : {0ull, 1ull, 2ull, 4ull}) {
                if (fieldAddress + 4 + tail + static_cast<std::uint64_t>(rel) == target) {
                    candidate = true;
                    break;
                }
            }
            if (!candidate && load<std::uint32_t>(data + i) == static_cast<std::uint32_t>(target) && (!x64 || target <= 0xFFFFFFFFull)) {
                candidate = true;
            }
            if (!candidate && x64 && i + 8 <= stop && load<std::uint64_t>(data + i) == target) {
                candidate = true;
            }
            if (!candidate || !image_.readable(fieldAddress, 4)) {
                continue;
            }
            if (auto reference = confirm(fieldAddress)) {
                const bool duplicate = std::any_of(found.begin(), found.end(), [&](const Reference& r) { return r.site == reference->site; });
                if (!duplicate) {
                    found.push_back(*reference);
                }
            }
        }
    }
    return found;
}

BuildResult Builder::references(std::uint64_t target, const BuildOptions& options) const {
    BuildResult result;
    const auto sites = findReferences(target, options.maxReferenceSites);
    if (sites.empty()) {
        result.error = "nothing in " + image_.module().name + " refers to " + hex(target) +
                       " by a call, a jump, a RIP-relative operand or an absolute address";
        return result;
    }
    std::vector<Signature> unique;
    for (const auto& site : sites) {
        Signature s = grow(site.site, options, site.length);
        if (!s.unique()) {
            continue;
        }
        s.mode = Mode::Reference;
        s.target = target;
        s.referenceKind = site.kind;
        s.fieldOffset = site.fieldOffset;
        s.instructionLength = site.length;
        unique.push_back(std::move(s));
    }
    if (unique.empty()) {
        result.error = std::to_string(sites.size()) + " reference" + (sites.size() == 1 ? "" : "s") + " found, but none is unique within " +
                       std::to_string(options.maxBytes) + " bytes";
        return result;
    }
    // Best first: one that stays inside its function, then one with enough
    // fixed bytes, then the shortest, then the fewest wildcards. A short
    // signature that reaches into the padding after a tail jump is worse than
    // a longer one that does not.
    const std::size_t floor = options.minFixedBytes;
    std::stable_sort(unique.begin(), unique.end(), [floor](const Signature& a, const Signature& b) {
        if (a.crossesFunctionEnd != b.crossesFunctionEnd) {
            return !a.crossesFunctionEnd;
        }
        const bool aThin = a.pattern.fixedCount() < floor;
        const bool bThin = b.pattern.fixedCount() < floor;
        if (aThin != bThin) {
            return !aThin;
        }
        if (a.pattern.size() != b.pattern.size()) {
            return a.pattern.size() < b.pattern.size();
        }
        return a.pattern.wildcardCount() < b.pattern.wildcardCount();
    });
    if (unique.size() > options.maxReferenceResults) {
        unique.resize(options.maxReferenceResults);
    }
    if (sites.size() >= options.maxReferenceSites) {
        result.notes.push_back("stopped after " + std::to_string(options.maxReferenceSites) + " references; there may be shorter ones.");
    }
    result.signatures = std::move(unique);
    return result;
}

BuildResult build(const MemoryView& view, std::uint64_t address, Mode mode, const BuildOptions& options, std::uint64_t selectionEnd) {
    BuildResult result;
    const auto module = view.moduleAt(address);
    if (!module) {
        result.error = "the address " + hex(address) + " is not inside a module. A signature is searched for within a module, so it needs one.";
        return result;
    }
    std::string error;
    auto image = ModuleImage::capture(view, *module, &error);
    if (!image) {
        result.error = "could not read " + module->name + ": " + error;
        return result;
    }
    const Builder builder(view, std::move(*image));
    switch (mode) {
    case Mode::Forward:
        return builder.forward(address, options);
    case Mode::Shortest:
        return builder.shortest(address, options);
    case Mode::Selection:
        return builder.selection(address, selectionEnd, options);
    case Mode::Reference:
        return builder.references(address, options);
    }
    return builder.forward(address, options);
}

} // namespace siglab
