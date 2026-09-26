#include "core/Pattern.h"

#include <algorithm>
#include <cctype>

namespace siglab {

namespace {

constexpr char kHexDigits[] = "0123456789ABCDEF";

int hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

void appendHex(std::string& out, std::uint8_t byte) {
    out += kHexDigits[byte >> 4];
    out += kHexDigits[byte & 0x0F];
}

bool isSeparator(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',';
}

// The x64dbg spelling: whole bytes as hex, wildcards as "??", nibbles as "4?".
std::string spellX64dbg(const Pattern& p) {
    std::string out;
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        const std::uint8_t m = p.mask[i];
        const std::uint8_t b = p.bytes[i];
        if (m == 0xFF) {
            appendHex(out, b);
        } else if (m == 0xF0) {
            out += kHexDigits[b >> 4];
            out += '?';
        } else if (m == 0x0F) {
            out += '?';
            out += kHexDigits[b & 0x0F];
        } else {
            out += "??";
        }
    }
    return out;
}

// The IDA spelling has no nibble form, so a nibble mask degrades to a whole
// wildcard byte. That loses information but never produces a pattern that
// fails to match where the original did.
std::string spellIda(const Pattern& p) {
    std::string out;
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        if (p.mask[i] == 0xFF) {
            appendHex(out, p.bytes[i]);
        } else {
            out += '?';
        }
    }
    return out;
}

std::string spellMaskString(const Pattern& p) {
    std::string out;
    out.reserve(p.size());
    for (std::size_t i = 0; i < p.size(); ++i) {
        out += p.mask[i] == 0xFF ? 'x' : '?';
    }
    return out;
}

std::string spellCodeMask(const Pattern& p) {
    std::string out = "\"";
    for (std::size_t i = 0; i < p.size(); ++i) {
        out += "\\x";
        appendHex(out, p.mask[i] == 0xFF ? p.bytes[i] : std::uint8_t{0});
    }
    out += "\"\n\"";
    out += spellMaskString(p);
    out += '"';
    return out;
}

std::string spellCppArray(const Pattern& p) {
    std::string out = "const unsigned char sig[] = { ";
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += "0x";
        appendHex(out, p.mask[i] == 0xFF ? p.bytes[i] : std::uint8_t{0});
    }
    out += " };\nconst char mask[] = \"";
    out += spellMaskString(p);
    out += "\";";
    return out;
}

std::string spellPointerLab(const Pattern& p, std::string_view moduleName, std::string_view symbol) {
    // Pointer Lab's parser accepts '?' and '??' but not nibble wildcards, so a
    // nibble mask is widened to a whole byte here as in the IDA form.
    std::string out = "aobscanmodule(";
    out += symbol.empty() ? std::string_view{"INJECT"} : symbol;
    out += ", ";
    out += moduleName.empty() ? std::string_view{"module.exe"} : moduleName;
    out += ", ";
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        if (p.mask[i] == 0xFF) {
            appendHex(out, p.bytes[i]);
        } else {
            out += "??";
        }
    }
    out += ')';
    return out;
}

// Hex pairs with '?' wildcards, optionally with no separators at all.
std::optional<Pattern> parseHex(std::string_view text) {
    Pattern p;
    std::size_t i = 0;
    const std::size_t n = text.size();
    while (i < n) {
        const char c = text[i];
        if (isSeparator(c)) {
            ++i;
            continue;
        }
        const bool hasNext = i + 1 < n;
        const char next = hasNext ? text[i + 1] : '\0';
        if (c == '?') {
            if (hasNext && next == '?') {
                p.append(0, 0x00, ByteReason::Opcode);
                i += 2;
            } else if (hasNext && hexValue(next) >= 0) {
                p.append(static_cast<std::uint8_t>(hexValue(next)), 0x0F, ByteReason::Opcode);
                i += 2;
            } else {
                p.append(0, 0x00, ByteReason::Opcode);
                i += 1;
            }
            continue;
        }
        const int hi = hexValue(c);
        if (hi < 0) {
            return std::nullopt;
        }
        if (hasNext && hexValue(next) >= 0) {
            p.append(static_cast<std::uint8_t>((hi << 4) | hexValue(next)), 0xFF, ByteReason::Opcode);
            i += 2;
        } else if (hasNext && next == '?') {
            p.append(static_cast<std::uint8_t>(hi << 4), 0xF0, ByteReason::Opcode);
            i += 2;
        } else {
            // A lone hex digit is a typo, not half a byte.
            return std::nullopt;
        }
    }
    if (p.empty()) {
        return std::nullopt;
    }
    p.reasons.clear();
    return p;
}

// Looks for the mask that goes with `count` parsed bytes in text from which
// every byte token has already been blanked out: a run of 'x' and '?' or a
// "0b0110..." bitmask (1 = compare) of exactly `count` characters.
//
// A mask of the wrong length is an error rather than something to ignore.
// The Handbook's own chapter 14 once printed a 15-character mask under a
// 13-byte pattern, and a parser that quietly compared every byte instead
// would report "not found" with no hint why.
struct MaskSearch {
    bool present = false;
    std::optional<std::vector<std::uint8_t>> mask;
};

MaskSearch findMask(std::string_view blanked, std::size_t count) {
    MaskSearch search;
    std::size_t i = 0;
    const std::size_t n = blanked.size();
    while (i < n) {
        std::vector<std::uint8_t> run;
        std::size_t j = i;
        if (blanked[i] == '0' && i + 1 < n && (blanked[i + 1] == 'b' || blanked[i + 1] == 'B')) {
            j = i + 2;
            while (j < n && (blanked[j] == '0' || blanked[j] == '1')) {
                run.push_back(blanked[j] == '1' ? 0xFF : 0x00);
                ++j;
            }
        } else if (blanked[i] == 'x' || blanked[i] == '?') {
            while (j < n && (blanked[j] == 'x' || blanked[j] == '?')) {
                run.push_back(blanked[j] == 'x' ? 0xFF : 0x00);
                ++j;
            }
        }
        if (run.size() >= 2) {
            search.present = true;
            if (run.size() == count && !search.mask) {
                search.mask = std::move(run);
            }
        }
        i = j > i ? j : i + 1;
    }
    return search;
}

// Applies the mask found in the text: the right-length one if there is one,
// every byte compared if there is none, failure if there is only a wrong one.
bool applyMask(Pattern& p, std::string_view blanked) {
    MaskSearch search = findMask(blanked, p.size());
    if (search.mask) {
        p.mask = std::move(*search.mask);
        return true;
    }
    return !search.present;
}

// "\x48\x8B..." optionally followed by an "xxx????" mask.
std::optional<Pattern> parseCodeStyle(std::string_view text) {
    Pattern p;
    std::string blanked(text);
    for (std::size_t i = 0; i + 3 < text.size(); ++i) {
        if (text[i] == '\\' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            const int hi = hexValue(text[i + 2]);
            const int lo = hexValue(text[i + 3]);
            if (hi < 0 || lo < 0) {
                return std::nullopt;
            }
            p.append(static_cast<std::uint8_t>((hi << 4) | lo), 0xFF, ByteReason::Opcode);
            blanked[i] = blanked[i + 1] = blanked[i + 2] = blanked[i + 3] = ' ';
            i += 3;
        }
    }
    if (p.empty()) {
        return std::nullopt;
    }
    if (!applyMask(p, blanked)) {
        return std::nullopt;
    }
    p.reasons.clear();
    return p;
}

// "{ 0x48, 0x8B, ... }" optionally followed by an "xxx????" mask or a bitmask.
std::optional<Pattern> parseCArray(std::string_view text) {
    Pattern p;
    std::string blanked(text);
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X') && hexValue(text[i + 2]) >= 0) {
            int value = hexValue(text[i + 2]);
            std::size_t end = i + 3;
            if (end < text.size() && hexValue(text[end]) >= 0) {
                value = (value << 4) | hexValue(text[end]);
                ++end;
            }
            if (end < text.size() && hexValue(text[end]) >= 0) {
                // 0x123 is not a byte.
                return std::nullopt;
            }
            p.append(static_cast<std::uint8_t>(value), 0xFF, ByteReason::Opcode);
            for (std::size_t k = i; k < end; ++k) {
                blanked[k] = ' ';
            }
            i = end - 1;
        }
    }
    if (p.empty()) {
        return std::nullopt;
    }
    if (!applyMask(p, blanked)) {
        return std::nullopt;
    }
    p.reasons.clear();
    return p;
}

} // namespace

const char* reasonName(ByteReason reason) {
    switch (reason) {
    case ByteReason::Opcode:
        return "opcode";
    case ByteReason::Immediate:
        return "immediate";
    case ByteReason::LargeImmediate:
        return "large immediate";
    case ByteReason::StructOffset:
        return "struct offset";
    case ByteReason::BranchRel8:
        return "short branch target";
    case ByteReason::BranchRel32:
        return "branch target";
    case ByteReason::RipRelative:
        return "RIP-relative displacement";
    case ByteReason::AbsoluteAddress:
        return "absolute address";
    case ByteReason::PointerImmediate:
        return "pointer immediate";
    case ByteReason::Undecodable:
        return "undecodable";
    }
    return "unknown";
}

const char* formatName(Format form) {
    switch (form) {
    case Format::X64dbg:
        return "x64dbg";
    case Format::Ida:
        return "IDA";
    case Format::CodeMask:
        return "code+mask";
    case Format::CppArray:
        return "C++ array";
    case Format::PointerLab:
        return "Pointer Lab";
    }
    return "unknown";
}

std::optional<Format> formatFromName(std::string_view name) {
    std::string lower;
    lower.reserve(name.size());
    for (char c : name) {
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (lower == "x64dbg" || lower == "x32dbg" || lower == "dbg") {
        return Format::X64dbg;
    }
    if (lower == "ida") {
        return Format::Ida;
    }
    if (lower == "code+mask" || lower == "code" || lower == "mask" || lower == "codemask") {
        return Format::CodeMask;
    }
    if (lower == "c++ array" || lower == "cpp" || lower == "c" || lower == "array" || lower == "cpparray") {
        return Format::CppArray;
    }
    if (lower == "pointer lab" || lower == "pointerlab" || lower == "pl" || lower == "aob" || lower == "aobscanmodule") {
        return Format::PointerLab;
    }
    return std::nullopt;
}

std::size_t Pattern::wildcardCount() const {
    return static_cast<std::size_t>(std::count_if(mask.begin(), mask.end(), [](std::uint8_t m) { return m != 0xFF; }));
}

bool Pattern::hasNibbleMask() const {
    return std::any_of(mask.begin(), mask.end(), [](std::uint8_t m) { return m != 0xFF && m != 0x00; });
}

Pattern Pattern::prefix(std::size_t count) const {
    Pattern out;
    count = std::min(count, size());
    out.bytes.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(count));
    out.mask.assign(mask.begin(), mask.begin() + static_cast<std::ptrdiff_t>(count));
    if (hasReasons()) {
        out.reasons.assign(reasons.begin(), reasons.begin() + static_cast<std::ptrdiff_t>(count));
    }
    return out;
}

void Pattern::append(std::uint8_t byte, std::uint8_t maskByte, ByteReason reason) {
    bytes.push_back(byte);
    mask.push_back(maskByte);
    reasons.push_back(reason);
}

void Pattern::append(const Pattern& other) {
    bytes.insert(bytes.end(), other.bytes.begin(), other.bytes.end());
    mask.insert(mask.end(), other.mask.begin(), other.mask.end());
    if (other.hasReasons()) {
        reasons.insert(reasons.end(), other.reasons.begin(), other.reasons.end());
    }
}

void Pattern::trimTrailingWildcards() {
    while (!mask.empty() && mask.back() == 0) {
        mask.pop_back();
        bytes.pop_back();
        if (!reasons.empty()) {
            reasons.pop_back();
        }
    }
}

void Pattern::clear() {
    bytes.clear();
    mask.clear();
    reasons.clear();
}

std::string format(const Pattern& pattern, Format form, std::string_view moduleName, std::string_view symbol) {
    switch (form) {
    case Format::X64dbg:
        return spellX64dbg(pattern);
    case Format::Ida:
        return spellIda(pattern);
    case Format::CodeMask:
        return spellCodeMask(pattern);
    case Format::CppArray:
        return spellCppArray(pattern);
    case Format::PointerLab:
        return spellPointerLab(pattern, moduleName, symbol);
    }
    return spellX64dbg(pattern);
}

std::optional<Pattern> parse(std::string_view text) {
    while (!text.empty() && isSeparator(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && isSeparator(text.back())) {
        text.remove_suffix(1);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    if (text.find("\\x") != std::string_view::npos || text.find("\\X") != std::string_view::npos) {
        return parseCodeStyle(text);
    }
    // A Pointer Lab line: the pattern is the last argument inside the parentheses.
    if (text.rfind("aobscan", 0) == 0) {
        const auto open = text.find('(');
        const auto close = text.rfind(')');
        if (open == std::string_view::npos || close == std::string_view::npos || close <= open) {
            return std::nullopt;
        }
        std::string_view inner = text.substr(open + 1, close - open - 1);
        const auto lastComma = inner.rfind(',');
        if (lastComma != std::string_view::npos) {
            inner = inner.substr(lastComma + 1);
        }
        return parseHex(inner);
    }
    if (text.find("0x") != std::string_view::npos || text.find("0X") != std::string_view::npos) {
        return parseCArray(text);
    }
    return parseHex(text);
}

std::string hexBytes(const std::uint8_t* data, std::size_t size) {
    std::string out;
    out.reserve(size * 3);
    for (std::size_t i = 0; i < size; ++i) {
        if (i != 0) {
            out += ' ';
        }
        appendHex(out, data[i]);
    }
    return out;
}

} // namespace siglab
