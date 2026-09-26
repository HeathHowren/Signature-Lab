#include "core/Report.h"

#include <cstdio>

namespace siglab {

namespace {

std::string hex(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%llX", static_cast<unsigned long long>(value));
    return buffer;
}

// Indents every line after the first, so a two-line form lines up under its label.
std::string hang(const std::string& text, const std::string& indent) {
    std::string out;
    for (char c : text) {
        out += c;
        if (c == '\n') {
            out += indent;
        }
    }
    return out;
}

void line(std::string& out, const char* label, const std::string& value) {
    constexpr std::size_t kLabelWidth = 13;
    std::string padded = "  ";
    padded += label;
    while (padded.size() < kLabelWidth + 2) {
        padded += ' ';
    }
    out += padded;
    out += hang(value, std::string(kLabelWidth + 2, ' '));
    out += '\n';
}

std::string matchText(const Signature& s) {
    if (s.matches == 0) {
        return "no match";
    }
    if (s.matches == 1) {
        return "unique";
    }
    return std::to_string(s.matches) + (s.matches >= s.matchCap ? "+" : "") + " matches";
}

} // namespace

std::string moduleOffset(const std::string& moduleName, std::uint64_t moduleBase, std::uint64_t address) {
    if (moduleName.empty() || address < moduleBase) {
        return hex(address);
    }
    return moduleName + "+0x" + hex(address - moduleBase);
}

std::string clipboardText(const Signature& s, Format primary) {
    return format(s.pattern, primary, s.moduleName);
}

std::string describe(const BuildResult& result, const ReportOptions& options) {
    std::string out;
    if (!result.error.empty()) {
        out += result.error + "\n";
    }
    for (std::size_t n = 0; n < result.signatures.size(); ++n) {
        const Signature& s = result.signatures[n];
        if (n != 0) {
            out += '\n';
        }
        out += moduleOffset(s.moduleName, s.moduleBase, s.address) + " (" + hex(s.address) + ")  " + modeName(s.mode);
        if (s.mode == Mode::Reference) {
            out += " #" + std::to_string(n + 1) + " for " + moduleOffset(s.moduleName, s.moduleBase, s.target);
        }
        out += "  " + std::to_string(s.pattern.size()) + " bytes, " + std::to_string(s.pattern.wildcardCount()) + " wildcards, " +
               matchText(s) + "\n";

        line(out, formatName(options.primary), format(s.pattern, options.primary, s.moduleName));
        if (options.allFormats) {
            for (Format form : kAllFormats) {
                if (form != options.primary) {
                    line(out, formatName(form), format(s.pattern, form, s.moduleName));
                }
            }
        }
        const std::string wildcards = s.wildcardSummary();
        line(out, "wildcards", wildcards.empty() ? std::string("none") : wildcards);
        if (s.crossesFunctionEnd) {
            line(out, "caution", "runs past the end of the function; a rebuild may move what follows it");
        }
        if (s.referenceKind != ReferenceKind::None) {
            line(out, "resolve", "target = " + s.resolution());
        }
        if (options.instructions && !s.instructions.empty()) {
            out += "  instructions\n";
            for (const auto& instruction : s.instructions) {
                out += "    " + hex(instruction.address) + "  " + instruction.text + "\n";
            }
        }
    }
    for (const auto& note : result.notes) {
        out += "  note: " + note + "\n";
    }
    return out;
}

} // namespace siglab
