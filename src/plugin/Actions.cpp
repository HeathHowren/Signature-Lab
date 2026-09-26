#include "plugin/Actions.h"

#include "core/ModuleImage.h"
#include "core/Report.h"
#include "plugin/BridgeMemoryView.h"
#include "plugin/Clipboard.h"
#include "plugin/Sdk.h"

#include <cstdio>

namespace siglab::plugin {

std::string hexAddress(std::uint64_t address) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(address));
    return buffer;
}

BuildResult runBuild(std::uint64_t address, Mode mode, std::uint64_t selectionEnd, const PluginSettings& settings) {
    const BridgeMemoryView view;
    return build(view, address, mode, settings.options, selectionEnd);
}

void reportBuild(const BuildResult& result, const PluginSettings& settings, bool copy) {
    ReportOptions options;
    options.primary = settings.format;
    options.allFormats = settings.logAllFormats;
    options.instructions = settings.logInstructions;
    std::string text = "[Signature Lab] " + describe(result, options);

    // A signature that is not unique is still copied from a selection,
    // where the user chose the bytes and asked for their count. From the
    // other modes it is not: pasting a pattern that matches twice into a
    // scanner is how a trainer ends up patching the wrong function.
    if (copy && result.ok()) {
        const Signature& s = result.signatures.front();
        if (s.unique() || s.mode == Mode::Selection) {
            if (copyToClipboard(clipboardText(s, settings.format))) {
                text += "  copied       " + std::string(formatName(settings.format)) + " form to the clipboard\n";
            } else {
                text += "  note: the clipboard was busy; nothing was copied\n";
            }
        } else {
            text += "  not copied: the signature is not unique\n";
        }
    }
    _plugin_logprint(text.c_str());
}

TestResult testPattern(std::string_view text, std::uint64_t moduleAddress, std::size_t cap) {
    TestResult result;
    result.cap = cap;
    auto pattern = parse(text);
    if (!pattern) {
        result.error = "not a pattern Signature Lab can read. It accepts \"48 8B ?? 05\", \"48 8B ? 05\", "
                       "\"\\x48\\x8B\\x00\\x05\" with an \"xx?x\" mask, a C array, or an aobscanmodule(...) line; "
                       "a mask must be as long as the pattern.";
        return result;
    }
    result.pattern = std::move(*pattern);
    const BridgeMemoryView view;
    const auto module = view.moduleAt(moduleAddress);
    if (!module) {
        result.error = "there is no module at " + hexAddress(moduleAddress) + " to search";
        return result;
    }
    std::string error;
    const auto image = ModuleImage::capture(view, *module, &error);
    if (!image) {
        result.error = "could not read " + module->name + ": " + error;
        return result;
    }
    result.moduleName = module->name;
    result.moduleBase = module->base;
    result.matches = image->find(result.pattern, cap);
    return result;
}

std::string describeTest(const TestResult& r, std::size_t listed) {
    if (!r.error.empty()) {
        return "[Signature Lab] " + r.error + "\n";
    }
    std::string out = "[Signature Lab] " + format(r.pattern, Format::X64dbg) + "\n  ";
    if (r.matches.empty()) {
        out += "no match in " + r.moduleName + "\n";
        return out;
    }
    if (r.matches.size() == 1) {
        out += "unique in " + r.moduleName + "\n";
    } else {
        out += std::to_string(r.matches.size()) + (r.matches.size() >= r.cap ? "+" : "") + " matches in " + r.moduleName + "\n";
    }
    for (std::size_t i = 0; i < r.matches.size() && i < listed; ++i) {
        out += "    " + moduleOffset(r.moduleName, r.moduleBase, r.matches[i]) + "\n";
    }
    if (r.matches.size() > listed) {
        out += "    ... " + std::to_string(r.matches.size() - listed) + " more\n";
    }
    return out;
}

void showInReferences(const TestResult& r) {
    if (!r.error.empty()) {
        return;
    }
    const std::string title = "Signature Lab: " + format(r.pattern, Format::X64dbg);
    GuiReferenceInitialize(title.c_str());
    GuiReferenceAddColumn(2 * static_cast<int>(sizeof(duint)), "Address");
    GuiReferenceAddColumn(40, "Module offset");
    GuiReferenceAddColumn(60, "Disassembly");
    GuiReferenceSetRowCount(static_cast<int>(r.matches.size()));
    for (std::size_t i = 0; i < r.matches.size(); ++i) {
        const int row = static_cast<int>(i);
        char address[32];
        std::snprintf(address, sizeof(address), sizeof(duint) == 8 ? "%016llX" : "%08llX", static_cast<unsigned long long>(r.matches[i]));
        GuiReferenceSetCellContent(row, 0, address);
        GuiReferenceSetCellContent(row, 1, moduleOffset(r.moduleName, r.moduleBase, r.matches[i]).c_str());
        DISASM_INSTR instruction{};
        DbgDisasmAt(static_cast<duint>(r.matches[i]), &instruction);
        GuiReferenceSetCellContent(row, 2, instruction.instruction);
    }
    GuiReferenceReloadData();
}

std::optional<std::uint64_t> disassemblySelectionStart() {
    if (!DbgIsDebugging()) {
        return std::nullopt;
    }
    SELECTIONDATA selection{};
    if (!GuiSelectionGet(GUI_DISASSEMBLY, &selection)) {
        return std::nullopt;
    }
    return selection.start;
}

} // namespace siglab::plugin
