#pragma once

#include "core/Builder.h"
#include "core/Pattern.h"

#include <string>

namespace siglab {

struct ReportOptions {
    Format primary = Format::X64dbg;
    bool allFormats = true;   // every form, not only the primary one
    bool instructions = true; // the disassembly the signature covers
};

// "ac_client.exe+0x29D1F"
[[nodiscard]] std::string moduleOffset(const std::string& moduleName, std::uint64_t moduleBase, std::uint64_t address);

// The text shown in the log and the dialog for one build. Plain text, lines
// separated by "\n"; the caller converts line endings for a Win32 edit box.
[[nodiscard]] std::string describe(const BuildResult& result, const ReportOptions& options);

// One signature in the primary format, for the clipboard.
[[nodiscard]] std::string clipboardText(const Signature& signature, Format primary);

} // namespace siglab
