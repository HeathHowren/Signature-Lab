#pragma once

#include "core/Builder.h"
#include "plugin/Settings.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace siglab::plugin {

// The work behind every entry point. The menu entries queue a command, the
// commands call these, and the dialog calls them directly, so the three
// routes cannot drift apart.

[[nodiscard]] BuildResult runBuild(std::uint64_t address, Mode mode, std::uint64_t selectionEnd, const PluginSettings& settings);

// Writes the report to the x64dbg log and, when `copy` is set and the build
// produced something worth pasting, puts the primary form on the clipboard.
void reportBuild(const BuildResult& result, const PluginSettings& settings, bool copy);

struct TestResult {
    std::string error;
    Pattern pattern;
    std::string moduleName;
    std::uint64_t moduleBase = 0;
    std::vector<std::uint64_t> matches;
    std::size_t cap = 0;
};

// Counts where a pattern, in any form Signature Lab can parse, matches in the
// module that contains `moduleAddress`.
[[nodiscard]] TestResult testPattern(std::string_view text, std::uint64_t moduleAddress, std::size_t cap = 1000);
[[nodiscard]] std::string describeTest(const TestResult& result, std::size_t listed = 20);
// Lists the matches in x64dbg's References view, where each row can be
// double-clicked to follow it.
void showInReferences(const TestResult& result);

// The start of the disassembly selection, or nothing when not debugging.
[[nodiscard]] std::optional<std::uint64_t> disassemblySelectionStart();

// "0x" + hex, the form x64dbg's expression parser accepts back.
[[nodiscard]] std::string hexAddress(std::uint64_t address);

} // namespace siglab::plugin
