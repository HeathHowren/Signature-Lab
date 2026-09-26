#pragma once

#include "core/Builder.h"
#include "core/Pattern.h"

namespace siglab::plugin {

struct PluginSettings {
    BuildOptions options;
    Format format = Format::X64dbg; // what goes on the clipboard
    bool logAllFormats = true;
    bool logInstructions = true;

    bool operator==(const PluginSettings&) const = default;
};

// Stored in x64dbg's own ini, section [Signature Lab], so the plugin has no
// file of its own to lose or to leave behind when it is removed. Missing or
// malformed keys fall back to the defaults above one by one.
[[nodiscard]] PluginSettings loadSettings();
void saveSettings(const PluginSettings& settings);

} // namespace siglab::plugin
