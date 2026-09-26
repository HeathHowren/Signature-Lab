#include "plugin/Settings.h"

#include "plugin/Sdk.h"

#include <algorithm>

namespace siglab::plugin {

namespace {

constexpr const char* kSection = "Signature Lab";

void loadBool(const char* key, bool& value) {
    duint stored = 0;
    if (BridgeSettingGetUint(kSection, key, &stored)) {
        value = stored != 0;
    }
}

void saveBool(const char* key, bool value) {
    BridgeSettingSetUint(kSection, key, value ? 1 : 0);
}

} // namespace

PluginSettings loadSettings() {
    PluginSettings s;
    WildcardPolicy& p = s.options.policy;
    loadBool("WildcardBranchRel32", p.branchRel32);
    loadBool("WildcardBranchRel8", p.branchRel8);
    loadBool("WildcardRipRelative", p.ripRelative);
    loadBool("WildcardAbsoluteAddress", p.absoluteAddress);
    loadBool("WildcardPointerImmediate", p.pointerImmediate);
    loadBool("WildcardStructOffset", p.structOffset);
    loadBool("WildcardLargeImmediate", p.largeImmediate);
    loadBool("LogAllFormats", s.logAllFormats);
    loadBool("LogInstructions", s.logInstructions);

    duint number = 0;
    if (BridgeSettingGetUint(kSection, "MaxBytes", &number) && number >= 4) {
        s.options.maxBytes = std::min<std::size_t>(static_cast<std::size_t>(number), 1024);
    }
    if (BridgeSettingGetUint(kSection, "MinFixedBytes", &number)) {
        s.options.minFixedBytes = std::min<std::size_t>(static_cast<std::size_t>(number), 64);
    }
    char text[MAX_SETTING_SIZE] = {};
    if (BridgeSettingGet(kSection, "Format", text)) {
        if (auto form = formatFromName(text)) {
            s.format = *form;
        }
    }
    return s;
}

void saveSettings(const PluginSettings& s) {
    const WildcardPolicy& p = s.options.policy;
    saveBool("WildcardBranchRel32", p.branchRel32);
    saveBool("WildcardBranchRel8", p.branchRel8);
    saveBool("WildcardRipRelative", p.ripRelative);
    saveBool("WildcardAbsoluteAddress", p.absoluteAddress);
    saveBool("WildcardPointerImmediate", p.pointerImmediate);
    saveBool("WildcardStructOffset", p.structOffset);
    saveBool("WildcardLargeImmediate", p.largeImmediate);
    saveBool("LogAllFormats", s.logAllFormats);
    saveBool("LogInstructions", s.logInstructions);
    BridgeSettingSetUint(kSection, "MaxBytes", static_cast<duint>(s.options.maxBytes));
    BridgeSettingSetUint(kSection, "MinFixedBytes", static_cast<duint>(s.options.minFixedBytes));
    BridgeSettingSet(kSection, "Format", formatName(s.format));
    BridgeSettingFlush();
}

} // namespace siglab::plugin
