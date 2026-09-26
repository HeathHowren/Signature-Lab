// Signature Lab: the x64dbg entry points. Menus, hotkeys and commands are
// thin; every one of them ends in plugin/Actions.cpp.

#include "Version.h"
#include "plugin/Actions.h"
#include "plugin/Clipboard.h"
#include "plugin/Dialog.h"
#include "plugin/Sdk.h"
#include "resource.h"

#include <cctype>
#include <cstring>
#include <string>

namespace siglab::plugin {
int g_pluginHandle = 0;
HINSTANCE g_instance = nullptr;
} // namespace siglab::plugin

namespace {

using namespace siglab;
using namespace siglab::plugin;

// Menu entry ids. The labels and hotkeys they carry are pinned for the 1.x
// series: The Game Hacker's Handbook quotes them.
enum MenuEntry : int {
    kMakeSignature = 1,
    kMakeShortest,
    kMakeFromSelection,
    kMakeReference,
    kDisasmDialog,
    kDumpReference,
    kMainDialog,
    kMainTestClipboard,
    kMainAbout,
};

constexpr const char* kSigmakeUsage = "[Signature Lab] usage: sigmake address[, forward|shortest|selection|reference[, end]]\n";

void log(const std::string& text) {
    _plugin_logprint(text.c_str());
}

std::string trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
    }
    return std::string(text);
}

// Every failure path goes through here, so a failed command never leaves the
// previous command's $result behind for a script to read as this one's. It is
// cleared only after the arguments are evaluated: "find ...; sigmake $result"
// is the natural script, and clearing first would sign address 0.
bool fail(const std::string& message) {
    DbgValSetScalar("$result", 0);
    log(message);
    return false;
}

bool evaluate(const char* expression, duint& value) {
    bool ok = false;
    value = DbgEval(trim(expression).c_str(), &ok);
    return ok;
}

bool selection(GUISELECTIONTYPE window, SELECTIONDATA& data) {
    if (!DbgIsDebugging()) {
        log("[Signature Lab] nothing is being debugged.\n");
        return false;
    }
    if (!GuiSelectionGet(window, &data)) {
        log("[Signature Lab] could not read the selection.\n");
        return false;
    }
    return true;
}

// Menu entries queue a command instead of doing the work themselves: the
// command runs on x64dbg's command thread, so the window does not freeze
// while a large module is read and searched, and the log shows exactly what
// was run, which a script can then copy.
void queue(const std::string& command) {
    DbgCmdExec(command.c_str());
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

bool runSigmake(duint address, Mode mode, duint end) {
    const PluginSettings settings = loadSettings();
    const BuildResult result = runBuild(address, mode, end, settings);
    reportBuild(result, settings, true);
    duint value = 0;
    if (result.ok()) {
        value = mode == Mode::Reference ? static_cast<duint>(result.signatures.size()) : static_cast<duint>(result.signatures.front().matches);
    }
    DbgValSetScalar("$result", value);
    return result.ok();
}

bool cmdSigmake(int argc, char** argv) {
    if (argc < 2) {
        return fail(kSigmakeUsage);
    }
    duint address = 0;
    if (!evaluate(argv[1], address)) {
        return fail("[Signature Lab] cannot evaluate \"" + trim(argv[1]) + "\".\n");
    }
    Mode mode = Mode::Forward;
    if (argc >= 3) {
        const auto parsed = modeFromName(trim(argv[2]));
        if (!parsed) {
            return fail(kSigmakeUsage);
        }
        mode = *parsed;
    }
    duint end = address;
    if (mode == Mode::Selection) {
        if (argc < 4 || !evaluate(argv[3], end)) {
            return fail("[Signature Lab] selection mode needs an end address: sigmake start, selection, end\n");
        }
    }
    return runSigmake(address, mode, end);
}

bool cmdSigxref(int argc, char** argv) {
    if (argc < 2) {
        return fail("[Signature Lab] usage: sigxref address\n");
    }
    duint address = 0;
    if (!evaluate(argv[1], address)) {
        return fail("[Signature Lab] cannot evaluate \"" + trim(argv[1]) + "\".\n");
    }
    return runSigmake(address, Mode::Reference, address);
}

bool runTest(const std::string& pattern) {
    std::optional<std::uint64_t> where = disassemblySelectionStart();
    if (!where) {
        return fail("[Signature Lab] nothing is being debugged.\n");
    }
    const TestResult result = testPattern(pattern, *where);
    log(describeTest(result));
    showInReferences(result);
    DbgValSetScalar("$result", static_cast<duint>(result.matches.size()));
    return result.error.empty();
}

bool cmdSigtest(int argc, char** argv) {
    if (argc < 2) {
        return fail("[Signature Lab] usage: sigtest pattern   (searches the module shown in the disassembly view)\n");
    }
    // x64dbg splits arguments at commas, and a C array is full of them, so
    // the pieces are joined back into the text that was typed.
    std::string pattern;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) {
            pattern += ',';
        }
        pattern += argv[i];
    }
    return runTest(pattern);
}

// ---------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------

void about() {
    const std::wstring body = widen(std::string(SIGLAB_PRODUCT_NAME " " SIGLAB_VERSION_STRING "\n\n"
                                                "A signature maker for x64dbg: operand-aware wildcards, a whole-module "
                                                "uniqueness check, and reference signatures.\n\n"
                                                "By Heath Howren (Cyborg Elf), Game Reversal Club.\n"
                                                "Companion tool to The Game Hacker's Handbook.\n\n" SIGLAB_HOME_URL "\n" SIGLAB_REPO_URL
                                                "\n\n" SIGLAB_COPYRIGHT "\nDisassembly by Zydis (MIT)."));
    MessageBoxW(GuiGetWindowHandle(), body.c_str(), L"About Signature Lab", MB_OK | MB_ICONINFORMATION);
}

void onMenuEntry(CBTYPE, void* info) {
    const auto* entry = static_cast<PLUG_CB_MENUENTRY*>(info);
    SELECTIONDATA data{};
    switch (entry->hEntry) {
    case kMakeSignature:
        if (selection(GUI_DISASSEMBLY, data)) {
            queue("sigmake " + hexAddress(data.start) + ", forward");
        }
        break;
    case kMakeShortest:
        if (selection(GUI_DISASSEMBLY, data)) {
            queue("sigmake " + hexAddress(data.start) + ", shortest");
        }
        break;
    case kMakeFromSelection:
        if (selection(GUI_DISASSEMBLY, data)) {
            queue("sigmake " + hexAddress(data.start) + ", selection, " + hexAddress(data.end));
        }
        break;
    case kMakeReference:
        if (selection(GUI_DISASSEMBLY, data)) {
            queue("sigxref " + hexAddress(data.start));
        }
        break;
    case kDumpReference:
        if (selection(GUI_DUMP, data)) {
            queue("sigxref " + hexAddress(data.start));
        }
        break;
    case kDisasmDialog:
    case kMainDialog:
        if (selection(GUI_DISASSEMBLY, data)) {
            showDialog(data.start, data.end);
        }
        break;
    case kMainTestClipboard: {
        const std::string text = clipboardText();
        if (text.empty()) {
            log("[Signature Lab] the clipboard holds no text to test.\n");
        } else {
            runTest(text);
        }
        break;
    }
    case kMainAbout:
        about();
        break;
    default:
        break;
    }
}

void setIcon(int menu) {
    const HRSRC resource = FindResourceW(g_instance, MAKEINTRESOURCEW(IDR_MENU_ICON), RT_RCDATA);
    if (resource == nullptr) {
        return;
    }
    const HGLOBAL loaded = LoadResource(g_instance, resource);
    if (loaded == nullptr) {
        return;
    }
    ICONDATA icon{};
    icon.data = LockResource(loaded);
    icon.size = SizeofResource(g_instance, resource);
    if (icon.data != nullptr) {
        _plugin_menuseticon(menu, &icon);
    }
}

void addEntry(int menu, MenuEntry id, const char* title, const char* hotkey = nullptr) {
    _plugin_menuaddentry(menu, id, title);
    if (hotkey != nullptr) {
        _plugin_menuentrysethotkey(g_pluginHandle, id, hotkey);
    }
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* init) {
    init->pluginVersion = SIGLAB_VERSION_MAJOR;
    init->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(init->pluginName, sizeof(init->pluginName), kPluginName, _TRUNCATE);
    g_pluginHandle = init->pluginHandle;

    _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, onMenuEntry);
    const bool registered = _plugin_registercommand(g_pluginHandle, "sigmake", cmdSigmake, true) &&
                            _plugin_registercommand(g_pluginHandle, "sigxref", cmdSigxref, true) &&
                            _plugin_registercommand(g_pluginHandle, "sigtest", cmdSigtest, true);
    if (!registered) {
        log("[Signature Lab] a command name is already taken by another plugin; some commands are unavailable.\n");
    }
    log("[Signature Lab] " SIGLAB_VERSION_STRING " loaded. Right-click an instruction, Signature Lab, or press Alt+Shift+S.\n");
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setup) {
    addEntry(setup->hMenuDisasm, kMakeSignature, "Make signature", "Alt+Shift+S");
    addEntry(setup->hMenuDisasm, kMakeShortest, "Make shortest signature", "Ctrl+Alt+Shift+S");
    addEntry(setup->hMenuDisasm, kMakeFromSelection, "Make signature from selection");
    addEntry(setup->hMenuDisasm, kMakeReference, "Make reference signature", "Alt+Shift+R");
    _plugin_menuaddseparator(setup->hMenuDisasm);
    addEntry(setup->hMenuDisasm, kDisasmDialog, "Signature Lab...");

    addEntry(setup->hMenuDump, kDumpReference, "Make reference signature");

    addEntry(setup->hMenu, kMainDialog, "Signature Lab...");
    addEntry(setup->hMenu, kMainTestClipboard, "Test signature from clipboard");
    _plugin_menuaddseparator(setup->hMenu);
    addEntry(setup->hMenu, kMainAbout, "About");

    setIcon(setup->hMenu);
    setIcon(setup->hMenuDisasm);
    setIcon(setup->hMenuDump);
}

PLUG_EXPORT bool plugstop() {
    _plugin_unregistercallback(g_pluginHandle, CB_MENUENTRY);
    _plugin_unregistercommand(g_pluginHandle, "sigmake");
    _plugin_unregistercommand(g_pluginHandle, "sigxref");
    _plugin_unregistercommand(g_pluginHandle, "sigtest");
    return true;
}
