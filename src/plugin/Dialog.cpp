#include "plugin/Dialog.h"

#include "Version.h"
#include "core/Report.h"
#include "plugin/Actions.h"
#include "plugin/Clipboard.h"
#include "plugin/Sdk.h"
#include "resource.h"

#include <commctrl.h>

#include <memory>
#include <string>

// Common Controls 6, so the dialog's buttons and check boxes are drawn in
// the current Windows style rather than the Windows 2000 one. The linker
// embeds this as the DLL's resource 2, and showDialog activates it.
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' "   \
                        "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace siglab::plugin {

namespace {

constexpr Mode kModes[] = {Mode::Forward, Mode::Shortest, Mode::Selection, Mode::Reference};
constexpr const wchar_t* kModeLabels[] = {L"Forward (grow until unique)", L"Shortest unique", L"Exactly the selection",
                                          L"Reference (sign the code that uses it)"};

struct State {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    PluginSettings settings;
    BuildResult last;
    HFONT mono = nullptr;
};

State* state(HWND dialog) {
    return reinterpret_cast<State*>(GetWindowLongPtrW(dialog, DWLP_USER));
}

std::wstring text(HWND dialog, int id) {
    const HWND control = GetDlgItem(dialog, id);
    const int length = GetWindowTextLengthW(control);
    std::wstring out(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(control, out.data(), length + 1);
    out.resize(static_cast<std::size_t>(length));
    return out;
}

// Win32 edit controls want CRLF.
std::wstring forEdit(const std::string& utf8) {
    std::string crlf;
    crlf.reserve(utf8.size() + utf8.size() / 16);
    for (char c : utf8) {
        if (c == '\n') {
            crlf += '\r';
        }
        crlf += c;
    }
    return widen(crlf);
}

void setOutput(HWND dialog, const std::string& utf8) {
    SetDlgItemTextW(dialog, IDC_OUTPUT, forEdit(utf8).c_str());
}

void setStatus(HWND dialog, const std::wstring& message) {
    SetDlgItemTextW(dialog, IDC_FOOTER, message.c_str());
}

void check(HWND dialog, int id, bool on) {
    CheckDlgButton(dialog, id, on ? BST_CHECKED : BST_UNCHECKED);
}

bool checked(HWND dialog, int id) {
    return IsDlgButtonChecked(dialog, id) == BST_CHECKED;
}

Mode selectedMode(HWND dialog) {
    const auto index = SendDlgItemMessageW(dialog, IDC_MODE, CB_GETCURSEL, 0, 0);
    return index >= 0 && index < static_cast<LRESULT>(std::size(kModes)) ? kModes[index] : Mode::Forward;
}

Format selectedFormat(HWND dialog) {
    const auto index = SendDlgItemMessageW(dialog, IDC_FORMAT, CB_GETCURSEL, 0, 0);
    return index >= 0 && index < static_cast<LRESULT>(std::size(kAllFormats)) ? kAllFormats[index] : Format::X64dbg;
}

void updateEndEnabled(HWND dialog) {
    const BOOL enable = selectedMode(dialog) == Mode::Selection ? TRUE : FALSE;
    EnableWindow(GetDlgItem(dialog, IDC_END), enable);
    EnableWindow(GetDlgItem(dialog, IDC_END_LABEL), enable);
}

void writeControls(HWND dialog, const PluginSettings& s) {
    const WildcardPolicy& p = s.options.policy;
    check(dialog, IDC_W_REL32, p.branchRel32);
    check(dialog, IDC_W_REL8, p.branchRel8);
    check(dialog, IDC_W_RIP, p.ripRelative);
    check(dialog, IDC_W_ABS, p.absoluteAddress);
    check(dialog, IDC_W_PTR, p.pointerImmediate);
    check(dialog, IDC_W_STRUCT, p.structOffset);
    check(dialog, IDC_W_IMM, p.largeImmediate);
    SetDlgItemInt(dialog, IDC_MAXBYTES, static_cast<UINT>(s.options.maxBytes), FALSE);
    for (std::size_t i = 0; i < std::size(kAllFormats); ++i) {
        if (kAllFormats[i] == s.format) {
            SendDlgItemMessageW(dialog, IDC_FORMAT, CB_SETCURSEL, i, 0);
        }
    }
}

PluginSettings readControls(HWND dialog, const PluginSettings& base) {
    PluginSettings s = base;
    WildcardPolicy& p = s.options.policy;
    p.branchRel32 = checked(dialog, IDC_W_REL32);
    p.branchRel8 = checked(dialog, IDC_W_REL8);
    p.ripRelative = checked(dialog, IDC_W_RIP);
    p.absoluteAddress = checked(dialog, IDC_W_ABS);
    p.pointerImmediate = checked(dialog, IDC_W_PTR);
    p.structOffset = checked(dialog, IDC_W_STRUCT);
    p.largeImmediate = checked(dialog, IDC_W_IMM);
    BOOL ok = FALSE;
    const UINT maxBytes = GetDlgItemInt(dialog, IDC_MAXBYTES, &ok, FALSE);
    if (ok && maxBytes >= 4) {
        s.options.maxBytes = std::min<std::size_t>(maxBytes, 1024);
    }
    s.format = selectedFormat(dialog);
    return s;
}

// Evaluates an address box with x64dbg's own expression parser, so
// "ac_client.exe+29D1F", a label or a register all work.
std::optional<std::uint64_t> evaluate(HWND dialog, int id) {
    const std::string expression = narrow(text(dialog, id));
    if (expression.empty()) {
        return std::nullopt;
    }
    bool ok = false;
    const duint value = DbgEval(expression.c_str(), &ok);
    if (!ok) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(value);
}

std::string render(const State& st) {
    ReportOptions options;
    options.primary = st.settings.format;
    return describe(st.last, options);
}

void generate(HWND dialog) {
    State* st = state(dialog);
    st->settings = readControls(dialog, st->settings);
    const auto address = evaluate(dialog, IDC_ADDRESS);
    if (!address) {
        setOutput(dialog, "The address is not an expression x64dbg can evaluate.");
        return;
    }
    const Mode mode = selectedMode(dialog);
    std::uint64_t end = *address;
    if (mode == Mode::Selection) {
        const auto evaluated = evaluate(dialog, IDC_END);
        if (!evaluated) {
            setOutput(dialog, "Selection mode needs an end address: the last byte to include.");
            return;
        }
        end = *evaluated;
    }
    const HCURSOR previous = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    st->last = runBuild(*address, mode, end, st->settings);
    SetCursor(previous);
    setOutput(dialog, render(*st));
    setStatus(dialog, st->last.ok() ? L"Generated. Copy puts the chosen form on the clipboard." : L"No signature.");
}

void copy(HWND dialog) {
    State* st = state(dialog);
    if (!st->last.ok()) {
        setStatus(dialog, L"Generate a signature first.");
        return;
    }
    st->settings.format = selectedFormat(dialog);
    const Signature& s = st->last.signatures.front();
    if (copyToClipboard(clipboardText(s, st->settings.format))) {
        setStatus(dialog, L"Copied the " + widen(formatName(st->settings.format)) + L" form.");
    } else {
        setStatus(dialog, L"The clipboard was busy; try again.");
    }
}

void test(HWND dialog) {
    const std::string pattern = narrow(text(dialog, IDC_TEST_PATTERN));
    auto where = evaluate(dialog, IDC_ADDRESS);
    if (!where) {
        where = state(dialog)->start;
    }
    const HCURSOR previous = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    const TestResult result = testPattern(pattern, *where);
    SetCursor(previous);
    setOutput(dialog, describeTest(result, 50));
    if (result.error.empty()) {
        showInReferences(result);
        setStatus(dialog, L"Matches are also listed in the References tab.");
    }
}

void initialise(HWND dialog, State* st) {
    SetWindowLongPtrW(dialog, DWLP_USER, reinterpret_cast<LONG_PTR>(st));

    if (HICON icon = LoadIconW(g_instance, MAKEINTRESOURCEW(IDI_SIGLAB))) {
        SendMessageW(dialog, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon));
        SendMessageW(dialog, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(icon));
    }

    SetDlgItemTextW(dialog, IDC_ADDRESS, widen(hexAddress(st->start)).c_str());
    SetDlgItemTextW(dialog, IDC_END, widen(hexAddress(st->end)).c_str());
    for (const wchar_t* label : kModeLabels) {
        SendDlgItemMessageW(dialog, IDC_MODE, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    SendDlgItemMessageW(dialog, IDC_MODE, CB_SETCURSEL, 0, 0);
    for (Format form : kAllFormats) {
        SendDlgItemMessageW(dialog, IDC_FORMAT, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(formatName(form)).c_str()));
    }
    writeControls(dialog, st->settings);
    updateEndEnabled(dialog);
    SendDlgItemMessageW(dialog, IDC_MAXBYTES, EM_SETLIMITTEXT, 4, 0);

    // A monospace face for the output, where byte columns have to line up.
    const HDC dc = GetDC(dialog);
    const int height = -MulDiv(9, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(dialog, dc);
    st->mono = CreateFontW(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendDlgItemMessageW(dialog, IDC_OUTPUT, WM_SETFONT, reinterpret_cast<WPARAM>(st->mono), TRUE);
    SendDlgItemMessageW(dialog, IDC_TEST_PATTERN, WM_SETFONT, reinterpret_cast<WPARAM>(st->mono), TRUE);

    SendDlgItemMessageW(dialog, IDC_TEST_PATTERN, EM_SETCUEBANNER, TRUE,
                        reinterpret_cast<LPARAM>(L"48 8B 05 ?? ?? ?? ??, or code+mask, a C array, an aobscanmodule line"));
    setStatus(dialog, widen(std::string(SIGLAB_PRODUCT_NAME " " SIGLAB_VERSION_STRING "  \xC2\xB7  Game Reversal Club  \xC2\xB7  gamereversal.club")));

    // Generate straight away: the dialog was opened on an instruction, and
    // the first thing anyone wants is its signature.
    generate(dialog);
}

INT_PTR CALLBACK dialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG:
        initialise(dialog, reinterpret_cast<State*>(lParam));
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_GENERATE:
            generate(dialog);
            return TRUE;
        case IDC_COPY:
            copy(dialog);
            return TRUE;
        case IDC_TEST:
            test(dialog);
            return TRUE;
        case IDC_SAVE: {
            State* st = state(dialog);
            st->settings = readControls(dialog, st->settings);
            saveSettings(st->settings);
            setStatus(dialog, L"Saved. The menu entries and commands use these settings from now on.");
            return TRUE;
        }
        case IDC_DEFAULTS:
            writeControls(dialog, PluginSettings{});
            setStatus(dialog, L"Defaults restored in the dialog. Save to keep them.");
            return TRUE;
        case IDC_MODE:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                updateEndEnabled(dialog);
            }
            return TRUE;
        case IDC_FORMAT:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                State* st = state(dialog);
                st->settings.format = selectedFormat(dialog);
                if (st->last.ok()) {
                    setOutput(dialog, render(*st));
                }
            }
            return TRUE;
        case IDCANCEL:
            EndDialog(dialog, 0);
            return TRUE;
        default:
            return FALSE;
        }
    case WM_DESTROY:
        if (State* st = state(dialog); st != nullptr && st->mono != nullptr) {
            DeleteObject(st->mono);
            st->mono = nullptr;
        }
        return FALSE;
    default:
        return FALSE;
    }
}

} // namespace

void showDialog(std::uint64_t start, std::uint64_t end) {
    auto st = std::make_unique<State>();
    st->start = start;
    st->end = end;
    st->settings = loadSettings();

    ACTCTXW context{};
    context.cbSize = sizeof(context);
    context.dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID;
    context.hModule = g_instance;
    context.lpResourceName = MAKEINTRESOURCEW(2);
    const HANDLE activation = CreateActCtxW(&context);
    ULONG_PTR cookie = 0;
    const bool activated = activation != INVALID_HANDLE_VALUE && ActivateActCtx(activation, &cookie);

    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_SIGLAB), GuiGetWindowHandle(), dialogProc, reinterpret_cast<LPARAM>(st.get()));

    if (activated) {
        DeactivateActCtx(0, cookie);
    }
    if (activation != INVALID_HANDLE_VALUE) {
        ReleaseActCtx(activation);
    }
}

} // namespace siglab::plugin
