#include "plugin/Clipboard.h"

#include "plugin/Sdk.h"

#include <cstring>

namespace siglab::plugin {

namespace {

bool openClipboard() {
    // EmptyClipboard with no owner window makes the next SetClipboardData
    // fail, so the clipboard is opened on x64dbg's main window.
    const HWND owner = GuiGetWindowHandle();
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (OpenClipboard(owner)) {
            return true;
        }
        Sleep(10);
    }
    return false;
}

} // namespace

std::wstring widen(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length);
    return out;
}

std::string narrow(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length, nullptr, nullptr);
    return out;
}

bool copyToClipboard(std::string_view text) {
    const std::wstring wide = widen(text);
    const std::size_t bytes = (wide.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == nullptr) {
        return false;
    }
    void* locked = GlobalLock(memory);
    if (locked == nullptr) {
        GlobalFree(memory);
        return false;
    }
    std::memcpy(locked, wide.c_str(), bytes);
    GlobalUnlock(memory);

    if (!openClipboard()) {
        GlobalFree(memory);
        return false;
    }
    EmptyClipboard();
    const bool ok = SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    CloseClipboard();
    if (!ok) {
        // Ownership passes to the system only on success.
        GlobalFree(memory);
    }
    return ok;
}

std::string clipboardText() {
    if (!openClipboard()) {
        return {};
    }
    std::string out;
    if (HANDLE data = GetClipboardData(CF_UNICODETEXT)) {
        if (const auto* text = static_cast<const wchar_t*>(GlobalLock(data))) {
            out = narrow(text);
            GlobalUnlock(data);
        }
    }
    CloseClipboard();
    return out;
}

} // namespace siglab::plugin
