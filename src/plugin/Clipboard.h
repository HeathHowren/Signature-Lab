#pragma once

#include <string>
#include <string_view>

namespace siglab::plugin {

// UTF-8 in, CF_UNICODETEXT on the clipboard. Retries briefly, because the
// clipboard is a shared lock and a clipboard manager holding it for a few
// milliseconds is common. Returns false if it never got the lock.
bool copyToClipboard(std::string_view text);

// The clipboard's text as UTF-8, or an empty string.
[[nodiscard]] std::string clipboardText();

// UTF-8 <-> UTF-16 for the Win32 dialog.
[[nodiscard]] std::wstring widen(std::string_view text);
[[nodiscard]] std::string narrow(std::wstring_view text);

} // namespace siglab::plugin
