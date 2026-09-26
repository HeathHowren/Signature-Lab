#pragma once

#include <cstdint>

namespace siglab::plugin {

// The Signature Lab dialog: every option, generate, test, copy, save as
// defaults. Modal on x64dbg's main window. Win32 rather than Qt so the
// plugin carries no Qt build dependency and cannot break when x64dbg moves
// to a new Qt.
void showDialog(std::uint64_t start, std::uint64_t end);

} // namespace siglab::plugin
