#pragma once

// The one place the x64dbg plugin SDK is included. Its headers predate /W4
// and /permissive-, so their warnings are silenced here rather than
// weakening the flags for the plugin's own code.

#include <windows.h>

#pragma warning(push, 0)
#pragma warning(disable : 4091 4201 4324 4458 4996)
#include "_plugins.h"
#include "_scriptapi_gui.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_module.h"
#include "bridgelist.h"
#pragma warning(pop)

#define PLUG_EXPORT extern "C" __declspec(dllexport)

namespace siglab::plugin {

// Set in pluginit and used by every call that needs to name the plugin.
extern int g_pluginHandle;
extern HINSTANCE g_instance;

inline constexpr const char* kPluginName = "Signature Lab";

} // namespace siglab::plugin
