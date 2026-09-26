#include "plugin/BridgeMemoryView.h"

#include "plugin/Sdk.h"

#include <limits>

namespace siglab::plugin {

namespace {

bool isExecutable(unsigned int protect) {
    const unsigned int base = protect & 0xFF;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

} // namespace

Bitness BridgeMemoryView::bitness() const {
    // The plugin is always the same width as the debugger that loads it, and
    // x64dbg only debugs targets of its own width.
    return sizeof(duint) == 8 ? Bitness::X64 : Bitness::X86;
}

std::optional<ModuleInfo> BridgeMemoryView::moduleAt(std::uint64_t address) const {
    if (address > std::numeric_limits<duint>::max()) {
        return std::nullopt;
    }
    Script::Module::ModuleInfo info{};
    if (!Script::Module::InfoFromAddr(static_cast<duint>(address), &info) || info.size == 0) {
        return std::nullopt;
    }
    ModuleInfo module;
    module.base = info.base;
    module.size = info.size;
    module.name = info.name;

    BridgeList<Script::Module::ModuleSectionInfo> sections;
    if (Script::Module::SectionListFromAddr(static_cast<duint>(address), &sections)) {
        for (int i = 0; i < sections.Count(); ++i) {
            const auto& section = sections[static_cast<size_t>(i)];
            Section s;
            s.address = section.addr;
            s.size = section.size;
            s.name = section.name;
            // The section table's own characteristics are not in the SDK's
            // struct; the page protection x64dbg reports is, and it is what a
            // scanner in the target would see anyway.
            s.executable = isExecutable(Script::Memory::GetProtect(section.addr));
            module.sections.push_back(std::move(s));
        }
    }
    return module;
}

bool BridgeMemoryView::read(std::uint64_t address, void* destination, std::size_t size) const {
    if (address > std::numeric_limits<duint>::max()) {
        return false;
    }
    return DbgMemRead(static_cast<duint>(address), destination, static_cast<duint>(size));
}

bool BridgeMemoryView::isReadable(std::uint64_t address) const {
    if (address > std::numeric_limits<duint>::max()) {
        return false;
    }
    return DbgMemIsValidReadPtr(static_cast<duint>(address));
}

} // namespace siglab::plugin
