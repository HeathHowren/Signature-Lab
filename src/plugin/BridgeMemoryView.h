#pragma once

#include "core/MemoryView.h"

namespace siglab::plugin {

// The debuggee, as the core sees it, over the x64dbg bridge. Reads go
// through DbgMemRead, which returns the original bytes under a software
// breakpoint rather than the int3 x64dbg wrote there, so a breakpoint on
// the instruction being signed does not end up in the signature as CC.
class BridgeMemoryView final : public MemoryView {
public:
    [[nodiscard]] Bitness bitness() const override;
    [[nodiscard]] std::optional<ModuleInfo> moduleAt(std::uint64_t address) const override;
    [[nodiscard]] bool read(std::uint64_t address, void* destination, std::size_t size) const override;
    [[nodiscard]] bool isReadable(std::uint64_t address) const override;
};

} // namespace siglab::plugin
