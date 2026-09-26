#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace siglab {

enum class Bitness : std::uint8_t { X86, X64 };

struct Section {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::string name;
    bool executable = false;
};

struct ModuleInfo {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string name; // "ac_client.exe"
    // May be empty when the implementation cannot enumerate sections; every
    // consumer treats an empty list as "the whole module".
    std::vector<Section> sections;

    [[nodiscard]] bool contains(std::uint64_t address) const { return address >= base && address - base < size; }
};

// The core's only window onto the debuggee. The plugin implements it over the
// x64dbg bridge; the tests implement it over a byte vector. Nothing in
// src/core includes an x64dbg header, so everything that decides what a
// signature looks like can be tested without a debugger running.
class MemoryView {
public:
    virtual ~MemoryView() = default;

    [[nodiscard]] virtual Bitness bitness() const = 0;

    // The module that contains `address`, or nothing if it is not inside one.
    [[nodiscard]] virtual std::optional<ModuleInfo> moduleAt(std::uint64_t address) const = 0;

    // Reads exactly `size` bytes or fails. Callers keep reads within one page,
    // so an implementation may fail the whole read if any byte is unreadable.
    [[nodiscard]] virtual bool read(std::uint64_t address, void* destination, std::size_t size) const = 0;

    // Whether `address` is inside committed, readable memory. Used to decide
    // whether an immediate is a pointer.
    [[nodiscard]] virtual bool isReadable(std::uint64_t address) const = 0;

    [[nodiscard]] virtual std::uint64_t pageSize() const { return 0x1000; }

    [[nodiscard]] std::size_t pointerSize() const { return bitness() == Bitness::X64 ? 8 : 4; }
};

} // namespace siglab
