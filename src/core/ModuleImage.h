#pragma once

#include "core/MemoryView.h"
#include "core/Pattern.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace siglab {

// A copy of one module's memory, taken once per operation. Growing a
// signature asks "how many times does this match?" a dozen times; asking the
// debuggee each time would mean a dozen full reads of the module.
//
// Unreadable pages (guard pages, a section the loader decommitted) are kept
// as zeros and marked in a bitmap, and a match that touches one is not a
// match. A real scanner reading the same module would fail on that page too.
class ModuleImage {
public:
    // Reads the module in large chunks, falling back to single pages where a
    // chunk fails. Fails only if the module could not be allocated or not a
    // single page could be read.
    [[nodiscard]] static std::optional<ModuleImage> capture(const MemoryView& view, const ModuleInfo& module, std::string* error = nullptr);

    // For tests: a module whose every page is readable.
    [[nodiscard]] static ModuleImage fromBytes(ModuleInfo module, std::vector<std::uint8_t> bytes, std::uint64_t pageSize = 0x1000);

    [[nodiscard]] const ModuleInfo& module() const { return module_; }
    [[nodiscard]] std::uint64_t base() const { return module_.base; }
    [[nodiscard]] std::size_t size() const { return bytes_.size(); }
    [[nodiscard]] const std::uint8_t* data() const { return bytes_.data(); }
    [[nodiscard]] bool contains(std::uint64_t address) const { return address >= base() && address - base() < size(); }

    // Whether every byte in [address, address + length) is inside the module
    // and on a readable page.
    [[nodiscard]] bool readable(std::uint64_t address, std::size_t length) const;

    // Copies up to `length` bytes starting at `address`, stopping at the end
    // of the module or the first unreadable page. Returns the count copied.
    [[nodiscard]] std::size_t read(std::uint64_t address, std::uint8_t* destination, std::size_t length) const;

    // Every address in the module where `pattern` matches, in ascending
    // order, stopping after `cap` matches. Overlapping matches all count: a
    // scanner that takes the first hit would take a different one than the
    // one intended.
    [[nodiscard]] std::vector<std::uint64_t> find(const Pattern& pattern, std::size_t cap) const;

    // As find(), but only the count.
    [[nodiscard]] std::size_t count(const Pattern& pattern, std::size_t cap) const;

    // The ranges searched for code references: executable sections when the
    // module reported any, otherwise the whole module.
    [[nodiscard]] std::vector<std::pair<std::uint64_t, std::uint64_t>> codeRanges() const;

private:
    ModuleImage() = default;
    void buildHistogram();
    [[nodiscard]] bool matchesAt(std::size_t offset, const Pattern& pattern) const;

    ModuleInfo module_;
    std::vector<std::uint8_t> bytes_;
    std::vector<bool> readablePages_;
    std::uint64_t pageSize_ = 0x1000;
    std::array<std::uint64_t, 256> histogram_{};
};

} // namespace siglab
