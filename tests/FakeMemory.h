#pragma once

#include "core/MemoryView.h"

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <utility>
#include <vector>

namespace siglab::test {

// A debuggee made of one module in a byte vector, plus optional readable
// ranges outside it. Unfilled module bytes are a fixed pseudo-random filler
// rather than zeros, because real modules are not mostly zeros and a pattern
// of zeros would otherwise match everywhere.
class FakeMemory final : public MemoryView {
public:
    FakeMemory(Bitness bitness, std::uint64_t base, std::size_t size, std::string name = "game.exe")
        : bitness_(bitness), bytes_(size) {
        module_.base = base;
        module_.size = size;
        module_.name = std::move(name);
        std::uint32_t state = 0x12345678u;
        for (auto& b : bytes_) {
            state = state * 1664525u + 1013904223u;
            b = static_cast<std::uint8_t>(state >> 24);
        }
    }

    void write(std::uint64_t address, std::initializer_list<std::uint8_t> data) {
        std::size_t offset = static_cast<std::size_t>(address - module_.base);
        for (std::uint8_t b : data) {
            bytes_.at(offset++) = b;
        }
    }

    void write32(std::uint64_t address, std::uint32_t value) {
        std::memcpy(&bytes_.at(static_cast<std::size_t>(address - module_.base)), &value, 4);
    }

    void write64(std::uint64_t address, std::uint64_t value) {
        std::memcpy(&bytes_.at(static_cast<std::size_t>(address - module_.base)), &value, 8);
    }

    void addSection(std::uint64_t address, std::uint64_t size, const char* name, bool executable) {
        module_.sections.push_back({address, size, name, executable});
    }

    void markUnreadable(std::uint64_t address, std::uint64_t size) { unreadable_.emplace_back(address, address + size); }
    void addReadable(std::uint64_t address, std::uint64_t size) { extraReadable_.emplace_back(address, address + size); }

    Bitness bitness() const override { return bitness_; }

    std::optional<ModuleInfo> moduleAt(std::uint64_t address) const override {
        if (module_.contains(address)) {
            return module_;
        }
        return std::nullopt;
    }

    bool read(std::uint64_t address, void* destination, std::size_t size) const override {
        for (std::size_t i = 0; i < size; ++i) {
            if (!readableInModule(address + i)) {
                return false;
            }
        }
        std::memcpy(destination, bytes_.data() + (address - module_.base), size);
        return true;
    }

    bool isReadable(std::uint64_t address) const override {
        if (readableInModule(address)) {
            return true;
        }
        for (const auto& [start, end] : extraReadable_) {
            if (address >= start && address < end) {
                return true;
            }
        }
        return false;
    }

    const std::vector<std::uint8_t>& bytes() const { return bytes_; }
    const ModuleInfo& module() const { return module_; }

private:
    bool readableInModule(std::uint64_t address) const {
        if (!module_.contains(address)) {
            return false;
        }
        for (const auto& [start, end] : unreadable_) {
            if (address >= start && address < end) {
                return false;
            }
        }
        return true;
    }

    Bitness bitness_;
    ModuleInfo module_;
    std::vector<std::uint8_t> bytes_;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> unreadable_;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> extraReadable_;
};

inline std::uint32_t rel32(std::uint64_t from, std::uint8_t instructionLength, std::uint64_t to) {
    return static_cast<std::uint32_t>(to - (from + instructionLength));
}

} // namespace siglab::test
