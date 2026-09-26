#include "core/ModuleImage.h"

#include <algorithm>
#include <cstring>
#include <new>

namespace siglab {

namespace {

// Big enough that a 50 MB module is a few hundred reads, small enough that a
// chunk holding one bad page does not cost much to retry page by page.
constexpr std::size_t kChunkSize = 0x10000;

// A module larger than this is almost certainly a size reported wrongly, and
// a copy of it would exhaust a 32-bit x32dbg's address space.
constexpr std::uint64_t kMaxModuleSize = 0x40000000; // 1 GiB

} // namespace

std::optional<ModuleImage> ModuleImage::capture(const MemoryView& view, const ModuleInfo& module, std::string* error) {
    if (module.size == 0) {
        if (error) {
            *error = "the module reports a size of zero";
        }
        return std::nullopt;
    }
    if (module.size > kMaxModuleSize) {
        if (error) {
            *error = "the module is larger than 1 GiB; refusing to copy it";
        }
        return std::nullopt;
    }

    ModuleImage image;
    image.module_ = module;
    image.pageSize_ = view.pageSize() == 0 ? 0x1000 : view.pageSize();
    try {
        image.bytes_.assign(static_cast<std::size_t>(module.size), 0);
    } catch (const std::bad_alloc&) {
        if (error) {
            *error = "not enough memory to copy the module";
        }
        return std::nullopt;
    }
    const std::size_t pageSize = static_cast<std::size_t>(image.pageSize_);
    const std::size_t pageCount = (image.bytes_.size() + pageSize - 1) / pageSize;
    image.readablePages_.assign(pageCount, false);

    std::size_t readablePages = 0;
    for (std::size_t chunk = 0; chunk < image.bytes_.size(); chunk += kChunkSize) {
        const std::size_t chunkSize = std::min(kChunkSize, image.bytes_.size() - chunk);
        if (view.read(module.base + chunk, image.bytes_.data() + chunk, chunkSize)) {
            for (std::size_t off = 0; off < chunkSize; off += pageSize) {
                image.readablePages_[(chunk + off) / pageSize] = true;
                ++readablePages;
            }
            continue;
        }
        for (std::size_t off = 0; off < chunkSize; off += pageSize) {
            const std::size_t pageBytes = std::min(pageSize, chunkSize - off);
            std::uint8_t* destination = image.bytes_.data() + chunk + off;
            if (view.read(module.base + chunk + off, destination, pageBytes)) {
                image.readablePages_[(chunk + off) / pageSize] = true;
                ++readablePages;
            } else {
                std::memset(destination, 0, pageBytes);
            }
        }
    }
    if (readablePages == 0) {
        if (error) {
            *error = "no page of the module could be read";
        }
        return std::nullopt;
    }
    image.buildHistogram();
    return image;
}

ModuleImage ModuleImage::fromBytes(ModuleInfo module, std::vector<std::uint8_t> bytes, std::uint64_t pageSize) {
    ModuleImage image;
    module.size = bytes.size();
    image.module_ = std::move(module);
    image.bytes_ = std::move(bytes);
    image.pageSize_ = pageSize == 0 ? 0x1000 : pageSize;
    const std::size_t pages = (image.bytes_.size() + static_cast<std::size_t>(image.pageSize_) - 1) / static_cast<std::size_t>(image.pageSize_);
    image.readablePages_.assign(pages, true);
    image.buildHistogram();
    return image;
}

void ModuleImage::buildHistogram() {
    histogram_.fill(0);
    for (std::uint8_t b : bytes_) {
        ++histogram_[b];
    }
}

bool ModuleImage::readable(std::uint64_t address, std::size_t length) const {
    if (length == 0) {
        return contains(address) || address == base() + size();
    }
    if (!contains(address) || length > size() - (address - base())) {
        return false;
    }
    const std::size_t first = static_cast<std::size_t>((address - base()) / pageSize_);
    const std::size_t last = static_cast<std::size_t>((address - base() + length - 1) / pageSize_);
    for (std::size_t page = first; page <= last; ++page) {
        if (!readablePages_[page]) {
            return false;
        }
    }
    return true;
}

std::size_t ModuleImage::read(std::uint64_t address, std::uint8_t* destination, std::size_t length) const {
    if (!contains(address)) {
        return 0;
    }
    std::size_t offset = static_cast<std::size_t>(address - base());
    std::size_t copied = 0;
    while (copied < length && offset < size() && readablePages_[offset / static_cast<std::size_t>(pageSize_)]) {
        destination[copied++] = bytes_[offset++];
    }
    return copied;
}

bool ModuleImage::matchesAt(std::size_t offset, const Pattern& pattern) const {
    const std::uint8_t* at = bytes_.data() + offset;
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        const std::uint8_t m = pattern.mask[i];
        if ((at[i] & m) != (pattern.bytes[i] & m)) {
            return false;
        }
    }
    return readable(base() + offset, pattern.size());
}

std::vector<std::uint64_t> ModuleImage::find(const Pattern& pattern, std::size_t cap) const {
    std::vector<std::uint64_t> matches;
    if (pattern.empty() || pattern.size() > size() || cap == 0) {
        return matches;
    }
    const std::size_t last = size() - pattern.size();

    // Anchor on the fixed byte that is rarest in this module, and let memchr
    // find candidates for it. A pattern that starts with 48 8B would
    // otherwise be verified at every one of the hundreds of thousands of
    // places a 64-bit module has a 48.
    std::size_t anchor = pattern.size();
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        if (pattern.mask[i] != 0xFF) {
            continue;
        }
        if (anchor == pattern.size() || histogram_[pattern.bytes[i]] < histogram_[pattern.bytes[anchor]]) {
            anchor = i;
        }
    }

    if (anchor == pattern.size()) {
        // No whole byte to anchor on: every wildcard or nibble. Walk it.
        for (std::size_t offset = 0; offset <= last && matches.size() < cap; ++offset) {
            if (matchesAt(offset, pattern)) {
                matches.push_back(base() + offset);
            }
        }
        return matches;
    }

    const std::uint8_t needle = pattern.bytes[anchor];
    const std::uint8_t* begin = bytes_.data();
    const std::uint8_t* cursor = begin + anchor;
    const std::uint8_t* end = begin + last + anchor + 1;
    while (cursor < end && matches.size() < cap) {
        const void* hit = std::memchr(cursor, needle, static_cast<std::size_t>(end - cursor));
        if (hit == nullptr) {
            break;
        }
        const std::size_t offset = static_cast<std::size_t>(static_cast<const std::uint8_t*>(hit) - begin) - anchor;
        if (matchesAt(offset, pattern)) {
            matches.push_back(base() + offset);
        }
        cursor = static_cast<const std::uint8_t*>(hit) + 1;
    }
    return matches;
}

std::size_t ModuleImage::count(const Pattern& pattern, std::size_t cap) const {
    return find(pattern, cap).size();
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> ModuleImage::codeRanges() const {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    for (const auto& section : module_.sections) {
        if (!section.executable || section.size == 0) {
            continue;
        }
        const std::uint64_t start = std::max(section.address, base());
        const std::uint64_t stop = std::min(section.address + section.size, base() + size());
        if (start < stop) {
            ranges.emplace_back(start, stop);
        }
    }
    if (ranges.empty()) {
        ranges.emplace_back(base(), base() + size());
    }
    return ranges;
}

} // namespace siglab
