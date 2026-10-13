#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <charconv>
#include <cstring>
#include <limits>

namespace testsmem4u::memory_pages {

inline void skipSpaces(const char*& cursor) {
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
}

inline bool readUnsigned(const char*& cursor, uint64_t& value, int radix = 10) {
    const auto result = std::from_chars(cursor, cursor + std::strlen(cursor), value, radix);
    if (result.ec != std::errc{} || result.ptr == cursor) return false;
    cursor = result.ptr;
    return true;
}

inline bool readKilobytes(const char* cursor, uint64_t& value) {
    skipSpaces(cursor);
    if (!readUnsigned(cursor, value)) return false;
    skipSpaces(cursor);
    return std::strncmp(cursor, "kB", 2) == 0 &&
           (cursor[2] == '\0' || cursor[2] == '\n' || cursor[2] == '\r');
}

inline bool alignSize(size_t size, size_t alignment, size_t& aligned) {
    if (size == 0 || alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        size > std::numeric_limits<size_t>::max() - (alignment - 1)) return false;
    aligned = (size + alignment - 1) & ~(alignment - 1);
    return true;
}

inline uint32_t normalizeWindow(uint32_t mb, bool prefer_large, size_t page_size) {
    if (!prefer_large || page_size == 0 || mb == 0) return mb;
    constexpr uint64_t mib = 1024ULL * 1024;
    const uint64_t bytes = uint64_t{mb} * mib;
    const uint64_t aligned = (bytes / page_size) * page_size;
    return aligned == 0 ? mb : static_cast<uint32_t>(aligned / mib);
}

struct Coverage {
    size_t bytes = 0;
    size_t possible_bytes = 0;
    size_t page_size = 0;
    bool known = false;
    bool transparent = false;
};

// smaps gives per-VMA totals, not the positions of individual THPs. Partial
// overlaps provide bounds; never invent a prefix or count pages outside a slice.
class SmapsCoverage {
    uintptr_t begin_;
    uintptr_t end_;
    uintptr_t map_begin_ = 0;
    uintptr_t map_end_ = 0;
    size_t covered_ = 0;
    Coverage result_;
    bool valid_ = true;
public:
    SmapsCoverage(uintptr_t begin, size_t size) : begin_(begin), end_(begin) {
        valid_ = size > 0 && size <= std::numeric_limits<uintptr_t>::max() - begin;
        if (valid_) end_ += size;
        result_.transparent = true;
    }

    void consume(const char* line) {
        uint64_t start = 0;
        uint64_t end = 0;
        const char* cursor = line;
        bool addresses = readUnsigned(cursor, start, 16);
        if (addresses && *cursor == '-') {
            ++cursor;
            addresses = readUnsigned(cursor, end, 16);
        } else addresses = false;
        skipSpaces(cursor);
        if (addresses && std::strlen(cursor) >= 4 &&
            (cursor[0] == 'r' || cursor[0] == '-') &&
            (cursor[1] == 'w' || cursor[1] == '-') &&
            (cursor[2] == 'x' || cursor[2] == '-') &&
            (cursor[3] == 'p' || cursor[3] == 's')) {
            if (start >= end || start > std::numeric_limits<uintptr_t>::max() || end > std::numeric_limits<uintptr_t>::max()) {
                valid_ = false;
                return;
            }
            map_begin_ = static_cast<uintptr_t>(start);
            map_end_ = static_cast<uintptr_t>(end);
            return;
        }
        constexpr const char* key = "AnonHugePages:";
        if (!valid_ || std::strncmp(line, key, std::strlen(key)) != 0) return;
        uint64_t kb = 0;
        if (!readKilobytes(line + std::strlen(key), kb)) {
            valid_ = false;
            return;
        }
        if (map_end_ <= map_begin_ || map_end_ <= begin_ || map_begin_ >= end_) return;
        const size_t overlap = std::min(map_end_, end_) - std::max(map_begin_, begin_);
        const size_t map_size = map_end_ - map_begin_;
        if (std::max(map_begin_, begin_) != begin_ + covered_ ||
            kb > map_size / 1024 || covered_ > end_ - begin_ - overlap) {
            valid_ = false;
            return;
        }
        const size_t huge = static_cast<size_t>(kb) * 1024;
        const size_t outside = map_size - overlap;
        result_.bytes += huge > outside ? huge - outside : 0;
        result_.possible_bytes += std::min(huge, overlap);
        covered_ += overlap;
    }

    Coverage finish() const {
        Coverage result = result_;
        result.known = valid_ && covered_ == end_ - begin_;
        if (!result.known) result.bytes = result.possible_bytes = 0;
        return result;
    }
};

} // namespace testsmem4u::memory_pages
