#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace testsmem4u::cgroup_limit {

constexpr uint64_t kUnlimitedMemory = std::numeric_limits<uint64_t>::max();
// Linux cgroup v1 encodes "unlimited" near PAGE_COUNTER_MAX * PAGE_SIZE
// (~8 EiB on 64-bit kernels). Anything at or above 1 EiB is treated as unset.
constexpr uint64_t kCgroupV1UnlimitedThreshold = uint64_t{1} << 60;

inline std::string_view trimView(std::string_view text) {
    while (!text.empty() &&
           (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' || text.front() == '\n')) {
        text.remove_prefix(1);
    }
    while (!text.empty() &&
           (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n')) {
        text.remove_suffix(1);
    }
    return text;
}

inline bool parseStrictUint64(std::string_view text, uint64_t& value) {
    text = trimView(text);
    if (text.empty()) return false;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto res = std::from_chars(begin, end, value);
    return res.ec == std::errc{} && res.ptr == end;
}

// Decodes octal escape sequences (\040, \011, \012, \134) used by Linux
// /proc/self/mountinfo paths.
inline std::string unescapeMountField(std::string_view field) {
    std::string out;
    out.reserve(field.size());
    for (size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 3 < field.size() &&
            field[i + 1] >= '0' && field[i + 1] <= '7' &&
            field[i + 2] >= '0' && field[i + 2] <= '7' &&
            field[i + 3] >= '0' && field[i + 3] <= '7') {
            const unsigned code = static_cast<unsigned>((field[i + 1] - '0') * 64 +
                                                        (field[i + 2] - '0') * 8 +
                                                        (field[i + 3] - '0'));
            out.push_back(static_cast<char>(code));
            i += 3;
        } else {
            out.push_back(field[i]);
        }
    }
    return out;
}

inline bool commaListContains(std::string_view list, std::string_view needle) {
    size_t pos = 0;
    while (pos <= list.size()) {
        const size_t comma = list.find(',', pos);
        const std::string_view item = comma == std::string_view::npos
            ? list.substr(pos)
            : list.substr(pos, comma - pos);
        if (item == needle) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

struct CgroupMount {
    std::string root;
    std::string mount_point;
};

struct ParsedMounts {
    std::vector<CgroupMount> v2;
    std::vector<CgroupMount> v1_memory;
};

inline ParsedMounts parseMountInfo(std::string_view text) {
    ParsedMounts parsed;
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        pos = nl == std::string_view::npos ? text.size() : nl + 1;

        const size_t sep = line.find(" - ");
        if (sep == std::string_view::npos) continue;
        const std::string_view prefix = line.substr(0, sep);
        const std::string_view suffix = line.substr(sep + 3);

        auto nextToken = [](std::string_view s, size_t& cursor) -> std::string_view {
            while (cursor < s.size() && s[cursor] == ' ') ++cursor;
            const size_t start = cursor;
            while (cursor < s.size() && s[cursor] != ' ') ++cursor;
            return s.substr(start, cursor - start);
        };

        size_t pc = 0;
        const std::string_view f0 = nextToken(prefix, pc); // mount ID
        const std::string_view f1 = nextToken(prefix, pc); // parent ID
        const std::string_view f2 = nextToken(prefix, pc); // major:minor
        const std::string_view root_raw = nextToken(prefix, pc);
        const std::string_view mount_raw = nextToken(prefix, pc);
        const std::string_view mount_opts = nextToken(prefix, pc);
        if (f0.empty() || f1.empty() || f2.empty() || root_raw.empty() || mount_raw.empty()) continue;

        size_t sc = 0;
        const std::string_view fs_type = nextToken(suffix, sc);
        const std::string_view source = nextToken(suffix, sc);
        const std::string_view super_opts = nextToken(suffix, sc);
        (void)source;

        if (fs_type == "cgroup2") {
            parsed.v2.push_back({unescapeMountField(root_raw), unescapeMountField(mount_raw)});
        } else if (fs_type == "cgroup" &&
                   (commaListContains(super_opts, "memory") || commaListContains(mount_opts, "memory"))) {
            parsed.v1_memory.push_back({unescapeMountField(root_raw), unescapeMountField(mount_raw)});
        }
    }
    return parsed;
}

struct CgroupPaths {
    bool has_v2 = false;
    std::string v2_path;
    bool has_v1_memory = false;
    std::string v1_memory_path;
};

inline CgroupPaths parseProcCgroup(std::string_view text) {
    CgroupPaths result;
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string_view raw_line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        pos = nl == std::string_view::npos ? text.size() : nl + 1;

        const std::string_view line = trimView(raw_line);
        if (line.empty()) continue;
        const size_t c1 = line.find(':');
        if (c1 == std::string_view::npos) continue;
        const size_t c2 = line.find(':', c1 + 1);
        if (c2 == std::string_view::npos) continue;

        const std::string_view hierarchy = line.substr(0, c1);
        const std::string_view controllers = line.substr(c1 + 1, c2 - c1 - 1);
        const std::string_view path = line.substr(c2 + 1);

        if (hierarchy == "0" && controllers.empty()) {
            result.has_v2 = true;
            result.v2_path = std::string(path);
        } else if (commaListContains(controllers, "memory")) {
            result.has_v1_memory = true;
            result.v1_memory_path = std::string(path);
        }
    }
    return result;
}

inline std::string stripMountRootPrefix(std::string_view cgroup_path, std::string_view mount_root) {
    while (cgroup_path.size() > 1 && cgroup_path.back() == '/') cgroup_path.remove_suffix(1);
    while (mount_root.size() > 1 && mount_root.back() == '/') mount_root.remove_suffix(1);
    if (mount_root.empty() || mount_root == "/") {
        return cgroup_path == "/" ? std::string{} : std::string(cgroup_path);
    }
    if (cgroup_path == mount_root) return {};
    if (cgroup_path.size() > mount_root.size() &&
        cgroup_path.compare(0, mount_root.size(), mount_root) == 0 &&
        cgroup_path[mount_root.size()] == '/') {
        return std::string(cgroup_path.substr(mount_root.size()));
    }
    return cgroup_path == "/" ? std::string{} : std::string(cgroup_path);
}

inline std::vector<std::string> hierarchyDirectories(const std::string& mount_point,
                                                     const std::string& cgroup_path,
                                                     const std::string& mount_root) {
    std::vector<std::string> dirs;
    std::string base = mount_point;
    while (base.size() > 1 && base.back() == '/') base.pop_back();
    dirs.push_back(base);

    const std::string rel = stripMountRootPrefix(cgroup_path, mount_root);
    size_t pos = 0;
    std::string current = base == "/" ? std::string{} : base;
    while (pos < rel.size()) {
        while (pos < rel.size() && rel[pos] == '/') ++pos;
        if (pos >= rel.size()) break;
        const size_t slash = rel.find('/', pos);
        const std::string_view part = slash == std::string::npos
            ? std::string_view(rel).substr(pos)
            : std::string_view(rel).substr(pos, slash - pos);
        if (!part.empty() && part != "." && part != "..") {
            current += '/';
            current.append(part.data(), part.size());
            dirs.push_back(current);
        }
        if (slash == std::string::npos) break;
        pos = slash + 1;
    }
    return dirs;
}

inline const CgroupMount* selectBestMount(const std::vector<CgroupMount>& mounts, const std::string& cgroup_path) {
    if (mounts.empty()) return nullptr;
    const CgroupMount* best = nullptr;
    size_t best_root_len = 0;
    for (const auto& m : mounts) {
        std::string_view r = m.root;
        while (r.size() > 1 && r.back() == '/') r.remove_suffix(1);
        const bool matches = (r == "/") || (cgroup_path == r) ||
                             (cgroup_path.size() > r.size() && cgroup_path.compare(0, r.size(), r) == 0 &&
                              cgroup_path[r.size()] == '/');
        if (matches && (!best || r.size() > best_root_len)) {
            best = &m;
            best_root_len = r.size();
        }
    }
    return best ? best : &mounts.front();
}

inline uint64_t parseV2MemoryMax(std::string_view content) {
    const std::string_view trimmed = trimView(content);
    if (trimmed.empty() || trimmed == "max") return kUnlimitedMemory;
    uint64_t value = 0;
    return parseStrictUint64(trimmed, value) ? value : kUnlimitedMemory;
}

inline uint64_t parseV1MemoryStatHierarchical(std::string_view content) {
    constexpr std::string_view kKey = "hierarchical_memory_limit";
    size_t pos = 0;
    while (pos < content.size()) {
        const size_t nl = content.find('\n', pos);
        const std::string_view line = nl == std::string::npos ? content.substr(pos) : content.substr(pos, nl - pos);
        pos = nl == std::string::npos ? content.size() : nl + 1;

        const std::string_view trimmed = trimView(line);
        if (trimmed.size() > kKey.size() &&
            trimmed.compare(0, kKey.size(), kKey) == 0 &&
            (trimmed[kKey.size()] == ' ' || trimmed[kKey.size()] == '\t')) {
            uint64_t value = 0;
            if (parseStrictUint64(trimmed.substr(kKey.size() + 1), value) &&
                value < kCgroupV1UnlimitedThreshold) {
                return value;
            }
        }
    }
    return kUnlimitedMemory;
}

using FileReadFn = std::function<bool(const std::string& path, std::string& content)>;

inline uint64_t resolveCgroupMemoryLimit(const std::string& proc_cgroup,
                                         const std::string& proc_mountinfo,
                                         const FileReadFn& read_file) {
    uint64_t limit = kUnlimitedMemory;
    const CgroupPaths cg = parseProcCgroup(proc_cgroup);
    const ParsedMounts mounts = parseMountInfo(proc_mountinfo);

    if (cg.has_v2) {
        const CgroupMount* mount = selectBestMount(mounts.v2, cg.v2_path);
        const std::string mount_point = mount ? mount->mount_point : "/sys/fs/cgroup";
        const std::string mount_root = mount ? mount->root : "/";
        for (const auto& dir : hierarchyDirectories(mount_point, cg.v2_path, mount_root)) {
            std::string body;
            if (read_file(dir + "/memory.max", body)) {
                limit = std::min(limit, parseV2MemoryMax(body));
            }
        }
    }

    if (cg.has_v1_memory) {
        const CgroupMount* mount = selectBestMount(mounts.v1_memory, cg.v1_memory_path);
        const std::string mount_point = mount ? mount->mount_point : "/sys/fs/cgroup/memory";
        const std::string mount_root = mount ? mount->root : "/";
        const auto dirs = hierarchyDirectories(mount_point, cg.v1_memory_path, mount_root);
        for (const auto& dir : dirs) {
            std::string body;
            if (read_file(dir + "/memory.limit_in_bytes", body)) {
                uint64_t value = 0;
                if (parseStrictUint64(body, value) && value < kCgroupV1UnlimitedThreshold) {
                    limit = std::min(limit, value);
                }
            }
        }
        if (!dirs.empty()) {
            std::string stat_body;
            if (read_file(dirs.back() + "/memory.stat", stat_body)) {
                limit = std::min(limit, parseV1MemoryStatHierarchical(stat_body));
            }
        }
    }

    return limit;
}

} // namespace testsmem4u::cgroup_limit
