#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <limits>

namespace testsmem4u {

class Utils {
public:
    static std::string trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }

    static bool parseKeyValue(const std::string& line, std::string& key, std::string& value) {
        size_t pos = line.find('=');
        if (pos == std::string::npos) return false;
        key = trim(line.substr(0, pos));
        value = trim(line.substr(pos + 1));
        return !key.empty();
    }

    static bool parseHexStrict(const std::string& str, uint64_t& value) {
        std::string s = trim(str);
        if (s.empty()) return false;

        // Reject leading minus — strtoull wraps negatives silently
        if (s[0] == '-') return false;

        if (s.size() > 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
            s = s.substr(2);
        }
        if (s.empty()) return false;

        errno = 0;
        char* endptr = nullptr;
        unsigned long long parsed = std::strtoull(s.c_str(), &endptr, 16);
        if (errno != 0 || endptr == s.c_str() || *endptr != '\0') {
            return false;
        }

        value = static_cast<uint64_t>(parsed);
        return true;
    }

    static bool parseUintStrict(const std::string& str, uint32_t& value) {
        std::string s = trim(str);
        if (s.empty()) return false;

        // Reject leading minus — strtoul wraps negatives silently
        if (s[0] == '-') return false;

        errno = 0;
        char* endptr = nullptr;
        unsigned long parsed = std::strtoul(s.c_str(), &endptr, 10);
        if (errno != 0 || endptr == s.c_str() || *endptr != '\0' ||
            parsed > std::numeric_limits<uint32_t>::max()) {
            return false;
        }

        value = static_cast<uint32_t>(parsed);
        return true;
    }

    static bool hasUnsafePathControlCharacters(const std::string& path) {
        if (path.empty()) return true;
        for (unsigned char ch : path) {
            if (ch == '\0' || std::iscntrl(ch)) {
                return true;
            }
        }
        return false;
    }

    static std::string sanitizeForLog(const std::string& value) {
        std::string out;
        out.reserve(value.size());
        for (unsigned char ch : value) {
            if (ch >= 0x20 && ch != 0x7F) {
                out.push_back(static_cast<char>(ch));
            } else {
                char escaped[5];
                std::snprintf(escaped, sizeof(escaped), "\\x%02X", ch);
                out += escaped;
            }
        }
        return out;
    }
};

} // namespace testsmem4u
