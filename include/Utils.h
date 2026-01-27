#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstdlib>

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

    static uint64_t parseHex(const std::string& str) {
        std::string s = trim(str);
        if (s.empty()) return 0;

        if (s.size() > 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
            s = s.substr(2);
        }

        char* endptr = nullptr;
        return std::strtoull(s.c_str(), &endptr, 16);
    }

    static uint32_t parseUint(const std::string& str) {
        std::string s = trim(str);
        if (s.empty()) return 0;

        char* endptr = nullptr;
        unsigned long val = std::strtoul(s.c_str(), &endptr, 10);
        return static_cast<uint32_t>(val);
    }
};

} // namespace testsmem4u
