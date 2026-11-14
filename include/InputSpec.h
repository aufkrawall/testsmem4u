#pragma once

// Shared parsing of user-entered memory sizes and time limits (wizard, CLI,
// saved configuration), so every entry point accepts the same spellings.

#include <cctype>
#include <cstdint>
#include <limits>
#include <string>

namespace testsmem4u {

// Longest accepted time limit: one year. Larger values are almost certainly typos.
constexpr uint64_t kMaxTimeLimitSeconds = uint64_t{366} * 24 * 3600;

struct MemoryTimeInput {
    uint32_t memory_mb = 0;          // explicit size in MiB (0 when a percentage was given)
    uint32_t memory_percent = 0;     // percentage of RAM as entered (0 when a size was given)
    uint64_t time_limit_seconds = 0; // 0 when no time limit was given
};

namespace input_spec {

inline void skipSpaces(const std::string& text, size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
}

// Reads a decimal integer at text[pos]; false without digits or on overflow.
inline bool readNumber(const std::string& text, size_t& pos, uint64_t& value) {
    const size_t start = pos;
    value = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        const uint64_t digit = static_cast<uint64_t>(text[pos] - '0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
        ++pos;
    }
    return pos != start;
}

// Reads a unit (letters or '%') at text[pos], lower-cased.
inline std::string readUnit(const std::string& text, size_t& pos) {
    std::string unit;
    while (pos < text.size() && (std::isalpha(static_cast<unsigned char>(text[pos])) || text[pos] == '%')) {
        unit.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(text[pos]))));
        ++pos;
    }
    return unit;
}

inline uint64_t timeUnitSeconds(const std::string& unit) {
    if (unit == "h" || unit == "hr" || unit == "hrs" || unit == "hour" || unit == "hours") return 3600;
    if (unit == "m" || unit == "min" || unit == "mins" || unit == "minute" || unit == "minutes") return 60;
    if (unit == "s" || unit == "sec" || unit == "secs" || unit == "second" || unit == "seconds") return 1;
    return 0;
}

} // namespace input_spec

// Time limit such as "4h", "30m", "1h30m", "2h 15m" or "90s". A bare number
// means minutes when allow_bare_minutes is set (CLI), otherwise it needs a unit.
inline bool parseTimeLimit(const std::string& text, uint64_t& seconds, std::string& error,
                           bool allow_bare_minutes) {
    size_t pos = 0;
    uint64_t total = 0;
    size_t parts = 0;
    input_spec::skipSpaces(text, pos);
    while (pos < text.size()) {
        uint64_t amount = 0;
        if (!input_spec::readNumber(text, pos, amount)) {
            error = "Time limit must look like 4h, 30m, 1h30m or 90s.";
            return false;
        }
        input_spec::skipSpaces(text, pos);
        const std::string unit = input_spec::readUnit(text, pos);
        uint64_t scale = input_spec::timeUnitSeconds(unit);
        if (unit.empty() && allow_bare_minutes && parts == 0) {
            input_spec::skipSpaces(text, pos);
            if (pos == text.size()) scale = 60;
        }
        if (scale == 0) {
            error = unit.empty() ? "Time limit needs a unit: h, m or s (for example 4h or 30m)."
                                 : "Unknown time unit '" + unit + "'; use h, m or s.";
            return false;
        }
        if (amount > kMaxTimeLimitSeconds / scale || total + amount * scale > kMaxTimeLimitSeconds) {
            error = "Time limit is longer than one year.";
            return false;
        }
        total += amount * scale;
        ++parts;
        input_spec::skipSpaces(text, pos);
    }
    if (parts == 0) {
        error = "Time limit is empty.";
        return false;
    }
    if (total == 0) {
        error = "Time limit must be longer than 0 seconds.";
        return false;
    }
    seconds = total;
    return true;
}

// "<memory>[<time limit>]". Memory: "85%", "2048" (MiB), "2048MB", "2048M",
// "27GB", "27G" (MB/GB are binary, as everywhere in this program). An optional
// time limit may follow directly or after spaces: "27GB4h", "50MB30m",
// "85% 2h". The first number is always the memory size, so after it "m" means
// minutes; a bare MiB number needs a space before the time ("2048 30m").
// Percentages are returned as entered (callers decide how to treat > 100).
inline bool parseMemoryAndTime(const std::string& text, MemoryTimeInput& out, std::string& error) {
    out = MemoryTimeInput{};
    size_t pos = 0;
    input_spec::skipSpaces(text, pos);
    uint64_t amount = 0;
    if (!input_spec::readNumber(text, pos, amount)) {
        error = "Memory must start with a number, for example 85%, 2048MB or 27GB.";
        return false;
    }
    input_spec::skipSpaces(text, pos);
    const std::string unit = input_spec::readUnit(text, pos);
    uint64_t mb = 0;
    if (unit == "%") {
        if (amount == 0 || amount > std::numeric_limits<uint32_t>::max()) {
            error = "Memory percentage must be at least 1%.";
            return false;
        }
        out.memory_percent = static_cast<uint32_t>(amount);
    } else if (unit.empty() || unit == "m" || unit == "mb" || unit == "mib") {
        mb = amount;
    } else if (unit == "g" || unit == "gb" || unit == "gib") {
        if (amount > std::numeric_limits<uint32_t>::max() / 1024) {
            error = "Memory size is too large.";
            return false;
        }
        mb = amount * 1024;
    } else {
        error = "Unknown memory unit '" + unit + "'; use %, MB or GB.";
        return false;
    }
    if (unit != "%") {
        if (mb == 0 || mb > std::numeric_limits<uint32_t>::max()) {
            error = mb == 0 ? "Memory size must be larger than 0 MB." : "Memory size is too large.";
            return false;
        }
        out.memory_mb = static_cast<uint32_t>(mb);
    }
    input_spec::skipSpaces(text, pos);
    // A unitless time ("2048 30") is rejected rather than guessed.
    if (pos < text.size() && !parseTimeLimit(text.substr(pos), out.time_limit_seconds, error, false)) return false;
    return true;
}

// "4h", "30m", "1h30m", "1m30s", "45s" (0 = "none").
inline std::string formatTimeLimit(uint64_t seconds) {
    if (seconds == 0) return "none";
    const uint64_t hours = seconds / 3600;
    const uint64_t minutes = (seconds % 3600) / 60;
    const uint64_t rest = seconds % 60;
    std::string text;
    if (hours) text += std::to_string(hours) + "h";
    if (minutes) text += std::to_string(minutes) + "m";
    if (rest) text += std::to_string(rest) + "s";
    return text;
}

} // namespace testsmem4u
