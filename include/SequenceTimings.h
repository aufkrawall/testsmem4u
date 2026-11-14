#pragma once
#include "Types.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace testsmem4u {

// Run-end time breakdown per sequence entry and cycle-completion milestones, so
// one log shows where a cycle's time goes and how soon every test type first
// runs, without --debug or post-processing. Workers record once per invocation
// (seconds to minutes apart), so one mutex is uncontended. Formatting returns
// lines; the caller logs them (keeps this testable without log capture).
class SequenceTimings {
public:
    using Clock = std::chrono::steady_clock;

    SequenceTimings(size_t entries, Clock::time_point start) : entries_(entries), start_(start) {}

    // completed=false records an invocation cut short by a stop request. Its
    // bytes were verified and count in the run total, so they count here too
    // (as its time does in worker-seconds); otherwise entries stopped late in
    // a run reported verified=0 against GiBs of real coverage.
    void record(size_t entry, Clock::time_point began, Clock::time_point ended, uint64_t verified_bytes,
                bool completed) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (entry >= entries_.size()) return;
        Entry& item = entries_[entry];
        const double seconds = std::chrono::duration<double>(ended - began).count();
        const double offset = std::chrono::duration<double>(began - start_).count();
        item.bytes += verified_bytes;
        if (completed) {
            ++item.runs;
            item.seconds += seconds;
        } else {
            ++item.stopped;
            item.stopped_seconds += seconds;
        }
        if (item.first_start < 0 || offset < item.first_start) item.first_start = offset;
    }

    // One line per newly completed whole-window cycle (least advanced chunk).
    std::vector<std::string> cycleMilestones(uint64_t completed_cycles, Clock::time_point now) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> lines;
        const double elapsed = std::chrono::duration<double>(now - start_).count();
        while (logged_cycles_ < completed_cycles) {
            ++logged_cycles_;
            char line[160];
            std::snprintf(line, sizeof(line), "Cycle %llu complete on every chunk after %.1fs (%.1f min)",
                          static_cast<unsigned long long>(logged_cycles_), elapsed, elapsed / 60.0);
            lines.emplace_back(line);
        }
        return lines;
    }

    std::vector<std::string> summary(const std::vector<uint32_t>& sequence,
                                     const std::map<uint32_t, TestConfig>& configs, size_t workers,
                                     size_t chunks, size_t chunk_bytes, double wall_seconds) const {
        std::lock_guard<std::mutex> lock(mutex_);
        double total = 0;
        for (const auto& item : entries_) total += item.seconds + item.stopped_seconds;
        std::vector<std::string> lines;
        char line[256];
        std::snprintf(line, sizeof(line),
                      "Time breakdown: wall=%.1fs workers=%zu chunks=%zu chunk-MiB=%.1f worker-seconds=%.1f "
                      "(share of worker time; first = seconds after start)",
                      wall_seconds, workers, chunks, static_cast<double>(chunk_bytes) / (1024.0 * 1024.0), total);
        lines.emplace_back(line);
        for (size_t i = 0; i < entries_.size() && i < sequence.size(); ++i) {
            const Entry& item = entries_[i];
            const auto config = configs.find(sequence[i]);
            const char* name = config == configs.end() ? "?" : config->second.function.c_str();
            if (config != configs.end() && !config->second.enabled) {
                std::snprintf(line, sizeof(line), "  #%-2zu %-22s disabled", i + 1, name);
            } else if (item.runs == 0 && item.stopped == 0) {
                std::snprintf(line, sizeof(line), "  #%-2zu %-22s not reached", i + 1, name);
            } else {
                const double share = total > 0 ? 100.0 * (item.seconds + item.stopped_seconds) / total : 0;
                int used = std::snprintf(line, sizeof(line),
                                         "  #%-2zu %-22s share=%5.1f%% runs=%llu avg=%.2fs first=%.1fs verified=%.2fGiB",
                                         i + 1, name, share, static_cast<unsigned long long>(item.runs),
                                         item.runs ? item.seconds / static_cast<double>(item.runs) : 0.0,
                                         item.first_start, static_cast<double>(item.bytes) / (1024.0 * 1024.0 * 1024.0));
                if (item.stopped && used > 0 && static_cast<size_t>(used) < sizeof(line)) {
                    std::snprintf(line + used, sizeof(line) - static_cast<size_t>(used), " stopped=%llu/%.1fs",
                                  static_cast<unsigned long long>(item.stopped), item.stopped_seconds);
                }
            }
            lines.emplace_back(line);
        }
        return lines;
    }

    // Totals per test function across all its sequence entries, in order of
    // first appearance. Interleaved presets list a function several times per
    // cycle; this answers how much of the run each kind of stress got and how
    // soon it first ran without summing per-entry lines by hand.
    std::vector<std::string> functionSummary(const std::vector<uint32_t>& sequence,
                                             const std::map<uint32_t, TestConfig>& configs) const {
        std::lock_guard<std::mutex> lock(mutex_);
        struct Total {
            std::string name;
            size_t entries = 0;
            Entry sum;
        };
        std::vector<Total> totals;
        double all = 0;
        for (size_t i = 0; i < entries_.size() && i < sequence.size(); ++i) {
            const auto config = configs.find(sequence[i]);
            if (config == configs.end() || !config->second.enabled) continue;
            const Entry& item = entries_[i];
            all += item.seconds + item.stopped_seconds;
            auto total = std::find_if(totals.begin(), totals.end(),
                                      [&](const Total& t) { return t.name == config->second.function; });
            if (total == totals.end()) {
                totals.push_back({config->second.function, 0, Entry{}});
                total = totals.end() - 1;
            }
            ++total->entries;
            total->sum.runs += item.runs;
            total->sum.stopped += item.stopped;
            total->sum.seconds += item.seconds;
            total->sum.stopped_seconds += item.stopped_seconds;
            total->sum.bytes += item.bytes;
            if (item.first_start >= 0 && (total->sum.first_start < 0 || item.first_start < total->sum.first_start)) {
                total->sum.first_start = item.first_start;
            }
        }
        std::vector<std::string> lines;
        lines.emplace_back("Time by function (entries = sequence slots per cycle; first = seconds after start):");
        char line[256];
        for (const Total& total : totals) {
            const Entry& item = total.sum;
            if (item.runs == 0 && item.stopped == 0) {
                std::snprintf(line, sizeof(line), "  %-22s entries=%zu not reached", total.name.c_str(), total.entries);
            } else {
                const double share = all > 0 ? 100.0 * (item.seconds + item.stopped_seconds) / all : 0;
                std::snprintf(line, sizeof(line),
                              "  %-22s share=%5.1f%% entries=%zu runs=%llu stopped=%llu first=%.1fs verified=%.2fGiB",
                              total.name.c_str(), share, total.entries, static_cast<unsigned long long>(item.runs),
                              static_cast<unsigned long long>(item.stopped), item.first_start,
                              static_cast<double>(item.bytes) / (1024.0 * 1024.0 * 1024.0));
            }
            lines.emplace_back(line);
        }
        return lines;
    }

private:
    struct Entry {
        uint64_t runs = 0;
        uint64_t stopped = 0;
        double seconds = 0;
        double stopped_seconds = 0;
        uint64_t bytes = 0;
        double first_start = -1;
    };
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
    Clock::time_point start_;
    uint64_t logged_cycles_ = 0;
};

} // namespace testsmem4u
