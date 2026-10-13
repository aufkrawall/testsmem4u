#pragma once
#include "TestProgress.h"
#include "WorkerProgress.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <vector>

namespace testsmem4u {

// Called by the monitor only, behind --debug. Sample atomics without worker
// clocks/locks; report every ten seconds, capped to the four least-recently
// advancing workers. An idle verified-byte count is diagnostic, not a hang verdict.
class ProgressDiagnostics {
public:
    using Clock = std::chrono::steady_clock;
    ProgressDiagnostics(size_t workers, Clock::time_point start, uint64_t initial_bytes)
        : samples_(workers), order_(workers), last_report_(start), reported_bytes_(initial_bytes) {
        for (auto& sample : samples_) sample.changed = start;
        std::iota(order_.begin(), order_.end(), size_t{0});
    }

    std::string update(Clock::time_point now, const TestResult& totals,
                       const std::vector<ProgressCounters>& workers,
                       const WorkerProgress& progress, size_t sequence_size) {
        for (size_t i = 0; i < workers.size(); ++i) {
            const uint64_t bytes = workers[i].snapshot().bytes_tested;
            if (bytes != samples_[i].bytes) samples_[i].changed = now;
            samples_[i].bytes = bytes;
        }
        if (now - last_report_ < std::chrono::seconds(10)) return {};
        const size_t shown = std::min<size_t>(4, workers.size());
        std::partial_sort(order_.begin(), order_.begin() + shown, order_.end(), [&](size_t a, size_t b) {
            if (samples_[a].changed == samples_[b].changed) return a < b;
            return samples_[a].changed < samples_[b].changed;
        });
        std::ostringstream output;
        output << "Progress: verified-bytes=" << totals.bytes_tested
               << " delta=" << totals.bytes_tested - reported_bytes_
               << " errors=" << totals.total_errors() << " workers=" << workers.size()
               << " omitted=" << workers.size() - shown;
        for (size_t j = 0; j < shown; ++j) {
            const size_t i = order_[j];
            const uint64_t position = progress.completedTests(i);
            output << " | w" << i << " C" << position / sequence_size + 1
                   << " T" << position % sequence_size + 1 << " bytes=" << samples_[i].bytes
                   << " step=" << std::fixed << std::setprecision(1)
                   << workers[i].step() / (ProgressCounters::kStepScale / 100.0) << "%"
                   << " idle=" << std::chrono::duration_cast<std::chrono::seconds>(now - samples_[i].changed).count()
                   << "s phase=" << std::string(workers[i].phase()).substr(0, 32);
        }
        last_report_ = now;
        reported_bytes_ = totals.bytes_tested;
        return output.str();
    }

private:
    struct Sample {
        uint64_t bytes = 0;
        Clock::time_point changed;
    };
    std::vector<Sample> samples_;
    std::vector<size_t> order_;
    Clock::time_point last_report_;
    uint64_t reported_bytes_;
};

} // namespace testsmem4u
