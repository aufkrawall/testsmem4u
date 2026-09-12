#pragma once
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <vector>

namespace testsmem4u {

// Workers exclusively own their memory and never wait for a peer's test phase.
// Progress is the minimum completed sequence position, not the fastest worker.
class WorkerProgress {
public:
    explicit WorkerProgress(size_t workers) : positions_(workers) {
        for (auto& position : positions_) position.store(0, std::memory_order_relaxed);
    }

    void publish(size_t worker, uint64_t completed_tests) {
        positions_[worker].store(completed_tests, std::memory_order_release);
    }

    uint64_t minimum() const {
        uint64_t result = std::numeric_limits<uint64_t>::max();
        for (const auto& position : positions_) {
            result = std::min(result, position.load(std::memory_order_acquire));
        }
        return positions_.empty() ? 0 : result;
    }

private:
    // Alignment keeps publication traffic off peers' progress cache lines.
    struct alignas(64) Position : std::atomic<uint64_t> {};
    std::vector<Position> positions_;
};

} // namespace testsmem4u
