#pragma once
#include "TestProgress.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <mutex>
#include <vector>

namespace testsmem4u {

// Workers pull work instead of owning fixed regions. The window is split into
// equal page-aligned chunks; each chunk walks the configured sequence in order
// and is held by at most one worker at a time. A worker that finishes a test
// takes the least advanced idle chunk, so coverage stays even across the window
// however fast individual workers run (SMT siblings, E-cores, CPUs busy with OS
// work). With at least as many chunks as workers an idle chunk always exists
// when a worker claims, so no worker ever waits for a peer. Claims happen once
// per test invocation (seconds to minutes), so a single mutex is uncontended.
class RegionScheduler {
public:
    static constexpr size_t kNone = std::numeric_limits<size_t>::max();

    struct Claim {
        size_t chunk = kNone;
        uint64_t position = 0; // completed sequence entries of that chunk
    };

    struct Snapshot {
        std::vector<uint64_t> positions; // per chunk
        std::vector<size_t> holder;      // per chunk: worker or kNone
        std::vector<size_t> serving;     // per worker: chunk or kNone
    };

    RegionScheduler(size_t chunks, size_t workers)
        : positions_(chunks, 0), holder_(chunks, kNone), released_(chunks, 0), serving_(workers, kNone) {
        // Before any release, ties go to the lowest chunk index.
        for (size_t chunk = 0; chunk < chunks; ++chunk) released_[chunk] = chunk;
        release_counter_ = chunks;
    }

    size_t chunks() const noexcept { return positions_.size(); }
    size_t workers() const noexcept { return serving_.size(); }

    // Least completed position first; ties go to the chunk idle the longest.
    // Returns kNone only if every chunk is held (impossible with chunks >= workers).
    Claim claim(size_t worker) {
        std::lock_guard<std::mutex> lock(mutex_);
        Claim best;
        uint64_t best_release = 0;
        for (size_t chunk = 0; chunk < positions_.size(); ++chunk) {
            if (holder_[chunk] != kNone) continue;
            if (best.chunk == kNone || positions_[chunk] < best.position ||
                (positions_[chunk] == best.position && released_[chunk] < best_release)) {
                best = {chunk, positions_[chunk]};
                best_release = released_[chunk];
            }
        }
        if (best.chunk != kNone) {
            holder_[best.chunk] = worker;
            serving_[worker] = best.chunk;
        }
        return best;
    }

    // Publishes a completed sequence position and returns the chunk to the pool.
    void complete(size_t worker, size_t chunk, uint64_t position) {
        std::lock_guard<std::mutex> lock(mutex_);
        positions_[chunk] = position;
        releaseLocked(worker, chunk);
    }

    // Returns a chunk without publishing progress (cancelled or failed test).
    void abandon(size_t worker, size_t chunk) {
        std::lock_guard<std::mutex> lock(mutex_);
        releaseLocked(worker, chunk);
    }

    // Completed cycles require every chunk: progress is the least advanced one.
    uint64_t minimum() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (positions_.empty()) return 0;
        return *std::min_element(positions_.begin(), positions_.end());
    }

    // One consistent view for the monitor; reuses the caller's capacity.
    void snapshot(Snapshot& out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        out.positions = positions_;
        out.holder = holder_;
        out.serving = serving_;
    }

private:
    void releaseLocked(size_t worker, size_t chunk) {
        holder_[chunk] = kNone;
        released_[chunk] = release_counter_++;
        if (worker < serving_.size()) serving_[worker] = kNone;
    }

    mutable std::mutex mutex_;
    std::vector<uint64_t> positions_;
    std::vector<size_t> holder_;
    std::vector<uint64_t> released_;
    std::vector<size_t> serving_;
    uint64_t release_counter_ = 0;
};

// Returns the claimed chunk on every exit path; complete() publishes progress.
class ChunkLease {
public:
    ChunkLease(RegionScheduler& scheduler, size_t worker, size_t chunk) noexcept
        : scheduler_(scheduler), worker_(worker), chunk_(chunk) {}
    ~ChunkLease() {
        if (chunk_ != RegionScheduler::kNone) scheduler_.abandon(worker_, chunk_);
    }
    ChunkLease(const ChunkLease&) = delete;
    ChunkLease& operator=(const ChunkLease&) = delete;

    void complete(uint64_t position) {
        scheduler_.complete(worker_, chunk_, position);
        chunk_ = RegionScheduler::kNone;
    }

private:
    RegionScheduler& scheduler_;
    size_t worker_;
    size_t chunk_;
};

// The status line follows the least advanced chunk: lowest completed position,
// then lowest current-test step (an idle chunk has not started its next test).
struct SlowestRegion {
    size_t chunk = 0;
    uint64_t position = 0;
    uint32_t step = 0;
};

inline SlowestRegion findSlowestRegion(const RegionScheduler::Snapshot& regions,
                                       const std::vector<ProgressCounters>& counters) {
    SlowestRegion slowest{0, std::numeric_limits<uint64_t>::max(), ProgressCounters::kStepScale};
    for (size_t chunk = 0; chunk < regions.positions.size(); ++chunk) {
        const size_t holder = regions.holder[chunk];
        const uint32_t step = holder < counters.size() ? counters[holder].step() : 0;
        const uint64_t position = regions.positions[chunk];
        if (position < slowest.position || (position == slowest.position && step < slowest.step)) {
            slowest = {chunk, position, step};
        }
    }
    if (regions.positions.empty()) slowest = {};
    return slowest;
}

} // namespace testsmem4u
