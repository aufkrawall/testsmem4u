#pragma once
#include "TestProgress.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace testsmem4u {

// Workers pull work instead of owning fixed regions. The window is split into
// equal page-aligned chunks; each chunk walks the configured sequence in order
// and is held by at most one worker at a time. A worker that finishes a test
// takes the least advanced idle chunk other than the one it just finished, so
// coverage stays even across the window however fast individual workers run
// (SMT siblings, E-cores, CPUs busy with OS work). Re-claiming the finished
// chunk would let a slow worker keep its own lagging chunk, which then advances
// only at that worker's pace (simulated: 42% of the average rate with one 2.5x
// slower worker of 16). With chunks >= workers an idle chunk always exists when
// a worker claims, so no worker ever waits for a peer. Claims happen once per
// test invocation (seconds to minutes), so a single mutex is uncontended.
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
        : positions_(chunks, 0), holder_(chunks, kNone), released_(chunks, 0), serving_(workers, kNone),
          finished_(workers, kNone) {
        // Before any release, ties go to the lowest chunk index.
        for (size_t chunk = 0; chunk < chunks; ++chunk) released_[chunk] = chunk;
        release_counter_ = chunks;
    }

    size_t chunks() const noexcept { return positions_.size(); }
    size_t workers() const noexcept { return serving_.size(); }

    // Least completed position first; ties go to the chunk idle the longest.
    // The worker's just-finished chunk is taken only when nothing else is idle.
    // Returns kNone only if every chunk is held (impossible with chunks >= workers).
    Claim claim(size_t worker) {
        std::lock_guard<std::mutex> lock(mutex_);
        const size_t finished = worker < finished_.size() ? finished_[worker] : kNone;
        Claim best = pick(finished);
        if (best.chunk == kNone) best = pick(kNone);
        if (best.chunk != kNone) {
            holder_[best.chunk] = worker;
            if (worker < serving_.size()) serving_[worker] = best.chunk;
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
    Claim pick(size_t excluded) const {
        Claim best;
        uint64_t best_release = 0;
        for (size_t chunk = 0; chunk < positions_.size(); ++chunk) {
            if (holder_[chunk] != kNone || chunk == excluded) continue;
            if (best.chunk == kNone || positions_[chunk] < best.position ||
                (positions_[chunk] == best.position && released_[chunk] < best_release)) {
                best = {chunk, positions_[chunk]};
                best_release = released_[chunk];
            }
        }
        return best;
    }

    void releaseLocked(size_t worker, size_t chunk) {
        holder_[chunk] = kNone;
        released_[chunk] = release_counter_++;
        if (worker < serving_.size()) {
            serving_[worker] = kNone;
            finished_[worker] = chunk;
        }
    }

    mutable std::mutex mutex_;
    std::vector<uint64_t> positions_;
    std::vector<size_t> holder_;
    std::vector<uint64_t> released_;
    std::vector<size_t> serving_;
    std::vector<size_t> finished_; // per worker: chunk it released last
    uint64_t release_counter_ = 0;
};

// Chunk positions count enabled sequence entries only. Walking disabled entries
// cost a claim and a release each, and every release replaced the worker's
// just-finished chunk: after skipping a disabled entry elsewhere, a slow worker
// could re-claim the lagging chunk it had just finished. Disabled entries also
// logged zero-second completions and could name the status line's test.
// Logs, status and timings keep the original sequence index (entry()).
//
// Interleaved presets list one test ID several times per cycle (TestMem5
// style: short slices of MirrorMove128 between other tests). Pass variation
// used to depend on (cycle, loop) only, so every occurrence of an ID in a cycle
// rewrote identical data. pass() numbers occurrences instead: occurrence k of
// K in chunk cycle c is pass c * K + k. An ID listed once keeps pass == cycle,
// so single-occurrence presets write exactly the data they wrote before.
//
// Staggered start (opt-in): chunk c begins its sequence at enabled slot
// c * N / chunks, so concurrently running workers execute different tests and
// the traffic mix stays constant over the run. Each chunk still runs every
// enabled slot exactly once per chunk cycle; cycle() and startsCycle() count
// completed invocations of the chunk, independent of its starting slot.
struct EnabledSequence {
    std::vector<size_t> entries;        // sequence index of each enabled entry, in order
    std::vector<uint32_t> occurrence;   // per slot: earlier enabled slots with the same test ID
    std::vector<uint32_t> occurrences;  // per slot: enabled slots with that test ID per cycle
    size_t chunks = 1;
    bool staggered = false;

    EnabledSequence() = default;
    // Treats every slot as a distinct test ID (one occurrence each).
    explicit EnabledSequence(std::vector<size_t> enabled)
        : entries(std::move(enabled)), occurrence(entries.size(), 0), occurrences(entries.size(), 1) {}
    // sequence: the full configured sequence of test IDs that entries index.
    EnabledSequence(std::vector<size_t> enabled, const std::vector<uint32_t>& sequence, size_t chunk_count,
                    bool stagger)
        : entries(std::move(enabled)), occurrence(entries.size(), 0), occurrences(entries.size(), 1),
          chunks(std::max<size_t>(1, chunk_count)), staggered(stagger) {
        for (size_t slot = 0; slot < entries.size(); ++slot) {
            uint32_t earlier = 0;
            uint32_t total = 0;
            for (size_t other = 0; other < entries.size(); ++other) {
                if (sequence[entries[other]] != sequence[entries[slot]]) continue;
                ++total;
                if (other < slot) ++earlier;
            }
            occurrence[slot] = earlier;
            occurrences[slot] = total;
        }
    }

    size_t size() const noexcept { return entries.size(); }
    // First enabled slot of a chunk (0 unless staggered).
    size_t offset(size_t chunk) const {
        if (!staggered || entries.empty()) return 0;
        return static_cast<size_t>((static_cast<uint64_t>(chunk % chunks) * entries.size()) / chunks);
    }
    size_t slot(uint64_t position, size_t chunk) const {
        return static_cast<size_t>((position + offset(chunk)) % entries.size());
    }
    uint64_t cycle(uint64_t position) const { return position / entries.size(); }
    size_t entry(uint64_t position, size_t chunk) const { return entries[slot(position, chunk)]; }
    bool startsCycle(uint64_t position) const { return position % entries.size() == 0; }
    // Data pass of this invocation: unique per chunk, cycle and occurrence.
    uint64_t pass(uint64_t position, size_t chunk) const {
        const size_t s = slot(position, chunk);
        return cycle(position) * occurrences[s] + occurrence[s];
    }
};

// One startup line describing the cycle: enabled slots, distinct test IDs and
// the IDs listed more than once (capped), so an interleaved preset's structure
// is visible in every log without reading the preset.
inline std::string describeSequence(const EnabledSequence& sequence, const std::vector<uint32_t>& ids,
                                    const std::map<uint32_t, TestConfig>& configs) {
    std::vector<uint32_t> distinct;
    std::string repeated;
    size_t repeated_ids = 0;
    for (size_t slot = 0; slot < sequence.size(); ++slot) {
        const uint32_t id = ids[sequence.entries[slot]];
        if (std::find(distinct.begin(), distinct.end(), id) != distinct.end()) continue;
        distinct.push_back(id);
        if (sequence.occurrences[slot] < 2) continue;
        if (++repeated_ids <= 8) {
            const auto config = configs.find(id);
            repeated += (repeated.empty() ? "" : ", ") +
                        (config == configs.end() ? std::string("?") : config->second.function) + "(Test" +
                        std::to_string(id) + ") x" + std::to_string(sequence.occurrences[slot]);
        }
    }
    if (repeated_ids > 8) repeated += ", +" + std::to_string(repeated_ids - 8) + " more";
    return "Sequence: " + std::to_string(sequence.size()) + " enabled entries per cycle, " +
           std::to_string(distinct.size()) + " distinct tests; repeated per cycle: " +
           (repeated.empty() ? std::string("none") : repeated);
}

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
