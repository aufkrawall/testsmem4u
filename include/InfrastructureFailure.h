#pragma once
#include "TestEngine.h"
#include "Logger.h"
#include <exception>
#include <optional>

namespace testsmem4u {

// summary is a static literal. Record failure/stop before allocating the detail
// string or using the logger, which may be the source of the original failure.
// A failing diagnostic must never escape a thread or replace the first cause.
inline void reportInfrastructureFailure(TestContext& ctx, const char* summary, const char* detail,
                                        std::optional<uint32_t> worker = std::nullopt) noexcept {
    const bool first = ctx.beginInfrastructureFailure(summary);
    try {
        std::string message = std::string(summary) + ": ";
        if (worker) message += "worker=" + std::to_string(*worker) + " ";
        message += detail;
        if (first) ctx.storeInfrastructureFailureMessage(message);
        LOG_ERROR("%s", message.c_str());
    } catch (...) {
        // C stdio avoids C++ allocation and logger/console exception paths.
        // Keep one bounded line per failure even when detailed logging fails.
        if (worker) {
            std::fprintf(stderr, "%s: worker=%u %.256s (diagnostics unavailable)\n", summary, *worker, detail);
        } else {
            std::fprintf(stderr, "%s: %.256s (diagnostics unavailable)\n", summary, detail);
        }
    }
}

} // namespace testsmem4u
