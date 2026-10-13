#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

namespace testsmem4u {

enum class ThpPolicy : uint8_t { UNKNOWN, ALWAYS, MADVISE, NEVER, INHERIT };
enum class ThpControl : uint8_t { GLOBAL, PMD };
enum class ThpReadStatus : uint8_t { OK, MISSING, READ_ERROR };

struct ThpReadResult {
    ThpReadStatus status = ThpReadStatus::READ_ERROR;
    std::string text;
    int error = 0;
};

// Injectable policy I/O keeps regression tests away from machine-wide settings.
class ThpPolicyAccess {
public:
    virtual ~ThpPolicyAccess() = default;
    virtual ThpReadResult read(ThpControl control) = 0;
    virtual int writeMadvise(ThpControl control) = 0; // zero or an errno value
    virtual int processMode() = 0; // PR_GET_THP_DISABLE value or negative errno
};

class NativeThpPolicyAccess : public ThpPolicyAccess {
    std::string root_;
    ThpReadResult controlPath(ThpControl control) const;
public:
    explicit NativeThpPolicyAccess(std::string root = "/sys/kernel/mm/transparent_hugepage");
    ThpReadResult read(ThpControl control) override;
    int writeMadvise(ThpControl control) override;
    int processMode() override;
};

enum class ThpAvailability : uint8_t { READY, DISABLED, UNAVAILABLE, UNKNOWN, PROCESS_DISABLED };

struct ThpPolicySnapshot {
    ThpAvailability availability = ThpAvailability::UNKNOWN;
    ThpPolicy global = ThpPolicy::UNKNOWN;
    ThpPolicy pmd = ThpPolicy::UNKNOWN;
    ThpPolicy effective = ThpPolicy::UNKNOWN;
    bool per_size = false;
    int process_mode = 0;
    int error = 0;
};

enum class ThpSetupResult : uint8_t { SKIPPED, READY, UNAVAILABLE, DECLINED, NEEDS_PRIVILEGE, CHANGED, SETUP_FAILED };

ThpPolicy parseThpPolicy(std::string_view text, bool allow_inherit);
ThpPolicySnapshot inspectThpPolicy(ThpPolicyAccess& access);
ThpSetupResult configureThpForRun(ThpPolicyAccess& access, bool use_large_pages,
                                bool interactive, bool privileged,
                                std::istream& input, std::ostream& output);
ThpSetupResult runLinuxHugePageSetup(bool use_large_pages, bool interactive, bool privileged,
                                   std::istream& input, std::ostream& output);

} // namespace testsmem4u
