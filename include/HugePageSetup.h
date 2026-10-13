#pragma once

#include <iosfwd>
#include <string>
#include <string_view>

namespace testsmem4u {

enum class ThpPolicy { Unknown, Always, Madvise, Never, Inherit };
enum class ThpControl { Global, Pmd };
enum class ThpReadStatus { Ok, Missing, Failed };

struct ThpReadResult {
    ThpReadStatus status = ThpReadStatus::Failed;
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

enum class ThpAvailability { Ready, Disabled, Unavailable, Unknown, ProcessDisabled };

struct ThpPolicySnapshot {
    ThpAvailability availability = ThpAvailability::Unknown;
    ThpPolicy global = ThpPolicy::Unknown;
    ThpPolicy pmd = ThpPolicy::Unknown;
    ThpPolicy effective = ThpPolicy::Unknown;
    bool per_size = false;
    int process_mode = 0;
    int error = 0;
};

enum class ThpSetupResult { Skipped, Ready, Unavailable, Declined, NeedsPrivilege, Changed, Failed };

ThpPolicy parseThpPolicy(std::string_view text, bool allow_inherit);
ThpPolicySnapshot inspectThpPolicy(ThpPolicyAccess& access);
ThpSetupResult configureThpForRun(ThpPolicyAccess& access, bool use_large_pages,
                                bool interactive, bool privileged,
                                std::istream& input, std::ostream& output);
ThpSetupResult runLinuxHugePageSetup(bool use_large_pages, bool interactive, bool privileged,
                                   std::istream& input, std::ostream& output);

} // namespace testsmem4u
