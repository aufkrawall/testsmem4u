#include "HugePageSetup.h"
#include "Logger.h"

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <utility>
#ifndef _WIN32
#include <sys/prctl.h>
#endif

namespace testsmem4u {
namespace {

const char* policyName(ThpPolicy policy) {
    switch (policy) {
    case ThpPolicy::Always: return "always";
    case ThpPolicy::Madvise: return "madvise";
    case ThpPolicy::Never: return "never";
    case ThpPolicy::Inherit: return "inherit";
    default: return "unknown";
    }
}

const char* controlName(ThpControl control) {
    return control == ThpControl::Pmd ? "page-size-specific enabled" : "global enabled";
}

ThpReadResult readFile(const std::string& path) {
    FILE* file = std::fopen(path.c_str(), "r");
    if (!file) return {errno == ENOENT ? ThpReadStatus::Missing : ThpReadStatus::Failed, {}, errno};
    std::array<char, 513> buffer{};
    const size_t count = std::fread(buffer.data(), 1, buffer.size(), file);
    int error = std::ferror(file) ? (errno != 0 ? errno : EIO) : 0;
    if (std::fclose(file) != 0 && error == 0) error = errno != 0 ? errno : EIO;
    if (count == buffer.size() && error == 0) error = EOVERFLOW;
    if (error != 0) return {ThpReadStatus::Failed, {}, error};
    return {ThpReadStatus::Ok, std::string(buffer.data(), count), 0};
}

bool samePolicy(const ThpPolicySnapshot& first, const ThpPolicySnapshot& second) {
    return first.availability == second.availability && first.global == second.global &&
           first.pmd == second.pmd && first.per_size == second.per_size &&
           first.process_mode == second.process_mode;
}

void reportInspectionFailure(const ThpPolicySnapshot& snapshot, std::ostream& output) {
    if (snapshot.availability == ThpAvailability::ProcessDisabled) {
        output << "[!] THP is disabled for this process by an inherited process policy.\n"
               << "    Launch from an environment that permits THP; OS policy setup cannot override this.\n";
    } else {
        output << "[!] Could not determine the effective Linux THP policy; leaving OS settings unchanged.\n"
               << "    Huge-page allocation remains best effort; check the THP controls and process policy.\n";
    }
    LOG_WARN("THP setup: inspection unavailable process-mode=%d error=%d; no policy write",
             snapshot.process_mode, snapshot.error);
}

} // namespace

ThpPolicy parseThpPolicy(std::string_view text, bool allow_inherit) {
    if (text.empty() || text.size() > 512) return ThpPolicy::Unknown;
    std::istringstream tokens{std::string(text)};
    std::array<bool, 5> seen{};
    ThpPolicy selected = ThpPolicy::Unknown;
    std::string token;
    while (tokens >> token) {
        const bool active = token.front() == '[';
        if (active) {
            if (token.size() < 3 || token.back() != ']' || selected != ThpPolicy::Unknown) return ThpPolicy::Unknown;
            token = token.substr(1, token.size() - 2);
        }
        ThpPolicy policy = ThpPolicy::Unknown;
        if (token == "always") policy = ThpPolicy::Always;
        else if (token == "madvise") policy = ThpPolicy::Madvise;
        else if (token == "never") policy = ThpPolicy::Never;
        else if (allow_inherit && token == "inherit") policy = ThpPolicy::Inherit;
        if (policy == ThpPolicy::Unknown || seen[static_cast<size_t>(policy)]) return ThpPolicy::Unknown;
        seen[static_cast<size_t>(policy)] = true;
        if (active) selected = policy;
    }
    return selected;
}

NativeThpPolicyAccess::NativeThpPolicyAccess(std::string root) : root_(std::move(root)) {}

ThpReadResult NativeThpPolicyAccess::controlPath(ThpControl control) const {
    if (control == ThpControl::Global) return {ThpReadStatus::Ok, root_ + "/enabled", 0};
    auto size = readFile(root_ + "/hpage_pmd_size");
    if (size.status != ThpReadStatus::Ok) return {ThpReadStatus::Failed, {}, size.error};
    const size_t end = size.text.find_first_of("\r\n");
    const auto number = std::string_view(size.text).substr(0, end);
    uint64_t bytes = 0;
    const auto parsed = std::from_chars(number.data(), number.data() + number.size(), bytes);
    if (parsed.ec != std::errc{} || parsed.ptr != number.data() + number.size() || bytes < 1024 ||
        (bytes & (bytes - 1)) != 0 || (end != std::string::npos && size.text.find_first_not_of("\r\n", end) != std::string::npos)) {
        return {ThpReadStatus::Failed, {}, EINVAL};
    }
    return {ThpReadStatus::Ok, root_ + "/hugepages-" + std::to_string(bytes / 1024) + "kB/enabled", 0};
}

ThpReadResult NativeThpPolicyAccess::read(ThpControl control) {
    const auto path = controlPath(control);
    return path.status == ThpReadStatus::Ok ? readFile(path.text) : path;
}

int NativeThpPolicyAccess::writeMadvise(ThpControl control) {
    const auto path = controlPath(control);
    if (path.status != ThpReadStatus::Ok) return path.error;
    FILE* file = std::fopen(path.text.c_str(), "w");
    if (!file) return errno != 0 ? errno : EIO;
    constexpr char value[] = "madvise\n";
    int error = std::fwrite(value, 1, sizeof(value) - 1, file) == sizeof(value) - 1 ? 0 : (errno != 0 ? errno : EIO);
    if (std::fflush(file) != 0 && error == 0) error = errno != 0 ? errno : EIO;
    if (std::fclose(file) != 0 && error == 0) error = errno != 0 ? errno : EIO;
    return error;
}

int NativeThpPolicyAccess::processMode() {
#ifndef _WIN32
    const int mode = prctl(PR_GET_THP_DISABLE, 0UL, 0UL, 0UL, 0UL);
    return mode < 0 ? -errno : mode;
#else
    return 0; // Portable filesystem fixtures; the Windows startup never calls this setup.
#endif
}

ThpPolicySnapshot inspectThpPolicy(ThpPolicyAccess& access) {
    ThpPolicySnapshot snapshot;
    const auto global = access.read(ThpControl::Global);
    snapshot.error = global.error;
    if (global.status == ThpReadStatus::Missing) {
        snapshot.availability = ThpAvailability::Unavailable;
        return snapshot;
    }
    if (global.status != ThpReadStatus::Ok) return snapshot;
    snapshot.global = parseThpPolicy(global.text, false);
    if (snapshot.global == ThpPolicy::Unknown) { snapshot.error = EINVAL; return snapshot; }
    const auto pmd = access.read(ThpControl::Pmd);
    snapshot.error = pmd.error;
    if (pmd.status == ThpReadStatus::Failed) return snapshot;
    snapshot.per_size = pmd.status == ThpReadStatus::Ok;
    if (snapshot.per_size) {
        snapshot.pmd = parseThpPolicy(pmd.text, true);
        if (snapshot.pmd == ThpPolicy::Unknown) { snapshot.error = EINVAL; return snapshot; }
    }
    snapshot.effective = snapshot.per_size && snapshot.pmd != ThpPolicy::Inherit ? snapshot.pmd : snapshot.global;
    snapshot.process_mode = access.processMode();
    snapshot.error = snapshot.process_mode < 0 ? -snapshot.process_mode : 0;
    if (snapshot.process_mode == 1) snapshot.availability = ThpAvailability::ProcessDisabled;
    else if (snapshot.process_mode == 0 || snapshot.process_mode == 3) {
        snapshot.availability = snapshot.effective == ThpPolicy::Never ? ThpAvailability::Disabled : ThpAvailability::Ready;
    }
    return snapshot;
}

ThpSetupResult configureThpForRun(ThpPolicyAccess& access, bool use_large_pages,
                                bool interactive, bool privileged,
                                std::istream& input, std::ostream& output) {
    if (!use_large_pages) return ThpSetupResult::Skipped;
    const auto initial = inspectThpPolicy(access);
    LOG_DEBUG("THP setup: global=%s PMD=%s per-size=%s effective=%s process-mode=%d error=%d",
              policyName(initial.global), policyName(initial.pmd), initial.per_size ? "yes" : "no",
              policyName(initial.effective), initial.process_mode, initial.error);
    if (initial.availability == ThpAvailability::Ready) return ThpSetupResult::Ready;
    if (initial.availability == ThpAvailability::Unavailable) {
        output << "[!] Linux THP controls are unavailable. Existing HugeTLB and locked native-page fallback remain supported.\n";
        return ThpSetupResult::Unavailable;
    }
    if (initial.availability != ThpAvailability::Disabled) {
        reportInspectionFailure(initial, output);
        return ThpSetupResult::Failed;
    }
    const auto control = initial.per_size ? ThpControl::Pmd : ThpControl::Global;
    output << "\n[!] Linux THP policy is 'never' for the huge-page size requested by this test.\n"
           << "    Recommended: use 'madvise' so allocations that request THP can receive huge pages.\n"
           << "    Setting: /sys/kernel/mm/transparent_hugepage/"
           << (initial.per_size ? "hugepages-<PMD-size>kB/enabled" : "enabled") << '\n'
           << (initial.per_size ? "    This changes system-wide policy for that page size and also affects other applications.\n" :
                                  "    This changes the system-wide default, including THP sizes that inherit it, and affects other applications.\n")
           << "    The runtime change lasts until reboot or another policy change.\n"
           << "    No boot configuration is saved. No reboot or sign-out is needed; this run can use it immediately.\n";
    if (!interactive) {
        output << "    Direct/non-interactive mode: skipping automatic THP policy setup.\n";
        LOG_DEBUG("THP setup: disabled policy; skipped non-interactive write");
        return ThpSetupResult::Skipped;
    }
    if (!privileged) {
        output << "    Automatic setup requires root. Relaunch with sudo to receive the setup offer.\n";
        LOG_DEBUG("THP setup: disabled policy; setup requires root");
        return ThpSetupResult::NeedsPrivilege;
    }
    output << "    Enable 'madvise' now? [Y/n]: " << std::flush;
    std::string answer;
    if (!std::getline(input, answer)) {
        output << "    No answer received; leaving OS settings unchanged.\n";
        LOG_DEBUG("THP setup: input closed; no policy write");
        return ThpSetupResult::Declined;
    }
    if (!answer.empty() && answer != "y" && answer != "Y" && answer != "yes" && answer != "Yes" && answer != "YES") {
        output << "    Leaving OS settings unchanged; huge-page allocation remains best effort.\n";
        LOG_DEBUG("THP setup: offer declined; no policy write");
        return ThpSetupResult::Declined;
    }
    // A user may leave the prompt open while an administrator changes policy.
    // Recheck before writing; never restore an old snapshot over somebody else's settings.
    const auto current = inspectThpPolicy(access);
    if (current.availability == ThpAvailability::Ready) {
        output << "    THP policy now permits this run; no setup change is needed.\n";
        LOG_DEBUG("THP setup: policy enabled externally before confirmation");
        return ThpSetupResult::Ready;
    }
    if (!samePolicy(initial, current)) {
        output << "[!] THP policy changed while waiting for confirmation; leaving it unchanged. Rerun to inspect it again.\n";
        LOG_WARN("THP setup: policy changed before write; no policy write");
        return ThpSetupResult::Failed;
    }
    const int error = access.writeMadvise(control);
    if (error != 0) {
        output << "[!] Could not complete THP policy setup (error " << error << "). Check root access and writable sysfs.\n"
               << "    A write may have partially applied; inspect THP policy. Huge-page allocation remains best effort.\n";
        LOG_WARN("THP setup: write failed control=%s error=%d; no retry or restoration", controlName(control), error);
        return ThpSetupResult::Failed;
    }
    const auto verified = inspectThpPolicy(access);
    const auto selected = control == ThpControl::Pmd ? verified.pmd : verified.global;
    if (verified.availability != ThpAvailability::Ready || selected != ThpPolicy::Madvise) {
        output << "[!] THP policy write could not be verified. Another policy manager may have changed it; check THP settings.\n"
               << "    Huge-page allocation remains best effort.\n";
        LOG_WARN("THP setup: readback failed control=%s effective=%s process-mode=%d error=%d",
                 controlName(control), policyName(verified.effective), verified.process_mode, verified.error);
        return ThpSetupResult::Failed;
    }
    output << "[+] THP 'madvise' policy verified. Continuing this run; no reboot is required.\n";
    LOG_INFO("THP setup: control=%s policy=madvise verified=yes persistence=runtime", controlName(control));
    return ThpSetupResult::Changed;
}

ThpSetupResult runLinuxHugePageSetup(bool use_large_pages, bool interactive, bool privileged,
                                   std::istream& input, std::ostream& output) {
    NativeThpPolicyAccess access;
    return configureThpForRun(access, use_large_pages, interactive, privileged, input, output);
}

} // namespace testsmem4u
