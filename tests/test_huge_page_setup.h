#pragma once

class ThpSetupFixture : public ThpPolicyAccess {
public:
    ThpReadResult global{ThpReadStatus::Ok, "always madvise [never]\n", 0};
    ThpReadResult pmd{ThpReadStatus::Ok, "always madvise never [inherit]\n", 0};
    int process_mode = 0;
    int write_error = 0;
    bool ignore_write = false;
    bool corrupt_readback = false;
    bool enable_before_confirmation = false;
    bool change_before_confirmation = false;
    size_t reads = 0;
    size_t global_reads = 0;
    size_t writes = 0;
    ThpControl written_control = ThpControl::Global;
    std::string prompts;

    ThpReadResult read(ThpControl control) override {
        ++reads;
        if (control == ThpControl::Global && ++global_reads == 2) {
            if (enable_before_confirmation) global.text = "always [madvise] never\n";
            if (change_before_confirmation) pmd.text = "always madvise [never] inherit\n";
        }
        if (corrupt_readback && writes > 0) return {ThpReadStatus::Failed, {}, EIO};
        return control == ThpControl::Global ? global : pmd;
    }
    int processMode() override { return process_mode; }
    int writeMadvise(ThpControl control) override {
        ++writes;
        written_control = control;
        if (write_error != 0) return write_error;
        if (!ignore_write) {
            auto& setting = control == ThpControl::Global ? global : pmd;
            setting.text = control == ThpControl::Global ? "always [madvise] never\n" : "always [madvise] never inherit\n";
        }
        return 0;
    }
    ThpSetupResult run(const std::string& answer = "\n", bool interactive = true, bool privileged = true, bool use_pages = true) {
        std::istringstream input(answer);
        std::ostringstream output;
        const auto result = configureThpForRun(*this, use_pages, interactive, privileged, input, output);
        prompts = output.str();
        return result;
    }
};

void testThpPolicyParsing() {
    expect(parseThpPolicy("always [madvise] never\n", false) == ThpPolicy::Madvise,
           "THP policy selects the bracketed active value");
    expect(parseThpPolicy("always madvise never [inherit]\n", true) == ThpPolicy::Inherit,
           "Native-size THP controls can inherit the global policy");
    const std::array<std::string, 11> invalid{{
        "", "always madvise never", "[always] [never]", "[madvise", "madvise]",
        "[[madvise]]", "[future] always", "[madvise] madvise", "[inherit]", "[always] garbage",
        std::string(513, 'x')
    }};
    for (const auto& text : invalid) {
        expect(parseThpPolicy(text, false) == ThpPolicy::Unknown, "Malformed/unknown/oversized THP policy cannot authorize setup");
    }
    ThpSetupFixture fixture;
    expect(inspectThpPolicy(fixture).availability == ThpAvailability::Disabled,
           "PMD inheritance observes a disabled global policy");
    fixture.global.text = "[always] madvise never";
    fixture.pmd.text = "always madvise [never] inherit";
    expect(inspectThpPolicy(fixture).availability == ThpAvailability::Disabled,
           "Per-size never overrides an enabled global policy");
    fixture.global.text = "always madvise [never]";
    fixture.pmd.text = "[always] madvise never inherit";
    expect(inspectThpPolicy(fixture).availability == ThpAvailability::Ready,
           "Per-size always overrides a disabled global policy");
    fixture.pmd = {ThpReadStatus::Missing, {}, ENOENT};
    expect(inspectThpPolicy(fixture).availability == ThpAvailability::Disabled && !inspectThpPolicy(fixture).per_size,
           "Older kernels without per-size controls use the global policy");
}

void testThpSetupConsentAndScope() {
    ThpSetupFixture fixture;
    expect(fixture.run() == ThpSetupResult::Changed && fixture.writes == 1 && fixture.written_control == ThpControl::Pmd,
           "Default-Yes setup enables the native-size control and verifies it once");
    expect(fixture.global.text == "always madvise [never]\n",
           "Native-size setup preserves the global policy and all other size controls");
    expect(fixture.prompts.find("Recommended:") != std::string::npos && fixture.prompts.find("[Y/n]") != std::string::npos &&
           fixture.prompts.find("system-wide") != std::string::npos && fixture.prompts.find("until reboot") != std::string::npos &&
           fixture.prompts.find("No boot configuration is saved") != std::string::npos &&
           fixture.prompts.find("no reboot is required") != std::string::npos,
           "THP setup explains recommendation, consent, scope, runtime persistence and immediate use");
    fixture = ThpSetupFixture{};
    fixture.pmd = {ThpReadStatus::Missing, {}, ENOENT};
    expect(fixture.run("y\n") == ThpSetupResult::Changed && fixture.written_control == ThpControl::Global &&
           fixture.prompts.find("sizes that inherit it") != std::string::npos,
           "Legacy setup changes only global enabled and explains the wider effect");
    for (const auto* answer : {"n\n", "invalid\n", ""}) {
        fixture = ThpSetupFixture{};
        expect(fixture.run(answer) == ThpSetupResult::Declined && fixture.writes == 0,
               "Declining, invalid input and closed stdin never authorize OS changes");
    }
    fixture = ThpSetupFixture{};
    expect(fixture.run("\n", false) == ThpSetupResult::Skipped && fixture.writes == 0 &&
           fixture.prompts.find("[Y/n]") == std::string::npos,
           "Direct/non-interactive runs diagnose disabled THP without prompts or writes");
    fixture = ThpSetupFixture{};
    expect(fixture.run("\n", true, false) == ThpSetupResult::NeedsPrivilege && fixture.writes == 0 &&
           fixture.prompts.find("requires root") != std::string::npos,
           "Unprivileged setup explains sudo and leaves OS settings unchanged");
    fixture = ThpSetupFixture{};
    expect(fixture.run("\n", true, true, false) == ThpSetupResult::Skipped && fixture.reads == 0 && fixture.writes == 0,
           "Disabling large pages bypasses policy probes and setup entirely");
    fixture = ThpSetupFixture{};
    fixture.global.text = "always [madvise] never";
    expect(fixture.run() == ThpSetupResult::Ready && fixture.writes == 0 && fixture.prompts.empty(),
           "Already suitable THP policy runs without an unnecessary setup offer");
}

void testThpSetupFailureAndRechecks() {
    ThpSetupFixture fixture;
    fixture.process_mode = 1;
    expect(fixture.run() == ThpSetupResult::Failed && fixture.writes == 0 &&
           fixture.prompts.find("inherited process policy") != std::string::npos,
           "Inherited complete THP disable cannot trigger ineffective global policy setup");
    fixture = ThpSetupFixture{};
    fixture.process_mode = 3;
    expect(fixture.run() == ThpSetupResult::Changed, "THP except-advised process mode permits the advised test allocation");
    for (const int mode : {-EINVAL, -EPERM, 2, 4}) {
        fixture = ThpSetupFixture{};
        fixture.process_mode = mode;
        expect(fixture.run() == ThpSetupResult::Failed && fixture.writes == 0,
               "Unsupported/unknown process THP policy cannot authorize a global write");
    }
    fixture = ThpSetupFixture{};
    fixture.global = {ThpReadStatus::Missing, {}, ENOENT};
    expect(fixture.run() == ThpSetupResult::Unavailable && fixture.writes == 0,
           "Missing THP support retains existing HugeTLB/native-page fallback");
    fixture = ThpSetupFixture{};
    fixture.pmd = {ThpReadStatus::Failed, {}, EACCES};
    expect(fixture.run() == ThpSetupResult::Failed && fixture.writes == 0,
           "Unreadable per-size policy cannot be mistaken for legacy global-only support");
    fixture = ThpSetupFixture{};
    fixture.pmd.text = "unknown";
    expect(fixture.run() == ThpSetupResult::Failed && fixture.writes == 0, "Malformed per-size policy fails closed");
    fixture = ThpSetupFixture{};
    fixture.write_error = EROFS;
    expect(fixture.run() == ThpSetupResult::Failed && fixture.writes == 1 && fixture.prompts.find("writable sysfs") != std::string::npos,
           "Read-only sysfs produces actionable diagnostics without retries or restoration");
    fixture = ThpSetupFixture{};
    fixture.ignore_write = true;
    expect(fixture.run() == ThpSetupResult::Failed && fixture.prompts.find("could not be verified") != std::string::npos,
           "A successful write return alone cannot claim THP setup success");
    fixture = ThpSetupFixture{};
    fixture.corrupt_readback = true;
    expect(fixture.run() == ThpSetupResult::Failed, "Readback errors prevent a false success message");
    fixture = ThpSetupFixture{};
    fixture.enable_before_confirmation = true;
    expect(fixture.run() == ThpSetupResult::Ready && fixture.writes == 0,
           "Externally enabled policy is rechecked before confirmation and left unchanged");
    fixture = ThpSetupFixture{};
    fixture.change_before_confirmation = true;
    expect(fixture.run() == ThpSetupResult::Failed && fixture.writes == 0 && fixture.prompts.find("changed while waiting") != std::string::npos,
           "A changed disabled policy requires a fresh offer rather than overwriting the administrator's choice");
}

class ThpDirectoryFixture {
public:
    std::string root = uniqueTempPath("_thp");
    ThpDirectoryFixture() { std::filesystem::create_directory(root); }
    ~ThpDirectoryFixture() {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    }
    void put(const std::string& name, const std::string& value) const {
        std::ofstream file(std::filesystem::path(root) / name);
        file << value;
    }
};

void testNativeThpPolicyFiles() {
    ThpDirectoryFixture fixture;
    NativeThpPolicyAccess access(fixture.root);
    expect(access.read(ThpControl::Global).status == ThpReadStatus::Missing, "Native policy reader distinguishes missing controls");
    fixture.put("enabled", "always madvise [never]\n");
    fixture.put("hpage_pmd_size", "2097152\n");
    std::filesystem::create_directory(std::filesystem::path(fixture.root) / "hugepages-2048kB");
    fixture.put("hugepages-2048kB/enabled", "always madvise never [inherit]\n");
    expect(parseThpPolicy(access.read(ThpControl::Pmd).text, true) == ThpPolicy::Inherit,
           "Native policy reader uses the actual PMD page size");
    expect(access.writeMadvise(ThpControl::Pmd) == 0 && access.read(ThpControl::Pmd).text == "madvise\n" &&
           access.read(ThpControl::Global).text == "always madvise [never]\n",
           "Native policy writer flushes exact madvise bytes to the selected control only");
    fixture.put("hpage_pmd_size", "536870912\n");
    std::filesystem::create_directory(std::filesystem::path(fixture.root) / "hugepages-524288kB");
    fixture.put("hugepages-524288kB/enabled", "always [madvise] never inherit\n");
    expect(parseThpPolicy(access.read(ThpControl::Pmd).text, true) == ThpPolicy::Madvise,
           "Native policy paths support non-2-MiB PMD sizes without x86 assumptions");
    for (const auto* size : {"", "-1\n", "3\n", "18446744073709551616\n", "2097152\ngarbage\n"}) {
        fixture.put("hpage_pmd_size", size);
        expect(access.read(ThpControl::Pmd).status == ThpReadStatus::Failed && access.writeMadvise(ThpControl::Pmd) != 0,
               "Invalid or overflowing PMD sizes cannot select an OS control for writing");
    }
    fixture.put("enabled", std::string(513, 'x'));
    expect(access.read(ThpControl::Global).status == ThpReadStatus::Failed, "Native policy reads are bounded");
    NativeThpPolicyAccess missing(fixture.root + "/missing");
    expect(missing.writeMadvise(ThpControl::Global) != 0, "Native policy writer surfaces open failures");
}

void testHugePageSetup() {
    testThpPolicyParsing();
    testThpSetupConsentAndScope();
    testThpSetupFailureAndRechecks();
    testNativeThpPolicyFiles();
}
