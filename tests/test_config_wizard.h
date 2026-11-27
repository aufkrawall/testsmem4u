#pragma once

class WizardFixture {
    std::string path_ = uniqueTempPath("_wizard.cfg");
public:
    WizardFixture() {
        std::ofstream file(path_);
        file << "Test Sequence=0\n[Test0]\nFunction=SimpleTest\nParameter=1\n";
    }
    ~WizardFixture() { cleanupFile(path_); }
    Config run(const std::string& answers, std::string& prompts) const {
        const size_t custom_choice = listPresets(".").size() + 1;
        std::istringstream input(answers + std::to_string(custom_choice) + "\n" + path_ + "\n");
        std::ostringstream output;
        Config config = runConfigWizard(input, output);
        prompts = output.str();
        return config;
    }
};

void testWizardDefaultPolicies() {
    WizardFixture fixture;
    std::string prompts;
    const Config requested = fixture.run("\n\n\n\n\n\n", prompts);
    expect(requested.memory_window_percent == 85 && requested.memory_window_mb == 0 && requested.cores == 0,
           "Wizard defaults preserve portable 85%-of-RAM and all-core policies");
    expect(requested.cycles == 3 && requested.halt_on_error && requested.use_locked_memory && requested.use_large_pages,
           "Both wizards retain three cycles, halt-on-error, strict locking and large-page preference");
    expect(prompts.find("Prefer large pages (hugepages)? (y/n) [Default: y]") != std::string::npos,
           "Both wizards ask the same large-page preference question");
    Config resolved = requested;
    auto platform = Platform::detectPlatform();
    uint64_t sizing_ram = 0;
    uint32_t requested_mb = 0;
    std::string error;
    expect(prepareConfigForRun(resolved, platform, sizing_ram, requested_mb, error), "Wizard defaults resolve through the shared configuration path");
    expect(resolved.memory_window_percent == 85 && resolved.memory_window_mb > 0 &&
           resolved.cores == std::max(uint32_t{1}, platform.cpu_cores),
           "Resolution applies current system RAM/core counts without changing requested wizard policies");
    const auto path = uniqueTempPath("_wizard.ini");
    expect(saveConfig(path, requested), "Wizard can save the unresolved sizing policies");
    Config loaded;
    expect(loadConfig(path, loaded) && loaded.memory_window_mb == 0 && loaded.memory_window_percent == 85 && loaded.cores == 0,
           "Saved default wizard config remains portable between systems");
    cleanupFile(path);
}

void testWizardExplicitSettings() {
    WizardFixture fixture;
    std::string prompts;
    auto config = fixture.run("17\n2\n1\ny\nn\nn\n", prompts);
    expect(config.memory_window_mb == 17 && config.memory_window_percent == 0 && config.cycles == 1 &&
           config.use_locked_memory && !config.use_large_pages && !config.halt_on_error,
           "Both wizards honor explicit page preference and halt settings in the same question order");
    uint64_t sizing_ram = 0;
    uint32_t requested_mb = 0;
    std::string error;
    expect(prepareConfigForRun(config, Platform::detectPlatform(), sizing_ram, requested_mb, error) && config.memory_window_mb == 17,
           "Explicit no-large-pages window retains every requested MiB");
    config = fixture.run("\n\ninvalid\n\n\n\n", prompts);
    expect(config.cycles == 3 && prompts.find("Invalid cycle count") != std::string::npos,
           "Invalid wizard cycles cannot silently turn a default run into an infinite run");
    config = fixture.run("\nabc\n\n\n\n\n", prompts);
    expect(config.cores == 0 && prompts.find("Invalid thread count") != std::string::npos,
           "Invalid wizard thread input keeps the portable all-core policy instead of saving this system's count");
    config = fixture.run("\n\n0\n\n\n\n", prompts);
    expect(config.cycles == 0, "Explicit infinite-cycle selection remains supported");
}

void testSizingBaselineNote() {
    constexpr uint64_t mib = 1024ULL * 1024ULL;
    constexpr uint64_t unlimited = std::numeric_limits<uint64_t>::max();
    expect(sizingBaselineNote(32768 * mib, unlimited, 32768 * mib).empty(),
           "Wizard adds no sizing note when total RAM is the baseline");
    expect(sizingBaselineNote(32768 * mib, 768 * mib, 768 * mib) == " (768 MB effective process limit)",
           "Wizard names an applied process memory limit");
    expect(sizingBaselineNote(0, unlimited, 4096 * mib) == " (4096 MB currently available)",
           "Wizard labels the available-RAM fallback when total RAM is unknown, not as a process limit");
    expect(sizingBaselineNote(0, 768 * mib, 768 * mib) == " (768 MB effective process limit)",
           "Wizard names the process limit when it caps the available-RAM fallback");
    expect(sizingBaselineNote(0, 8192 * mib, 4096 * mib) == " (4096 MB currently available)",
           "A process limit above the available-RAM fallback is not reported as the baseline");
}

// "Reserved Memory for Windows (Mb)" was parsed but sizing always reserved 256 MB.
void testPresetOsReserveSizing() {
    const auto platform = Platform::detectPlatform();
    auto resolve = [&](uint32_t reserve_mb, uint32_t window_mb, uint64_t& sizing_ram, std::string& error) {
        const auto path = uniqueTempPath("_reserve.cfg");
        {
            std::ofstream file(path);
            file << "[Global Memory Setup]\nReserved Memory for Windows (Mb)=" << reserve_mb
                 << "\nTest Sequence=0\n[Test0]\nFunction=SimpleTest\nParameter=1\n";
        }
        Config config;
        config.preset_file = path;
        config.memory_window_mb = window_mb;
        config.memory_window_percent = window_mb ? 0 : 100;
        config.use_large_pages = false;
        uint32_t requested = 0;
        const bool ok = prepareConfigForRun(config, platform, sizing_ram, requested, error);
        cleanupFile(path);
        return ok ? config.memory_window_mb : 0U;
    };
    uint64_t ram = 0;
    std::string error;
    const uint32_t with_512 = resolve(512, 0, ram, error);
    const uint32_t with_2048 = resolve(2048, 0, ram, error);
    const uint32_t with_0 = resolve(0, 0, ram, error);
    const uint32_t raw_mappable_mb = static_cast<uint32_t>(
        Platform::getMaxMappableMemory(false) / 1024ULL / 1024ULL);
    if (Platform::getMaxMappableMemory(false) == std::numeric_limits<uint64_t>::max() ||
        with_0 < raw_mappable_mb) {
        expect(with_512 > 0 && with_512 - with_2048 == 1536 && with_0 - with_512 == 256,
               "100% sizing subtracts the preset's OS reserve, at least 256 MB");
    } else {
        expect(with_512 == raw_mappable_mb && with_2048 == raw_mappable_mb && with_0 == raw_mappable_mb,
               "100% sizing clamps OS-reserve-adjusted windows to the 32-bit mappable cap");
        const uint64_t sub_2gb_ram = uint64_t{2000} * 1024 * 1024;
        const uint32_t c_256 = computeWindowMBFromPercent(sub_2gb_ram, 100, false, 256);
        const uint32_t c_512 = computeWindowMBFromPercent(sub_2gb_ram, 100, false, 512);
        const uint32_t c_1024 = computeWindowMBFromPercent(sub_2gb_ram, 100, false, 1024);
        expect(c_256 - c_512 == 256 && c_512 - c_1024 == 512,
               "100% sizing still subtracts OS reserve below the 32-bit mappable cap");
    }
    const uint32_t over = static_cast<uint32_t>(ram / 1024 / 1024) - 2048 + 1;
    error.clear();
    expect(resolve(2048, over, ram, error) == 0 && error.find("2048 MB OS reserve") != std::string::npos,
           "An explicit window that eats into the preset's OS reserve is refused with the reason");
    error.clear();
    const uint32_t max_mappable_mb = static_cast<uint32_t>(
        std::min<uint64_t>(Platform::getMaxMappableMemory(false) / 1024 / 1024, over - 1));
    if (sizeof(size_t) == 4 && over - 1 > max_mappable_mb) {
        expect(resolve(2048, over - 1, ram, error) == 0 &&
                   error.find("mappable address-space limit") != std::string::npos,
               "32-bit builds reject explicit windows above their mappable address space");
        error.clear();
    }
    expect(resolve(2048, max_mappable_mb, ram, error) == max_mappable_mb,
           "A window that leaves the OS reserve free is accepted: " + error);
}
