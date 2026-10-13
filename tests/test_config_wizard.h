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
