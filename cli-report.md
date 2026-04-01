## Current CLI Contract

### Default startup behavior

- The executable looks for config.ini in the current working directory unless --no-config is used.
- With an interactive stdin session and no run-specific CLI overrides, it shows a 3-second startup delay.
- Pressing a key during that delay opens the configuration wizard.
- If no key is pressed, the saved or default settings are used and the test run starts.

### Direct CLI mode

The program switches to direct, prompt-free execution when any of the following is true:

- --yes or --non-interactive is used.
- stdin is not interactive.
- A run-specific override is used, such as --preset, --memory, --cores, --cycles, --halt-on-error, --locked-memory, --large-pages, --show-config, or --dry-run.

In direct mode:

- The wizard is skipped.
- Exit pauses are suppressed.
- Windows privilege-grant prompts are skipped.

### Option reference

| Option | Behavior |
| --- | --- |
| -h, --help | Print usage and exit. |
| -v, --version | Print the program version and exit. |
| -d, --debug | Enable debug logging. |
| -y, --yes | Force non-interactive mode and suppress exit pause. |
| --non-interactive | Alias for --yes. |
| --no-pause | Do not wait for a key press before exit. |
| --no-elevation | Disable automatic Administrator/root relaunch. |
| --list-presets | List .cfg presets in the current working directory and exit. |
| --config FILE | Load configuration from FILE. In interactive wizard mode, the resulting config is also saved back to FILE. |
| --no-config | Ignore config files and do not save wizard output. |
| --preset FILE | Use FILE as the preset and skip the wizard. |
| positional preset path | Shorthand for --preset FILE. |
| --memory VALUE | Override memory window. Accepts values like 85%, 2048, 2048M, or 2048MB. |
| --cores VALUE | Override thread count. Accepts an integer or all. |
| --cycles VALUE | Override cycle count. Accepts an integer, 0, inf, or infinite. |
| --halt-on-error | Stop after the first detected error. |
| --no-halt-on-error | Continue after errors. |
| --locked-memory | Request locked memory. |
| --no-locked-memory | Allow swappable memory. |
| --large-pages | Prefer large pages or hugepages. |
| --no-large-pages | Disable large-page preference. |
| --show-config | Print the resolved configuration before execution. |
| --dry-run | Validate inputs, print the resolved configuration, and exit without running tests. |

### Validation behavior

The CLI rejects:

- Unknown arguments.
- Empty preset or config paths.
- Invalid memory percentages.
- Invalid core counts.
- Invalid cycle values.
- Missing explicit config files in direct CLI mode.
- Presets that fail to load or resolve to zero tests.
- Memory windows that resolve to 0 MB or exceed the safe maximum the runtime derives from system memory.

### Resolved configuration output

--show-config and --dry-run print:

- Config source.
- Preset file, name, and author when present.
- Effective memory window.
- Alignment-adjusted memory size when large-page rounding changes the request.
- Thread count.
- Cycle count.
- Halt-on-error behavior.
- Locked-memory and large-page selection.
- Debug logging state.
- Whether the run is interactive.

### Preset listing

--list-presets scans the current working directory for .cfg files and prints:

- The preset filename.
- The preset display name when available.
- The preset author when available.
- Test count.
- Cycle count when present in the preset metadata.

### Config resolution order

1. Start from built-in defaults.
2. Load config.ini or --config FILE unless --no-config is used.
3. Apply CLI overrides.
4. Load the selected preset.
5. Resolve the memory window.
6. Validate the final configuration before execution.

### Wizard behavior

The wizard supports:

- Memory entry by percentage or MB.
- Thread count selection.
- Cycle count selection.
- Locked-memory preference.
- Large-page preference on non-Windows platforms.
- Halt-on-error selection.
- Preset selection from currently available .cfg files, plus a custom file path option.

### Exit codes

| Exit code | Meaning |
| --- | --- |
| 0 | Successful test run with no detected memory errors, help/version/list command success, or dry-run success. |
| 1 | Test run completed with detected memory errors. |
| 2 | CLI, config, preset, or validation failure. |
