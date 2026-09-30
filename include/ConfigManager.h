#pragma once

#include "testsmem4u.h"
#include <string>

namespace testsmem4u {

// Save configuration to an INI file
bool saveConfig(const std::string& filename, const Config& config);

// Load configuration from an INI file
// Returns true if successful, false otherwise
bool loadConfig(const std::string& filename, Config& config);

// Missing optional configuration may use defaults; invalid/unreadable files may
// not. Keep the bool API above for callers that do not need this distinction.
enum class ConfigLoadStatus : uint8_t { LOADED, NOT_FOUND, INVALID };
ConfigLoadStatus loadConfigWithStatus(const std::string& filename, Config& config);

} // namespace testsmem4u
