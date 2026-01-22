#pragma once

#include "testsmem4u.h"
#include <string>

namespace testsmem4u {

// Save configuration to an INI file
bool saveConfig(const std::string& filename, const Config& config);

// Load configuration from an INI file
// Returns true if successful, false otherwise
bool loadConfig(const std::string& filename, Config& config);

} // namespace testsmem4u
