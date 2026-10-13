#pragma once

namespace testsmem4u::platform_detail {
#ifndef _WIN32
void restoreHugepages();
void restoreHugepagesSignalSafe();
#endif
}
