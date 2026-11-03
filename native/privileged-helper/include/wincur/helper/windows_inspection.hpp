#pragma once

#include "wincur/helper/inspection.hpp"

#include <Windows.h>

namespace wincur::helper {

inline constexpr REGSAM kInspectionRegistryView = KEY_WOW64_64KEY;

// Reads only fixed, compiled Windows targets in the 64-bit registry view or
// through INetFwPolicy2. It accepts no caller-selected path or profile.
[[nodiscard]] InspectionResult InspectWindowsAction(ActionId action) noexcept;

}  // namespace wincur::helper
