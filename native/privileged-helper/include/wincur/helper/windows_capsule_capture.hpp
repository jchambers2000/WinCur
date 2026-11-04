#pragma once

#include "wincur/helper/capsule.hpp"

#include <string>

namespace wincur::helper {

// Reads only fixed, compiled Windows targets. It accepts no paths or value
// names from the caller and never writes security configuration.
[[nodiscard]] std::optional<PreChangeCapsule> CaptureWindowsPreChangeState(
    ActionId action,
    std::wstring capsule_id,
    std::wstring transaction_id,
    std::wstring created_utc
) noexcept;

}  // namespace wincur::helper
