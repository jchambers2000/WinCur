#pragma once

#include "wincur/helper/management_posture.hpp"

namespace wincur::helper {

// Uses documented Windows APIs and fixed, compiled targets only. Collection is
// read-only and produces evidence; it does not authorize remediation.
[[nodiscard]] ManagementPostureResult InspectWindowsManagementPosture() noexcept;

// Integration-diagnostic only. Both attempts are read-only. The STA attempt
// creates, consumes, and closes the GPO COM object and HKEY on its own thread.
[[nodiscard]] LocalGroupPolicyApartmentDiagnostic
InspectLocalGroupPolicyApartmentsForDiagnostics() noexcept;

enum class WmiEnumerationDisposition : std::uint8_t {
    Object,
    NormalEnd,
    Timeout,
    Failure,
    Malformed,
};

[[nodiscard]] WmiEnumerationDisposition ClassifyWmiEnumerationResult(
    std::uint32_t raw_result,
    std::uint32_t returned_object_count,
    bool object_present
) noexcept;

}  // namespace wincur::helper
