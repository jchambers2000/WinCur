#pragma once

#include <Windows.h>

namespace wincur::helper {

inline constexpr wchar_t kPublicRegistrySecurityDescriptor[] =
    L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)";

[[nodiscard]] bool ValidatePublicRegistrySecurityDescriptor(
    PSECURITY_DESCRIPTOR security_descriptor
) noexcept;

}  // namespace wincur::helper
