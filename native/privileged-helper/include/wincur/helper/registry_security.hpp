#pragma once

#include <Windows.h>

namespace wincur::helper {

inline constexpr wchar_t kPublicRegistrySecurityDescriptor[] =
    L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)";
inline constexpr wchar_t kPrivateRegistrySecurityDescriptor[] =
    L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)";

[[nodiscard]] bool ValidatePublicRegistrySecurityDescriptor(
    PSECURITY_DESCRIPTOR security_descriptor
) noexcept;

[[nodiscard]] bool ValidatePrivateRegistrySecurityDescriptor(
    PSECURITY_DESCRIPTOR security_descriptor
) noexcept;

}  // namespace wincur::helper
