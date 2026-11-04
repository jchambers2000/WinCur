#pragma once

#include <Windows.h>

#include <string>

namespace wincur::helper {

enum class UuidGenerationStatus {
    Success,
    GenerationFailed,
    FormattingFailed,
    NonCanonical,
};

struct UuidGenerationResult final {
    UuidGenerationStatus status{UuidGenerationStatus::GenerationFailed};
    std::wstring value;
    HRESULT hresult{E_FAIL};
    int formatted_characters{0};
};

[[nodiscard]] UuidGenerationResult FormatCanonicalTransactionUuid(
    const GUID& guid
) noexcept;

[[nodiscard]] UuidGenerationResult GenerateCanonicalTransactionUuid() noexcept;

}  // namespace wincur::helper
