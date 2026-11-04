#include "wincur/helper/windows_uuid.hpp"

#include "wincur/helper/protocol.hpp"

#include <objbase.h>

#include <array>

namespace wincur::helper {

UuidGenerationResult FormatCanonicalTransactionUuid(const GUID& guid) noexcept {
    UuidGenerationResult result{};
    std::array<wchar_t, 39> text{};
    result.formatted_characters =
        StringFromGUID2(guid, text.data(), static_cast<int>(text.size()));
    // StringFromGUID2 returns the count including the terminating NUL. The
    // canonical textual GUID is 38 characters with braces, hence 39 here.
    if (result.formatted_characters != static_cast<int>(text.size())) {
        result.status = UuidGenerationStatus::FormattingFailed;
        result.hresult = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        return result;
    }
    try {
        result.value.assign(text.data() + 1, 36);
        for (wchar_t& character : result.value) {
            if (character >= L'A' && character <= L'F') {
                character = static_cast<wchar_t>(character + (L'a' - L'A'));
            }
        }
    } catch (...) {
        result.status = UuidGenerationStatus::FormattingFailed;
        result.hresult = E_OUTOFMEMORY;
        return result;
    }
    if (!IsCanonicalTransactionUuid(result.value)) {
        result.status = UuidGenerationStatus::NonCanonical;
        result.hresult = E_INVALIDARG;
        return result;
    }
    result.status = UuidGenerationStatus::Success;
    result.hresult = S_OK;
    return result;
}

UuidGenerationResult GenerateCanonicalTransactionUuid() noexcept {
    GUID guid{};
    const HRESULT generated = CoCreateGuid(&guid);
    if (FAILED(generated)) {
        UuidGenerationResult result{};
        result.status = UuidGenerationStatus::GenerationFailed;
        result.hresult = generated;
        return result;
    }
    return FormatCanonicalTransactionUuid(guid);
}

}  // namespace wincur::helper
