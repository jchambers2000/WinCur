#pragma once

#include "wincur/helper/capsule.hpp"

#include <Windows.h>

#include <optional>
#include <string_view>

namespace wincur::helper {

inline constexpr wchar_t kRollbackCapsulesSubkey[] = L"Rollback";

class WindowsCapsuleStorage final : public CapsuleStorage {
public:
    WindowsCapsuleStorage() noexcept = default;
    WindowsCapsuleStorage(const WindowsCapsuleStorage&) = delete;
    WindowsCapsuleStorage& operator=(const WindowsCapsuleStorage&) = delete;
    ~WindowsCapsuleStorage() noexcept override;

    [[nodiscard]] CapsuleCreateStatus Begin(
        std::wstring_view capsule_id
    ) noexcept override;
    [[nodiscard]] bool Write(const CapsuleValue& value) noexcept override;
    [[nodiscard]] bool Flush() noexcept override;
    [[nodiscard]] bool Read(std::vector<CapsuleValue>& values) noexcept override;

private:
    HKEY key_{nullptr};
    bool complete_written_{false};
};

enum class CapsuleRegistryReadStatus {
    Success,
    NotFound,
    Incomplete,
    Malformed,
    BindingMismatch,
    Untrusted,
    AccessDenied,
    Error,
};

struct CapsuleRegistryReadResult final {
    CapsuleRegistryReadStatus status{CapsuleRegistryReadStatus::Error};
    std::optional<PreChangeCapsule> capsule;
};

[[nodiscard]] CapsuleRegistryReadResult ReadCapsuleFromRegistry(
    std::wstring_view capsule_id,
    std::wstring_view transaction_id,
    Operation operation,
    ActionId action
) noexcept;

}  // namespace wincur::helper
