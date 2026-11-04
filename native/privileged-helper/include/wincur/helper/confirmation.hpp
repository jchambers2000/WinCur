#pragma once

#include "wincur/helper/inspection.hpp"
#include "wincur/helper/protocol.hpp"
#include "wincur/helper/transaction.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace wincur::helper {

inline constexpr std::uint32_t kConfirmationTimeoutMilliseconds = 300000;

enum class ConfirmationChoice {
    Confirmed,
    Cancelled,
    TimedOut,
    UiFailure,
};

struct ConfirmationBinding final {
    Operation operation{};
    ActionId action{};
    std::wstring transaction_id;
    std::optional<std::wstring> rollback_id;

    [[nodiscard]] bool operator==(
        const ConfirmationBinding& other
    ) const noexcept = default;
};

struct ConfirmationPrompt final {
    ConfirmationBinding binding;
    std::wstring action_name;
    std::wstring proposed_change;
    std::wstring affected_setting;
    std::wstring security_implications;
};

struct ConfirmationReceipt final {
    ConfirmationChoice choice{ConfirmationChoice::UiFailure};
    ConfirmationBinding binding;
    std::uint64_t challenge{0};
};

class ConfirmationPresenter {
public:
    ConfirmationPresenter() = default;
    ConfirmationPresenter(const ConfirmationPresenter&) = delete;
    ConfirmationPresenter& operator=(const ConfirmationPresenter&) = delete;
    virtual ~ConfirmationPresenter() = default;

    [[nodiscard]] virtual ConfirmationReceipt Present(
        const ConfirmationPrompt& prompt,
        std::uint64_t challenge
    ) noexcept = 0;
};

enum class AuthorizationReadiness {
    Eligible,
    AlreadyCompliant,
    Managed,
    Ambiguous,
    Inaccessible,
    Unsupported,
    Failed,
};

enum class AuthorizationStatus {
    Confirmed,
    Cancelled,
    TimedOut,
    UiFailure,
    ProtectedStateFailure,
    UnsupportedRequest,
    BindingMismatch,
    Replayed,
    BlockedManaged,
    BlockedAmbiguous,
    BlockedPrecondition,
    RevalidationFailed,
};

struct AuthorizationResult final {
    AuthorizationStatus status{AuthorizationStatus::BlockedPrecondition};
    std::wstring message_code;
    std::wstring display_message;
    std::wstring verification_summary;
};

using RevalidationFunction = std::function<AuthorizationReadiness()>;
using ConfirmationAcceptedFunction = std::function<bool()>;

[[nodiscard]] AuthorizationReadiness ReadinessFromInspection(
    const InspectionResult& inspection
) noexcept;

[[nodiscard]] std::optional<ConfirmationPrompt> MakeConfirmationPrompt(
    const Request& request,
    ActionId resolved_action
);

class ConfirmationSession final {
public:
    ConfirmationSession(
        ConfirmationPrompt prompt,
        std::uint64_t challenge
    );

    [[nodiscard]] const ConfirmationPrompt& prompt() const noexcept;
    [[nodiscard]] AuthorizationStatus Consume(
        const ConfirmationReceipt& receipt
    ) noexcept;

private:
    ConfirmationPrompt prompt_;
    std::uint64_t challenge_{0};
    bool consumed_{false};
};

[[nodiscard]] AuthorizationResult AuthorizeMutation(
    const Request& request,
    ActionId resolved_action,
    AuthorizationReadiness initial_readiness,
    ConfirmationPresenter& presenter,
    const RevalidationFunction& revalidate,
    std::uint64_t challenge,
    const ConfirmationAcceptedFunction& on_confirmed = {}
) noexcept;

[[nodiscard]] TransactionResult MakeAuthorizationTransactionResult(
    const Request& request,
    const AuthorizationResult& authorization,
    std::wstring timestamp_utc
);

}  // namespace wincur::helper
