#include "wincur/helper/confirmation.hpp"

#include <utility>

namespace wincur::helper {
namespace {

[[nodiscard]] AuthorizationResult Result(
    const AuthorizationStatus status,
    std::wstring code,
    std::wstring message,
    std::wstring verification
) {
    return {
        status,
        std::move(code),
        std::move(message),
        std::move(verification),
    };
}

[[nodiscard]] AuthorizationResult ReadinessResult(
    const AuthorizationReadiness readiness,
    const bool after_confirmation
) {
    const std::wstring phase = after_confirmation
                                   ? L"Post-confirmation revalidation"
                                   : L"Pre-confirmation validation";
    switch (readiness) {
        case AuthorizationReadiness::Eligible:
            break;
        case AuthorizationReadiness::AlreadyCompliant:
            return Result(
                AuthorizationStatus::BlockedPrecondition,
                L"AlreadyCompliant",
                L"The selected setting is already compliant.",
                phase + L" found no change to authorize."
            );
        case AuthorizationReadiness::Managed:
            return Result(
                AuthorizationStatus::BlockedManaged,
                L"ManagedPolicyBlocked",
                L"The selected setting is managed by policy.",
                phase + L" blocked local modification."
            );
        case AuthorizationReadiness::Ambiguous:
            return Result(
                AuthorizationStatus::BlockedAmbiguous,
                L"AmbiguousEvidenceBlocked",
                L"The selected setting cannot be changed safely because the evidence is ambiguous.",
                phase + L" could not establish safe local authority."
            );
        case AuthorizationReadiness::Inaccessible:
            return Result(
                AuthorizationStatus::RevalidationFailed,
                L"InspectionAccessDenied",
                L"WinCur could not access the evidence required to authorize this action.",
                phase + L" failed closed."
            );
        case AuthorizationReadiness::Unsupported:
            return Result(
                AuthorizationStatus::BlockedAmbiguous,
                L"InspectionUnsupported",
                L"This configuration cannot be inspected reliably on this system.",
                phase + L" failed closed."
            );
        case AuthorizationReadiness::Failed:
            return Result(
                AuthorizationStatus::RevalidationFailed,
                L"InspectionFailed",
                L"WinCur could not validate the selected setting.",
                phase + L" failed closed."
            );
    }
    return Result(
        AuthorizationStatus::Confirmed,
        L"ConfirmationValidated",
        L"The user confirmed the exact action.",
        L"Post-confirmation evidence still permits the future operation."
    );
}

}  // namespace

AuthorizationReadiness ReadinessFromInspection(
    const InspectionResult& inspection
) noexcept {
    switch (inspection.status) {
        case InspectionStatus::RemediationRequired:
            return AuthorizationReadiness::Eligible;
        case InspectionStatus::Compliant:
            return AuthorizationReadiness::AlreadyCompliant;
        case InspectionStatus::Managed:
            return AuthorizationReadiness::Managed;
        case InspectionStatus::Ambiguous:
        case InspectionStatus::Partial:
            return AuthorizationReadiness::Ambiguous;
        case InspectionStatus::Inaccessible:
            return AuthorizationReadiness::Inaccessible;
        case InspectionStatus::Unsupported:
            return AuthorizationReadiness::Unsupported;
    }
    return AuthorizationReadiness::Failed;
}

std::optional<ConfirmationPrompt> MakeConfirmationPrompt(
    const Request& request,
    const ActionId resolved_action
) {
    if (request.operation == Operation::Preview ||
        !IsCanonicalTransactionUuid(request.transaction_id)) {
        return std::nullopt;
    }
    if (request.operation == Operation::Apply &&
        (!request.action.has_value() || *request.action != resolved_action ||
         request.rollback_id.has_value())) {
        return std::nullopt;
    }
    if (request.operation == Operation::Rollback &&
        (request.action.has_value() || !request.rollback_id.has_value() ||
         !IsCanonicalTransactionUuid(*request.rollback_id))) {
        return std::nullopt;
    }

    ConfirmationPrompt prompt{};
    prompt.binding = {
        request.operation,
        resolved_action,
        request.transaction_id,
        request.rollback_id,
    };

    switch (resolved_action) {
        case ActionId::DisableAutoRun:
            prompt.action_name = request.operation == Operation::Rollback
                                     ? L"Restore AutoRun policy"
                                     : L"Disable AutoRun";
            prompt.proposed_change = request.operation == Operation::Rollback
                                         ? L"Restore the protected original AutoRun policy values."
                                         : L"Set the machine AutoRun policy to disable commands for all drive types.";
            prompt.affected_setting =
                L"Windows machine AutoRun policy (NoDriveTypeAutoRun and NoAutorun).";
            prompt.security_implications =
                L"Disabling AutoRun reduces automatic command execution from removable and mounted media. Restoring prior values may re-enable that behavior.";
            break;
        case ActionId::EnablePowerShellLogging:
            prompt.action_name = request.operation == Operation::Rollback
                                     ? L"Restore PowerShell logging policy"
                                     : L"Enable PowerShell audit logging";
            prompt.proposed_change = request.operation == Operation::Rollback
                                         ? L"Restore the protected original PowerShell logging policy values."
                                         : L"Enable Script Block Logging and all-module Module Logging by machine policy.";
            prompt.affected_setting =
                L"Windows PowerShell Script Block Logging and Module Logging machine policy.";
            prompt.security_implications =
                L"Logging improves audit visibility and may record script content. Restoring prior values may reduce that visibility.";
            break;
        case ActionId::EnableFirewallProfiles:
            if (request.operation == Operation::Rollback) {
                return std::nullopt;
            }
            prompt.action_name = L"Enable Windows Firewall profiles";
            prompt.proposed_change =
                L"Enable only Windows Firewall profiles that remain disabled after revalidation.";
            prompt.affected_setting =
                L"Windows Firewall Domain, Private, and Public profile enabled state.";
            prompt.security_implications =
                L"Enabling a firewall profile reduces unsolicited inbound network exposure and may affect applications that rely on unapproved inbound traffic.";
            break;
    }
    return prompt;
}

ConfirmationSession::ConfirmationSession(
    ConfirmationPrompt prompt,
    const std::uint64_t challenge
) : prompt_(std::move(prompt)), challenge_(challenge) {}

const ConfirmationPrompt& ConfirmationSession::prompt() const noexcept {
    return prompt_;
}

AuthorizationStatus ConfirmationSession::Consume(
    const ConfirmationReceipt& receipt
) noexcept {
    if (consumed_) {
        return AuthorizationStatus::Replayed;
    }
    consumed_ = true;
    if (receipt.challenge != challenge_ || receipt.binding != prompt_.binding) {
        return AuthorizationStatus::BindingMismatch;
    }
    switch (receipt.choice) {
        case ConfirmationChoice::Confirmed:
            return AuthorizationStatus::Confirmed;
        case ConfirmationChoice::Cancelled:
            return AuthorizationStatus::Cancelled;
        case ConfirmationChoice::TimedOut:
            return AuthorizationStatus::TimedOut;
        case ConfirmationChoice::UiFailure:
            return AuthorizationStatus::UiFailure;
    }
    return AuthorizationStatus::UiFailure;
}

AuthorizationResult AuthorizeMutation(
    const Request& request,
    const ActionId resolved_action,
    const AuthorizationReadiness initial_readiness,
    ConfirmationPresenter& presenter,
    const RevalidationFunction& revalidate,
    const std::uint64_t challenge
) noexcept {
    try {
        const auto prompt = MakeConfirmationPrompt(request, resolved_action);
        if (!prompt.has_value() || !revalidate) {
            return Result(
                AuthorizationStatus::UnsupportedRequest,
                L"ConfirmationRequestInvalid",
                L"The confirmation request was invalid or unsupported.",
                L"No action was authorized."
            );
        }
        if (challenge == 0) {
            return Result(
                AuthorizationStatus::UiFailure,
                L"ConfirmationChallengeUnavailable",
                L"WinCur could not create a trustworthy confirmation challenge.",
                L"Authorization was denied and no security setting was changed."
            );
        }
        if (initial_readiness != AuthorizationReadiness::Eligible) {
            return ReadinessResult(initial_readiness, false);
        }

        ConfirmationSession session(*prompt, challenge);
        const ConfirmationReceipt receipt = presenter.Present(
            session.prompt(),
            challenge
        );
        const AuthorizationStatus confirmation = session.Consume(receipt);
        switch (confirmation) {
            case AuthorizationStatus::Confirmed:
                break;
            case AuthorizationStatus::Cancelled:
                return Result(
                    confirmation,
                    L"UserCancelled",
                    L"The user cancelled the privileged action.",
                    L"No security setting was changed."
                );
            case AuthorizationStatus::TimedOut:
                return Result(
                    confirmation,
                    L"ConfirmationTimedOut",
                    L"The confirmation dialog timed out.",
                    L"No security setting was changed."
                );
            case AuthorizationStatus::UiFailure:
                return Result(
                    confirmation,
                    L"ConfirmationUiFailure",
                    L"WinCur could not display a trustworthy confirmation dialog.",
                    L"Authorization was denied and no security setting was changed."
                );
            case AuthorizationStatus::BindingMismatch:
                return Result(
                    confirmation,
                    L"ConfirmationBindingMismatch",
                    L"The confirmation response did not match the requested operation.",
                    L"Authorization was denied and no security setting was changed."
                );
            case AuthorizationStatus::Replayed:
                return Result(
                    confirmation,
                    L"ConfirmationReplayed",
                    L"A confirmation response was reused.",
                    L"Authorization was denied and no security setting was changed."
                );
            default:
                return Result(
                    AuthorizationStatus::UiFailure,
                    L"ConfirmationDenied",
                    L"The privileged action was not authorized.",
                    L"No security setting was changed."
                );
        }

        const AuthorizationReadiness current = revalidate();
        if (current != AuthorizationReadiness::Eligible) {
            return ReadinessResult(current, true);
        }
        return ReadinessResult(current, true);
    } catch (...) {
        return Result(
            AuthorizationStatus::UiFailure,
            L"ConfirmationInternalError",
            L"The privileged action could not be authorized safely.",
            L"No security setting was changed."
        );
    }
}

TransactionResult MakeAuthorizationTransactionResult(
    const Request& request,
    const AuthorizationResult& authorization,
    std::wstring timestamp_utc
) {
    TransactionResult result{};
    result.transaction_id = request.transaction_id;
    result.operation = request.operation;
    result.action = request.action;
    result.message_code = authorization.message_code;
    result.display_message = authorization.display_message;
    result.verification_summary = authorization.verification_summary;
    result.helper_version = std::wstring(kHelperVersion);
    result.build_id = std::wstring(kHelperBuildId);
    result.timestamp_utc = std::move(timestamp_utc);
    result.rollback_id = request.rollback_id;

    switch (authorization.status) {
        case AuthorizationStatus::Cancelled:
        case AuthorizationStatus::TimedOut:
            result.outcome = TransactionOutcome::Cancelled;
            break;
        case AuthorizationStatus::BlockedManaged:
            result.outcome = TransactionOutcome::BlockedManaged;
            break;
        case AuthorizationStatus::BlockedAmbiguous:
            result.outcome = TransactionOutcome::BlockedAmbiguous;
            break;
        case AuthorizationStatus::BlockedPrecondition:
        case AuthorizationStatus::UnsupportedRequest:
            result.outcome = TransactionOutcome::BlockedPrecondition;
            break;
        case AuthorizationStatus::Confirmed:
            // Confirmation alone is never an operation-success outcome. The
            // caller must execute and verify the future backend before it may
            // persist Succeeded.
            result.outcome = TransactionOutcome::BlockedPrecondition;
            break;
        default:
            result.outcome = TransactionOutcome::Failed;
            break;
    }
    return result;
}

}  // namespace wincur::helper
