#include "wincur/helper/operation_mutex.hpp"
#include "wincur/helper/confirmation.hpp"
#include "wincur/helper/capsule.hpp"
#include "wincur/helper/inspection.hpp"
#include "wincur/helper/protocol.hpp"
#include "wincur/helper/stub_backend.hpp"
#include "wincur/helper/transaction.hpp"
#include "wincur/helper/windows_transaction_store.hpp"
#include "wincur/helper/windows_confirmation.hpp"
#include "wincur/helper/windows_capsule_capture.hpp"
#include "wincur/helper/windows_capsule_store.hpp"
#include "wincur/helper/windows_inspection.hpp"
#include "wincur/helper/windows_uuid.hpp"

#include <Windows.h>
#include <Shellapi.h>

#include <cstddef>
#include <cwchar>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using wincur::helper::ExitCode;

[[nodiscard]] int ToExitCode(const ExitCode code) noexcept {
    return static_cast<int>(code);
}

[[nodiscard]] ExitCode FinalizeResult(
    wincur::helper::WindowsTransactionStorage& storage,
    const wincur::helper::Request& request,
    const wincur::helper::TransactionResult& result,
    const wincur::helper::TransactionLifecycle expected,
    const wincur::helper::TransactionLifecycle terminal,
    const ExitCode success_code
) noexcept {
    const std::wstring timestamp = wincur::helper::CurrentUtcTimestamp();
    if (timestamp.empty() ||
        wincur::helper::FinalizeReservedTransaction(
            storage,
            request,
            result,
            expected,
            terminal,
            timestamp
        ) !=
        wincur::helper::PersistStatus::Success) {
        return ExitCode::ProtectedStateError;
    }
    static_cast<void>(wincur::helper::PruneCompletedTransactionResults());
    return success_code;
}

[[nodiscard]] ExitCode ExitForAuthorization(
    const wincur::helper::AuthorizationStatus status
) noexcept {
    using wincur::helper::AuthorizationStatus;
    switch (status) {
        case AuthorizationStatus::Cancelled:
        case AuthorizationStatus::TimedOut:
            return ExitCode::UserCancelled;
        case AuthorizationStatus::BlockedManaged:
        case AuthorizationStatus::BlockedAmbiguous:
        case AuthorizationStatus::BlockedPrecondition:
        case AuthorizationStatus::UnsupportedRequest:
            return ExitCode::Blocked;
        case AuthorizationStatus::Confirmed:
            return ExitCode::Success;
        case AuthorizationStatus::ProtectedStateFailure:
            return ExitCode::ProtectedStateError;
        default:
            return ExitCode::Failed;
    }
}

[[nodiscard]] wincur::helper::AuthorizationReadiness ReadinessFromCapsule(
    const wincur::helper::CapsuleAuthorizationStatus status
) noexcept {
    using wincur::helper::AuthorizationReadiness;
    using wincur::helper::CapsuleAuthorizationStatus;
    switch (status) {
        case CapsuleAuthorizationStatus::Eligible:
            return AuthorizationReadiness::Eligible;
        case CapsuleAuthorizationStatus::Managed:
            return AuthorizationReadiness::Managed;
        case CapsuleAuthorizationStatus::Ambiguous:
        case CapsuleAuthorizationStatus::Changed:
            return AuthorizationReadiness::Ambiguous;
        case CapsuleAuthorizationStatus::Inaccessible:
            return AuthorizationReadiness::Inaccessible;
        case CapsuleAuthorizationStatus::Unsupported:
            return AuthorizationReadiness::Unsupported;
        case CapsuleAuthorizationStatus::Invalid:
            return AuthorizationReadiness::Failed;
    }
    return AuthorizationReadiness::Failed;
}

[[nodiscard]] wincur::helper::AuthorizationResult ProtectedFailure(
    std::wstring code,
    std::wstring message,
    std::wstring verification
) {
    return {
        wincur::helper::AuthorizationStatus::ProtectedStateFailure,
        std::move(code),
        std::move(message),
        std::move(verification),
    };
}

}  // namespace

int WINAPI wWinMain(
    HINSTANCE instance,
    HINSTANCE previous_instance,
    PWSTR command_line,
    int show_command
) {
    static_cast<void>(instance);
    static_cast<void>(previous_instance);
    static_cast<void>(command_line);
    static_cast<void>(show_command);

    try {
        const wchar_t* const raw_command_line = GetCommandLineW();
        if (raw_command_line == nullptr) {
            return ToExitCode(ExitCode::InternalError);
        }

        const std::size_t measured_length =
            wcsnlen_s(raw_command_line, wincur::helper::kMaximumCommandLineCodeUnits + 1);
        if (measured_length == 0 ||
            measured_length > wincur::helper::kMaximumCommandLineCodeUnits) {
            return ToExitCode(ExitCode::InvalidArguments);
        }

        int argument_count = 0;
        wchar_t** const argument_values =
            CommandLineToArgvW(raw_command_line, &argument_count);
        if (argument_values == nullptr || argument_count < 1) {
            if (argument_values != nullptr) {
                LocalFree(argument_values);
            }
            return ToExitCode(ExitCode::InvalidArguments);
        }

        std::vector<std::wstring_view> arguments;
        arguments.reserve(static_cast<std::size_t>(argument_count - 1));
        for (int index = 1; index < argument_count; ++index) {
            arguments.emplace_back(argument_values[index]);
        }

        const wincur::helper::ParseResult parse_result =
            wincur::helper::ParseArguments(arguments, measured_length);
        LocalFree(argument_values);

        if (parse_result.status == wincur::helper::ParseStatus::UnsupportedProtocol) {
            return ToExitCode(ExitCode::UnsupportedProtocol);
        }
        if (parse_result.status != wincur::helper::ParseStatus::Success ||
            !parse_result.request.has_value()) {
            return ToExitCode(ExitCode::InvalidArguments);
        }

        wincur::helper::OperationMutex operation_mutex;
        switch (operation_mutex.Acquire()) {
            case wincur::helper::MutexAcquireResult::Busy:
                return ToExitCode(ExitCode::Busy);
            case wincur::helper::MutexAcquireResult::Error:
                return ToExitCode(ExitCode::InternalError);
            case wincur::helper::MutexAcquireResult::Acquired:
                break;
        }

        const wincur::helper::RecoverySummary recovery =
            wincur::helper::RecoverIncompleteTransactions();
        if (!recovery.storage_trusted || !recovery.bounded) {
            return ToExitCode(ExitCode::ProtectedStateError);
        }
        static_cast<void>(wincur::helper::PruneCompletedTransactionResults());

        const std::wstring reservation_timestamp =
            wincur::helper::CurrentUtcTimestamp();
        if (reservation_timestamp.empty()) {
            return ToExitCode(ExitCode::InternalError);
        }
        wincur::helper::WindowsTransactionStorage storage;
        const wincur::helper::TransactionReservation reservation =
            wincur::helper::MakeTransactionReservation(
                *parse_result.request,
                reservation_timestamp
            );
        if (wincur::helper::ReserveTransaction(storage, reservation) !=
            wincur::helper::ReservationStatus::Success) {
            return ToExitCode(ExitCode::ProtectedStateError);
        }

        if (parse_result.request->operation == wincur::helper::Operation::Preview &&
            parse_result.request->action.has_value()) {
            const std::wstring executing_timestamp =
                wincur::helper::CurrentUtcTimestamp();
            if (executing_timestamp.empty() ||
                wincur::helper::TransitionTransaction(
                    storage,
                    *parse_result.request,
                    wincur::helper::TransactionLifecycle::Reserved,
                    wincur::helper::TransactionLifecycle::Executing,
                    executing_timestamp
                ) != wincur::helper::TransitionStatus::Success) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            const std::wstring timestamp = wincur::helper::CurrentUtcTimestamp();
            if (timestamp.empty()) {
                return ToExitCode(ExitCode::InternalError);
            }
            const wincur::helper::InspectionResult inspection =
                wincur::helper::InspectWindowsAction(*parse_result.request->action);
            const wincur::helper::TransactionResult result =
                wincur::helper::MakeInspectionTransactionResult(
                    *parse_result.request,
                    inspection,
                    timestamp
                );
            const std::wstring verifying_timestamp =
                wincur::helper::CurrentUtcTimestamp();
            if (verifying_timestamp.empty() ||
                wincur::helper::TransitionTransaction(
                    storage,
                    *parse_result.request,
                    wincur::helper::TransactionLifecycle::Executing,
                    wincur::helper::TransactionLifecycle::Verifying,
                    verifying_timestamp
                ) != wincur::helper::TransitionStatus::Success) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            return ToExitCode(FinalizeResult(
                storage,
                *parse_result.request,
                result,
                wincur::helper::TransactionLifecycle::Verifying,
                wincur::helper::TransactionLifecycle::Completed,
                ExitCode::Success
            ));
        }

        if (parse_result.request->operation == wincur::helper::Operation::Rollback) {
            const std::wstring timestamp = wincur::helper::CurrentUtcTimestamp();
            if (timestamp.empty()) {
                return ToExitCode(ExitCode::InternalError);
            }
            const wincur::helper::AuthorizationResult authorization{
                wincur::helper::AuthorizationStatus::BlockedPrecondition,
                L"RollbackCapsuleUnavailable",
                L"Protected pre-change evidence is not authorized for rollback in this development helper.",
                L"No rollback was authorized and no Windows security setting was changed.",
            };
            const auto result =
                wincur::helper::MakeAuthorizationTransactionResult(
                    *parse_result.request,
                    authorization,
                    timestamp
                );
            return ToExitCode(FinalizeResult(
                storage,
                *parse_result.request,
                result,
                wincur::helper::TransactionLifecycle::Reserved,
                wincur::helper::TransactionLifecycle::Completed,
                ExitCode::Blocked
            ));
        }

        if (parse_result.request->operation == wincur::helper::Operation::Apply &&
            parse_result.request->action.has_value()) {
            const wincur::helper::ActionId action =
                *parse_result.request->action;
            const wincur::helper::InspectionResult initial =
                wincur::helper::InspectWindowsAction(action);
            const wincur::helper::AuthorizationReadiness initial_readiness =
                wincur::helper::ReadinessFromInspection(initial);
            wincur::helper::TransactionLifecycle current_lifecycle =
                wincur::helper::TransactionLifecycle::Reserved;
            const auto finalize_authorization = [&storage,
                                                 &parse_result,
                                                 &current_lifecycle](
                const wincur::helper::AuthorizationResult& authorization,
                const ExitCode exit_code
            ) -> int {
                const std::wstring timestamp =
                    wincur::helper::CurrentUtcTimestamp();
                if (timestamp.empty()) return ToExitCode(ExitCode::InternalError);
                const auto result =
                    wincur::helper::MakeAuthorizationTransactionResult(
                        *parse_result.request,
                        authorization,
                        timestamp
                    );
                const bool failed =
                    authorization.status ==
                        wincur::helper::AuthorizationStatus::UiFailure ||
                    authorization.status ==
                        wincur::helper::AuthorizationStatus::BindingMismatch ||
                    authorization.status ==
                        wincur::helper::AuthorizationStatus::Replayed ||
                    authorization.status ==
                        wincur::helper::AuthorizationStatus::RevalidationFailed ||
                    authorization.status ==
                        wincur::helper::AuthorizationStatus::ProtectedStateFailure;
                return ToExitCode(FinalizeResult(
                    storage,
                    *parse_result.request,
                    result,
                    current_lifecycle,
                    failed ? wincur::helper::TransactionLifecycle::Failed
                           : wincur::helper::TransactionLifecycle::Completed,
                    exit_code
                ));
            };
            if (initial_readiness !=
                wincur::helper::AuthorizationReadiness::Eligible) {
                const auto authorization =
                    wincur::helper::MakeReadinessAuthorizationResult(
                        initial_readiness,
                        false
                    );
                return finalize_authorization(
                    authorization,
                    ExitForAuthorization(authorization.status)
                );
            }

            const auto generated =
                wincur::helper::GenerateCanonicalTransactionUuid();
            if (generated.status !=
                wincur::helper::UuidGenerationStatus::Success) {
                const auto failure = ProtectedFailure(
                    L"CapsuleIdentifierUnavailable",
                    L"WinCur could not create a protected capsule identifier.",
                    L"The operation stopped before confirmation and no security setting was changed."
                );
                return finalize_authorization(failure, ExitCode::ProtectedStateError);
            }
            const std::wstring capsule_id = generated.value;
            const std::wstring capture_timestamp =
                wincur::helper::CurrentUtcTimestamp();
            if (capture_timestamp.empty())
                return ToExitCode(ExitCode::InternalError);
            const auto captured =
                wincur::helper::CaptureWindowsPreChangeState(
                    action,
                    capsule_id,
                    parse_result.request->transaction_id,
                    capture_timestamp
                );
            if (!captured.has_value() ||
                !wincur::helper::CapsuleMatchesRequest(
                    *captured,
                    *parse_result.request,
                    capsule_id
                )) {
                const auto failure = ProtectedFailure(
                    L"CapsuleCaptureFailed",
                    L"WinCur could not capture trustworthy pre-change evidence.",
                    L"Confirmation was not displayed and no security setting was changed."
                );
                return finalize_authorization(failure, ExitCode::ProtectedStateError);
            }
            const auto capsule_readiness = ReadinessFromCapsule(
                wincur::helper::EvaluateCapsuleAuthorization(*captured)
            );
            if (capsule_readiness !=
                wincur::helper::AuthorizationReadiness::Eligible) {
                const auto authorization =
                    wincur::helper::MakeReadinessAuthorizationResult(
                        capsule_readiness,
                        false
                    );
                return finalize_authorization(
                    authorization,
                    ExitForAuthorization(authorization.status)
                );
            }

            {
                wincur::helper::WindowsCapsuleStorage capsule_storage;
                if (wincur::helper::PersistCapsule(
                        capsule_storage,
                        *captured
                    ) != wincur::helper::CapsulePersistStatus::Success) {
                    const auto failure = ProtectedFailure(
                        L"CapsulePersistenceFailed",
                        L"WinCur could not durably store the pre-change capsule.",
                        L"Confirmation was not displayed and no security setting was changed."
                    );
                    return finalize_authorization(
                        failure,
                        ExitCode::ProtectedStateError
                    );
                }
            }
            const auto durable = wincur::helper::ReadCapsuleFromRegistry(
                capsule_id,
                parse_result.request->transaction_id,
                parse_result.request->operation,
                action
            );
            if (durable.status !=
                    wincur::helper::CapsuleRegistryReadStatus::Success ||
                !durable.capsule.has_value() ||
                !wincur::helper::CapsuleMatchesRequest(
                    *durable.capsule,
                    *parse_result.request,
                    capsule_id
                ) ||
                wincur::helper::CompareCapturedState(
                    *captured,
                    *durable.capsule
                ) != wincur::helper::CapsuleAuthorizationStatus::Eligible) {
                const auto failure = ProtectedFailure(
                    L"CapsuleDurabilityVerificationFailed",
                    L"WinCur could not verify the protected pre-change capsule.",
                    L"Confirmation was not displayed and no security setting was changed."
                );
                return finalize_authorization(failure, ExitCode::ProtectedStateError);
            }
            const std::wstring binding_timestamp =
                wincur::helper::CurrentUtcTimestamp();
            if (binding_timestamp.empty())
                return ToExitCode(ExitCode::InternalError);
            if (wincur::helper::BindCapsuleToTransaction(
                    storage,
                    *parse_result.request,
                    capsule_id,
                    binding_timestamp
                ) != wincur::helper::CapsuleBindingStatus::Success) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            const std::wstring awaiting_timestamp =
                wincur::helper::CurrentUtcTimestamp();
            if (awaiting_timestamp.empty() ||
                wincur::helper::TransitionTransaction(
                    storage,
                    *parse_result.request,
                    current_lifecycle,
                    wincur::helper::TransactionLifecycle::AwaitingConfirmation,
                    awaiting_timestamp
                ) != wincur::helper::TransitionStatus::Success) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            current_lifecycle =
                wincur::helper::TransactionLifecycle::AwaitingConfirmation;

            wincur::helper::WindowsConfirmationPresenter presenter;
            const std::uint64_t challenge =
                wincur::helper::CreateConfirmationChallenge();
            std::optional<wincur::helper::PreChangeCapsule>
                post_confirmation_observation;
            const auto authorization = wincur::helper::AuthorizeMutation(
                *parse_result.request,
                action,
                capsule_id,
                initial_readiness,
                presenter,
                [action,
                 &capsule_id,
                 &captured,
                 &post_confirmation_observation,
                 &parse_result]() noexcept {
                    const auto current =
                        wincur::helper::CaptureWindowsPreChangeState(
                            action,
                            capsule_id,
                            parse_result.request->transaction_id,
                            wincur::helper::CurrentUtcTimestamp()
                        );
                    if (!current.has_value())
                        return wincur::helper::AuthorizationReadiness::Failed;
                    const auto status = wincur::helper::CompareCapturedState(
                        *captured,
                        *current
                    );
                    if (status ==
                        wincur::helper::CapsuleAuthorizationStatus::Eligible) {
                        post_confirmation_observation = *current;
                    }
                    return ReadinessFromCapsule(status);
                },
                challenge,
                [&storage, &current_lifecycle, &parse_result]() noexcept {
                    const std::wstring timestamp =
                        wincur::helper::CurrentUtcTimestamp();
                    if (timestamp.empty() ||
                        wincur::helper::TransitionTransaction(
                            storage,
                            *parse_result.request,
                            wincur::helper::TransactionLifecycle::AwaitingConfirmation,
                            wincur::helper::TransactionLifecycle::Confirmed,
                            timestamp
                        ) != wincur::helper::TransitionStatus::Success) {
                        return false;
                    }
                    current_lifecycle =
                        wincur::helper::TransactionLifecycle::Confirmed;
                    return true;
                }
            );
            if (authorization.status ==
                wincur::helper::AuthorizationStatus::ProtectedStateFailure) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            if (authorization.status !=
                wincur::helper::AuthorizationStatus::Confirmed) {
                return finalize_authorization(
                    authorization,
                    ExitForAuthorization(authorization.status)
                );
            }
            const auto revalidated_capsule =
                wincur::helper::ReadCapsuleFromRegistry(
                    capsule_id,
                    parse_result.request->transaction_id,
                    parse_result.request->operation,
                    action
                );
            if (!post_confirmation_observation.has_value() ||
                revalidated_capsule.status !=
                    wincur::helper::CapsuleRegistryReadStatus::Success ||
                !revalidated_capsule.capsule.has_value() ||
                !wincur::helper::CapsuleMatchesRequest(
                    *revalidated_capsule.capsule,
                    *parse_result.request,
                    capsule_id
                ) ||
                wincur::helper::CompareCapturedState(
                    *captured,
                    *revalidated_capsule.capsule
                ) != wincur::helper::CapsuleAuthorizationStatus::Eligible ||
                wincur::helper::ValidateTransactionCapsuleBinding(
                    storage,
                    *parse_result.request,
                    capsule_id
                ) != wincur::helper::CapsuleBindingStatus::Success ||
                wincur::helper::CompareCapturedState(
                    *revalidated_capsule.capsule,
                    *post_confirmation_observation
                ) != wincur::helper::CapsuleAuthorizationStatus::Eligible) {
                const auto failure = ProtectedFailure(
                    L"CapsuleRevalidationFailed",
                    L"WinCur could not revalidate the protected capsule binding.",
                    L"The operation stopped before the mutation boundary and no security setting was changed."
                );
                return finalize_authorization(
                    failure,
                    ExitCode::ProtectedStateError
                );
            }
            const std::wstring executing_timestamp =
                wincur::helper::CurrentUtcTimestamp();
            if (executing_timestamp.empty() ||
                wincur::helper::TransitionTransaction(
                    storage,
                    *parse_result.request,
                    wincur::helper::TransactionLifecycle::Confirmed,
                    wincur::helper::TransactionLifecycle::Executing,
                    executing_timestamp
                ) != wincur::helper::TransitionStatus::Success) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            current_lifecycle = wincur::helper::TransactionLifecycle::Executing;
        }

        const wincur::helper::BackendOutcome outcome =
            wincur::helper::ExecuteStub(*parse_result.request);
        if (outcome == wincur::helper::BackendOutcome::NotImplemented) {
            const std::wstring timestamp = wincur::helper::CurrentUtcTimestamp();
            if (timestamp.empty()) {
                return ToExitCode(ExitCode::InternalError);
            }
            const wincur::helper::TransactionResult result =
                wincur::helper::MakeNotImplementedResult(
                    *parse_result.request,
                    timestamp
                );
            return ToExitCode(FinalizeResult(
                storage,
                *parse_result.request,
                result,
                wincur::helper::TransactionLifecycle::Executing,
                wincur::helper::TransactionLifecycle::Failed,
                ExitCode::Failed
            ));
        }

        return ToExitCode(ExitCode::InternalError);
    } catch (...) {
        return ToExitCode(ExitCode::InternalError);
    }
}
