#include "wincur/helper/confirmation.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

constexpr std::wstring_view kTransaction =
    L"123e4567-e89b-12d3-a456-426614174000";
constexpr std::wstring_view kRollback =
    L"93b9c3d1-8a62-4d96-b772-0b0768722e17";
constexpr std::uint64_t kChallenge = 0x9c2f4b0187a56d3eULL;

int failures = 0;
int checks = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

[[nodiscard]] wincur::helper::Request ApplyRequest(
    const wincur::helper::ActionId action =
        wincur::helper::ActionId::DisableAutoRun
) {
    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Apply;
    request.transaction_id = std::wstring(kTransaction);
    request.action = action;
    return request;
}

[[nodiscard]] wincur::helper::Request RollbackRequest() {
    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Rollback;
    request.transaction_id = std::wstring(kTransaction);
    request.rollback_id = std::wstring(kRollback);
    return request;
}

class MockPresenter final : public wincur::helper::ConfirmationPresenter {
public:
    wincur::helper::ConfirmationChoice choice{
        wincur::helper::ConfirmationChoice::Confirmed
    };
    bool mismatch_transaction{false};
    bool mismatch_action{false};
    bool mismatch_operation{false};
    bool mismatch_challenge{false};
    int calls{0};
    std::optional<wincur::helper::ConfirmationPrompt> observed;

    [[nodiscard]] wincur::helper::ConfirmationReceipt Present(
        const wincur::helper::ConfirmationPrompt& prompt,
        const std::uint64_t challenge
    ) noexcept override {
        ++calls;
        observed = prompt;
        auto binding = prompt.binding;
        if (mismatch_transaction) {
            binding.transaction_id =
                L"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        }
        if (mismatch_action) {
            binding.action =
                wincur::helper::ActionId::EnablePowerShellLogging;
        }
        if (mismatch_operation) {
            binding.operation = wincur::helper::Operation::Rollback;
        }
        return {
            choice,
            std::move(binding),
            mismatch_challenge ? challenge + 1 : challenge,
        };
    }
};

void TestExplicitConfirmationAndFixedContent() {
    MockPresenter presenter;
    int revalidations = 0;
    const auto result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [&revalidations]() {
            ++revalidations;
            return wincur::helper::AuthorizationReadiness::Eligible;
        },
        kChallenge
    );
    Check(result.status == wincur::helper::AuthorizationStatus::Confirmed,
          "explicit confirmation with successful revalidation is authorized");
    Check(presenter.calls == 1 && revalidations == 1,
          "confirmation and post-confirmation validation each occur once");
    Check(presenter.observed.has_value() &&
              presenter.observed->action_name == L"Disable AutoRun" &&
              presenter.observed->proposed_change.find(L"all drive types") !=
                  std::wstring::npos &&
              presenter.observed->affected_setting.find(L"NoAutorun") !=
                  std::wstring::npos &&
              !presenter.observed->security_implications.empty(),
          "helper supplies fixed action, change, target, and implications");

    const auto confirmation_only =
        wincur::helper::MakeAuthorizationTransactionResult(
            ApplyRequest(),
            result,
            L"2026-11-03T04:00:00Z"
        );
    Check(confirmation_only.outcome !=
              wincur::helper::TransactionOutcome::Succeeded,
          "confirmation alone cannot serialize as successful remediation");
}

void TestCancellationClosureTimeoutAndFailure() {
    const struct Case {
        wincur::helper::ConfirmationChoice choice;
        wincur::helper::AuthorizationStatus status;
        const char* description;
    } cases[] = {
        {wincur::helper::ConfirmationChoice::Cancelled,
         wincur::helper::AuthorizationStatus::Cancelled,
         "cancel button denies authorization"},
        {wincur::helper::ConfirmationChoice::Cancelled,
         wincur::helper::AuthorizationStatus::Cancelled,
         "window closure is represented as cancellation"},
        {wincur::helper::ConfirmationChoice::TimedOut,
         wincur::helper::AuthorizationStatus::TimedOut,
         "timeout denies authorization"},
        {wincur::helper::ConfirmationChoice::UiFailure,
         wincur::helper::AuthorizationStatus::UiFailure,
         "dialog creation failure denies authorization"},
    };
    for (const auto& test : cases) {
        MockPresenter presenter;
        presenter.choice = test.choice;
        int revalidations = 0;
        const auto result = wincur::helper::AuthorizeMutation(
            ApplyRequest(),
            wincur::helper::ActionId::DisableAutoRun,
            wincur::helper::AuthorizationReadiness::Eligible,
            presenter,
            [&revalidations]() {
                ++revalidations;
                return wincur::helper::AuthorizationReadiness::Eligible;
            },
            kChallenge
        );
        Check(result.status == test.status, test.description);
        Check(revalidations == 0,
              "denied confirmation never reaches revalidation");
    }
}

void TestBindingMismatchAndReplay() {
    MockPresenter mismatch;
    mismatch.mismatch_transaction = true;
    auto result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        mismatch,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    Check(result.status == wincur::helper::AuthorizationStatus::BindingMismatch,
          "transaction mismatch denies confirmation");

    mismatch.mismatch_transaction = false;
    mismatch.mismatch_action = true;
    result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        mismatch,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    Check(result.status == wincur::helper::AuthorizationStatus::BindingMismatch,
          "action mismatch denies confirmation");

    const auto prompt = wincur::helper::MakeConfirmationPrompt(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun
    );
    Check(prompt.has_value(), "valid request creates a confirmation prompt");
    if (prompt.has_value()) {
        wincur::helper::ConfirmationSession session(*prompt, kChallenge);
        const wincur::helper::ConfirmationReceipt receipt{
            wincur::helper::ConfirmationChoice::Confirmed,
            prompt->binding,
            kChallenge,
        };
        Check(session.Consume(receipt) ==
                  wincur::helper::AuthorizationStatus::Confirmed,
              "first matching receipt is accepted");
        Check(session.Consume(receipt) ==
                  wincur::helper::AuthorizationStatus::Replayed,
              "replayed confirmation receipt is rejected");
    }
}

void TestUnsupportedRequests() {
    MockPresenter presenter;
    auto request = ApplyRequest();
    request.action = wincur::helper::ActionId::EnablePowerShellLogging;
    auto result = wincur::helper::AuthorizeMutation(
        request,
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    Check(result.status ==
              wincur::helper::AuthorizationStatus::UnsupportedRequest &&
              presenter.calls == 0,
          "action mismatch is rejected before presenting UI");

    request = ApplyRequest();
    request.operation = wincur::helper::Operation::Preview;
    result = wincur::helper::AuthorizeMutation(
        request,
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    Check(result.status ==
              wincur::helper::AuthorizationStatus::UnsupportedRequest,
          "preview cannot enter mutation confirmation");

    result = wincur::helper::AuthorizeMutation(
        RollbackRequest(),
        wincur::helper::ActionId::EnableFirewallProfiles,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    Check(result.status ==
              wincur::helper::AuthorizationStatus::UnsupportedRequest,
          "firewall rollback is unsupported");

    result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        0
    );
    Check(result.status == wincur::helper::AuthorizationStatus::UiFailure &&
              presenter.calls == 0,
          "failed challenge generation denies before presenting UI");
}

void TestPolicyBlocksAndRevalidation() {
    for (const auto readiness : {
             wincur::helper::AuthorizationReadiness::Managed,
             wincur::helper::AuthorizationReadiness::Ambiguous,
             wincur::helper::AuthorizationReadiness::AlreadyCompliant,
         }) {
        MockPresenter presenter;
        const auto result = wincur::helper::AuthorizeMutation(
            ApplyRequest(),
            wincur::helper::ActionId::DisableAutoRun,
            readiness,
            presenter,
            [] { return wincur::helper::AuthorizationReadiness::Eligible; },
            kChallenge
        );
        Check(result.status != wincur::helper::AuthorizationStatus::Confirmed &&
                  presenter.calls == 0,
              "managed, ambiguous, or compliant state blocks before dialog");
    }

    MockPresenter presenter;
    auto result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Managed; },
        kChallenge
    );
    Check(result.status == wincur::helper::AuthorizationStatus::BlockedManaged,
          "managed post-confirmation evidence blocks future mutation");

    result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Ambiguous; },
        kChallenge
    );
    Check(result.status ==
              wincur::helper::AuthorizationStatus::BlockedAmbiguous,
          "ambiguous post-confirmation evidence blocks future mutation");

    result = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Inaccessible; },
        kChallenge
    );
    Check(result.status ==
              wincur::helper::AuthorizationStatus::RevalidationFailed,
          "failed post-confirmation revalidation denies authorization");
}

void TestRollbackBindingAndTransactionResult() {
    MockPresenter presenter;
    const auto authorization = wincur::helper::AuthorizeMutation(
        RollbackRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    Check(authorization.status ==
              wincur::helper::AuthorizationStatus::Confirmed &&
              presenter.observed.has_value() &&
              presenter.observed->binding.rollback_id == kRollback,
          "future rollback confirmation binds protected rollback identifier");

    presenter.choice = wincur::helper::ConfirmationChoice::Cancelled;
    const auto cancelled = wincur::helper::AuthorizeMutation(
        ApplyRequest(),
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::AuthorizationReadiness::Eligible,
        presenter,
        [] { return wincur::helper::AuthorizationReadiness::Eligible; },
        kChallenge
    );
    const auto transaction =
        wincur::helper::MakeAuthorizationTransactionResult(
            ApplyRequest(),
            cancelled,
            L"2026-11-03T04:00:00Z"
        );
    Check(transaction.outcome ==
              wincur::helper::TransactionOutcome::Cancelled &&
              transaction.message_code == L"UserCancelled",
          "cancellation remains explicit in protected transaction schema");
    Check(wincur::helper::SerializeTransactionResult(transaction).has_value(),
          "cancellation transaction is bounded and serializable");
}

}  // namespace

int main() {
    TestExplicitConfirmationAndFixedContent();
    TestCancellationClosureTimeoutAndFailure();
    TestBindingMismatchAndReplay();
    TestUnsupportedRequests();
    TestPolicyBlocksAndRevalidation();
    TestRollbackBindingAndTransactionResult();

    if (failures != 0) {
        std::cerr << failures << " of " << checks
                  << " confirmation checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " confirmation checks passed.\n";
    return EXIT_SUCCESS;
}
