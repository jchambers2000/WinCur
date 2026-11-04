#include "wincur/helper/confirmation.hpp"
#include "wincur/helper/transaction.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::wstring_view kTransaction =
    L"123e4567-e89b-12d3-a456-426614174000";
constexpr std::wstring_view kOtherTransaction =
    L"93b9c3d1-8a62-4d96-b772-0b0768722e17";
constexpr std::wstring_view kCapsule =
    L"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
constexpr std::wstring_view kOtherCapsule =
    L"bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
constexpr std::wstring_view kTimestamp = L"2026-11-03T06:00:00Z";

int failures = 0;
int checks = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

struct SharedState final {
    std::mutex mutex;
    std::map<std::wstring, std::vector<wincur::helper::TransactionValue>> records;
};

class MemoryLifecycleStorage final : public wincur::helper::TransactionStorage {
public:
    explicit MemoryLifecycleStorage(std::shared_ptr<SharedState> state)
        : state_(std::move(state)) {}

    wincur::helper::StorageCreateStatus begin_override{
        wincur::helper::StorageCreateStatus::Created
    };
    std::size_t fail_write_call{static_cast<std::size_t>(-1)};
    std::size_t fail_flush_call{static_cast<std::size_t>(-1)};

    [[nodiscard]] wincur::helper::StorageCreateStatus Begin(
        const std::wstring_view transaction_id
    ) noexcept override {
        if (begin_override != wincur::helper::StorageCreateStatus::Created) {
            return begin_override;
        }
        try {
            std::scoped_lock lock(state_->mutex);
            const auto [iterator, inserted] = state_->records.emplace(
                std::wstring(transaction_id),
                std::vector<wincur::helper::TransactionValue>{}
            );
            if (!inserted) {
                return wincur::helper::StorageCreateStatus::Duplicate;
            }
            current_ = iterator->first;
            return wincur::helper::StorageCreateStatus::Created;
        } catch (...) {
            return wincur::helper::StorageCreateStatus::Error;
        }
    }

    [[nodiscard]] wincur::helper::StorageOpenStatus Open(
        const std::wstring_view transaction_id
    ) noexcept override {
        try {
            std::scoped_lock lock(state_->mutex);
            if (!state_->records.contains(std::wstring(transaction_id))) {
                return wincur::helper::StorageOpenStatus::NotFound;
            }
            current_ = std::wstring(transaction_id);
            return wincur::helper::StorageOpenStatus::Opened;
        } catch (...) {
            return wincur::helper::StorageOpenStatus::Error;
        }
    }

    [[nodiscard]] bool Write(
        const wincur::helper::TransactionValue& value
    ) noexcept override {
        if (write_calls_++ == fail_write_call || current_.empty()) {
            return false;
        }
        try {
            std::scoped_lock lock(state_->mutex);
            auto& values = state_->records.at(current_);
            const auto existing = std::find_if(
                values.begin(),
                values.end(),
                [&value](const auto& candidate) {
                    return candidate.name == value.name;
                }
            );
            if (existing == values.end()) {
                values.push_back(value);
            } else {
                *existing = value;
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] bool Flush() noexcept override {
        return flush_calls_++ != fail_flush_call && !current_.empty();
    }

    [[nodiscard]] bool Read(
        std::vector<wincur::helper::TransactionValue>& values
    ) noexcept override {
        try {
            std::scoped_lock lock(state_->mutex);
            values = state_->records.at(current_);
            return true;
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::vector<wincur::helper::TransactionValue> Values() {
        std::scoped_lock lock(state_->mutex);
        return state_->records.at(current_);
    }

private:
    std::shared_ptr<SharedState> state_;
    std::wstring current_;
    std::size_t write_calls_{0};
    std::size_t flush_calls_{0};
};

[[nodiscard]] wincur::helper::Request ApplyRequest() {
    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Apply;
    request.transaction_id = std::wstring(kTransaction);
    request.action = wincur::helper::ActionId::DisableAutoRun;
    return request;
}

[[nodiscard]] wincur::helper::TransactionReservation Reservation() {
    return wincur::helper::MakeTransactionReservation(
        ApplyRequest(),
        std::wstring(kTimestamp)
    );
}

void TestReservationAndReplay() {
    const auto serialized =
        wincur::helper::SerializeTransactionReservation(Reservation());
    Check(serialized.has_value() && !serialized->empty(),
          "valid reservation serializes");
    Check(serialized.has_value() &&
              serialized->back().name == L"ReservationComplete",
          "reservation durability marker is last");

    auto shared = std::make_shared<SharedState>();
    MemoryLifecycleStorage first(shared);
    Check(wincur::helper::ReserveTransaction(first, Reservation()) ==
              wincur::helper::ReservationStatus::Success,
          "first reservation succeeds");
    MemoryLifecycleStorage replay(shared);
    Check(wincur::helper::ReserveTransaction(replay, Reservation()) ==
              wincur::helper::ReservationStatus::Duplicate,
          "replayed transaction UUID is rejected before confirmation");
}

void TestConcurrentReservation() {
    auto shared = std::make_shared<SharedState>();
    wincur::helper::ReservationStatus left{};
    wincur::helper::ReservationStatus right{};
    std::thread first([&] {
        MemoryLifecycleStorage storage(shared);
        left = wincur::helper::ReserveTransaction(storage, Reservation());
    });
    std::thread second([&] {
        MemoryLifecycleStorage storage(shared);
        right = wincur::helper::ReserveTransaction(storage, Reservation());
    });
    first.join();
    second.join();
    const int successes =
        (left == wincur::helper::ReservationStatus::Success ? 1 : 0) +
        (right == wincur::helper::ReservationStatus::Success ? 1 : 0);
    const int duplicates =
        (left == wincur::helper::ReservationStatus::Duplicate ? 1 : 0) +
        (right == wincur::helper::ReservationStatus::Duplicate ? 1 : 0);
    Check(successes == 1 && duplicates == 1,
          "concurrent reservation has exactly one winner");
}

void TestTransitionsAndBinding() {
    auto shared = std::make_shared<SharedState>();
    MemoryLifecycleStorage storage(shared);
    Check(wincur::helper::ReserveTransaction(storage, Reservation()) ==
              wincur::helper::ReservationStatus::Success,
          "transition fixture reserves");
    Check(wincur::helper::BindCapsuleToTransaction(
              storage, ApplyRequest(), kCapsule, std::wstring(kTimestamp)) ==
              wincur::helper::CapsuleBindingStatus::Success,
          "transition fixture binds capsule before confirmation");
    Check(wincur::helper::TransitionTransaction(
              storage,
              ApplyRequest(),
              wincur::helper::TransactionLifecycle::Reserved,
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              std::wstring(kTimestamp)
          ) == wincur::helper::TransitionStatus::Success,
          "reserved advances to awaiting confirmation");

    auto mismatch = ApplyRequest();
    mismatch.action = wincur::helper::ActionId::EnablePowerShellLogging;
    Check(wincur::helper::TransitionTransaction(
              storage,
              mismatch,
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              wincur::helper::TransactionLifecycle::Confirmed,
              std::wstring(kTimestamp)
          ) == wincur::helper::TransitionStatus::BindingMismatch,
          "mismatched confirmation binding cannot advance lifecycle");
    Check(wincur::helper::TransitionTransaction(
              storage,
              ApplyRequest(),
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              wincur::helper::TransactionLifecycle::Confirmed,
              std::wstring(kTimestamp)
          ) == wincur::helper::TransitionStatus::Success,
          "matching confirmation advances lifecycle once");
    Check(wincur::helper::TransitionTransaction(
              storage,
              ApplyRequest(),
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              wincur::helper::TransactionLifecycle::Confirmed,
              std::wstring(kTimestamp)
          ) == wincur::helper::TransitionStatus::InvalidTransition,
          "replayed confirmation transition is rejected");
}

void TestProtectedCapsuleBindingAndMutationBoundary() {
    auto shared = std::make_shared<SharedState>();
    MemoryLifecycleStorage storage(shared);
    Check(wincur::helper::ReserveTransaction(storage, Reservation()) ==
              wincur::helper::ReservationStatus::Success,
          "capsule binding fixture reserves transaction");
    Check(wincur::helper::ValidateTransactionCapsuleBinding(
              storage, ApplyRequest(), kCapsule) ==
              wincur::helper::CapsuleBindingStatus::BindingMismatch,
          "missing capsule binding blocks authorization");
    Check(wincur::helper::TransitionTransaction(
              storage, ApplyRequest(),
              wincur::helper::TransactionLifecycle::Reserved,
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              std::wstring(kTimestamp)) ==
              wincur::helper::TransitionStatus::InvalidTransition,
          "apply cannot reach confirmation without protected capsule binding");
    Check(wincur::helper::BindCapsuleToTransaction(
              storage, ApplyRequest(), kCapsule, std::wstring(kTimestamp)) ==
              wincur::helper::CapsuleBindingStatus::Success,
          "durable capsule binds to exact transaction");
    Check(wincur::helper::ValidateTransactionCapsuleBinding(
              storage, ApplyRequest(), kCapsule) ==
              wincur::helper::CapsuleBindingStatus::Success,
          "capsule binding revalidates");
    Check(wincur::helper::BindCapsuleToTransaction(
              storage, ApplyRequest(), kCapsule, std::wstring(kTimestamp)) ==
              wincur::helper::CapsuleBindingStatus::Duplicate,
          "duplicate capsule binding is rejected");
    Check(wincur::helper::ValidateTransactionCapsuleBinding(
              storage, ApplyRequest(), kOtherCapsule) ==
              wincur::helper::CapsuleBindingStatus::BindingMismatch,
          "cross-capsule substitution is rejected");
    auto other_action = ApplyRequest();
    other_action.action = wincur::helper::ActionId::EnablePowerShellLogging;
    Check(wincur::helper::ValidateTransactionCapsuleBinding(
              storage, other_action, kCapsule) ==
              wincur::helper::CapsuleBindingStatus::BindingMismatch,
          "cross-action capsule substitution is rejected");
    auto other_transaction = ApplyRequest();
    other_transaction.transaction_id = std::wstring(kOtherTransaction);
    Check(wincur::helper::ValidateTransactionCapsuleBinding(
              storage, other_transaction, kCapsule) !=
              wincur::helper::CapsuleBindingStatus::Success,
          "cross-transaction capsule substitution is rejected");

    const auto parsed = wincur::helper::ParseTransactionReservation(
        storage.Values(), kTransaction);
    Check(parsed.status == wincur::helper::ReservationParseStatus::Success &&
              parsed.reservation.has_value() &&
              parsed.reservation->capsule_id.has_value() &&
              *parsed.reservation->capsule_id == kCapsule &&
              parsed.reservation->mutation_boundary ==
                  wincur::helper::MutationBoundary::MutationNotStarted,
          "protected reservation records capsule and pre-mutation boundary");
    Check(wincur::helper::ClassifyRecoveryDisposition(
              *parsed.reservation, true) ==
              wincur::helper::RecoveryDisposition::TerminalizePreMutation,
          "valid pre-mutation capsule is safely terminalizable");
    Check(wincur::helper::ClassifyRecoveryDisposition(
              *parsed.reservation, false) ==
              wincur::helper::RecoveryDisposition::TerminalizePreMutation,
          "missing pre-mutation capsule cannot imply a mutation");

    Check(wincur::helper::UpdateMutationBoundary(
              storage, ApplyRequest(), kCapsule,
              wincur::helper::MutationBoundary::MutationNotStarted,
              wincur::helper::MutationBoundary::MutationMayHaveStarted,
              std::wstring(kTimestamp)) ==
              wincur::helper::TransitionStatus::Success,
          "future boundary can advance only through explicit protected update");
    const auto may_have_started = wincur::helper::ParseTransactionReservation(
        storage.Values(), kTransaction);
    Check(may_have_started.reservation.has_value() &&
              wincur::helper::ClassifyRecoveryDisposition(
                  *may_have_started.reservation, true) ==
                  wincur::helper::RecoveryDisposition::PreserveIndeterminate,
          "possible mutation is retained for manual reconciliation");
    Check(may_have_started.reservation.has_value() &&
              wincur::helper::ClassifyRecoveryDisposition(
                  *may_have_started.reservation, false) ==
                  wincur::helper::RecoveryDisposition::PreserveIndeterminate,
          "missing capsule after possible mutation remains indeterminate");
}

void TestCapsuleBindingPartialWrite() {
    auto shared = std::make_shared<SharedState>();
    MemoryLifecycleStorage setup(shared);
    Check(wincur::helper::ReserveTransaction(setup, Reservation()) ==
              wincur::helper::ReservationStatus::Success,
          "partial capsule binding fixture reserves");
    MemoryLifecycleStorage failing(shared);
    Check(failing.Open(kTransaction) ==
              wincur::helper::StorageOpenStatus::Opened,
          "partial capsule binding fixture reopens");
    failing.fail_write_call = 1;
    Check(wincur::helper::BindCapsuleToTransaction(
              failing, ApplyRequest(), kCapsule, std::wstring(kTimestamp)) ==
              wincur::helper::CapsuleBindingStatus::PartialWrite,
          "failed capsule binding persistence is explicit");
    Check(wincur::helper::ParseTransactionReservation(
              failing.Values(), kTransaction).status ==
              wincur::helper::ReservationParseStatus::Incomplete,
          "partial capsule binding cannot be treated as valid");
}

void TestCancellationAndInterruption() {
    auto shared = std::make_shared<SharedState>();
    MemoryLifecycleStorage storage(shared);
    Check(wincur::helper::ReserveTransaction(storage, Reservation()) ==
              wincur::helper::ReservationStatus::Success,
          "cancellation fixture reserves");
    Check(wincur::helper::BindCapsuleToTransaction(
              storage, ApplyRequest(), kCapsule, std::wstring(kTimestamp)) ==
              wincur::helper::CapsuleBindingStatus::Success,
          "cancellation fixture binds capsule");
    Check(wincur::helper::TransitionTransaction(
              storage,
              ApplyRequest(),
              wincur::helper::TransactionLifecycle::Reserved,
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              std::wstring(kTimestamp)
          ) == wincur::helper::TransitionStatus::Success,
          "cancellation fixture awaits confirmation");
    const wincur::helper::AuthorizationResult cancelled{
        wincur::helper::AuthorizationStatus::Cancelled,
        L"UserCancelled",
        L"The user cancelled the privileged action.",
        L"No security setting was changed.",
    };
    const auto result = wincur::helper::MakeAuthorizationTransactionResult(
        ApplyRequest(),
        cancelled,
        std::wstring(kTimestamp)
    );
    Check(wincur::helper::FinalizeReservedTransaction(
              storage,
              ApplyRequest(),
              result,
              wincur::helper::TransactionLifecycle::AwaitingConfirmation,
              wincur::helper::TransactionLifecycle::Completed,
              std::wstring(kTimestamp)
          ) == wincur::helper::PersistStatus::Success,
          "cancellation becomes a completed non-success result");

    auto interrupted_shared = std::make_shared<SharedState>();
    {
        MemoryLifecycleStorage abandoned(interrupted_shared);
        Check(wincur::helper::ReserveTransaction(abandoned, Reservation()) ==
                  wincur::helper::ReservationStatus::Success,
              "abandoned reservation is durable");
        Check(wincur::helper::BindCapsuleToTransaction(
                  abandoned, ApplyRequest(), kCapsule,
                  std::wstring(kTimestamp)) ==
                  wincur::helper::CapsuleBindingStatus::Success,
              "abandoned operation binds capsule");
        Check(wincur::helper::TransitionTransaction(
                  abandoned,
                  ApplyRequest(),
                  wincur::helper::TransactionLifecycle::Reserved,
                  wincur::helper::TransactionLifecycle::AwaitingConfirmation,
                  std::wstring(kTimestamp)
              ) == wincur::helper::TransitionStatus::Success,
              "abandoned operation awaits confirmation");
        Check(wincur::helper::TransitionTransaction(
                  abandoned, ApplyRequest(),
                  wincur::helper::TransactionLifecycle::AwaitingConfirmation,
                  wincur::helper::TransactionLifecycle::Confirmed,
                  std::wstring(kTimestamp)) ==
                  wincur::helper::TransitionStatus::Success,
              "abandoned operation records confirmation");
        Check(wincur::helper::TransitionTransaction(
                  abandoned, ApplyRequest(),
                  wincur::helper::TransactionLifecycle::Confirmed,
                  wincur::helper::TransactionLifecycle::Executing,
                  std::wstring(kTimestamp)) ==
                  wincur::helper::TransitionStatus::Success,
              "simulated terminated process reached executing");
    }
    MemoryLifecycleStorage recovery(interrupted_shared);
    Check(recovery.Open(kTransaction) ==
              wincur::helper::StorageOpenStatus::Opened,
          "later helper opens abandoned reservation");
    std::vector<wincur::helper::TransactionValue> values;
    Check(recovery.Read(values), "recovery reads abandoned reservation");
    const auto parsed = wincur::helper::ParseTransactionReservation(
        values,
        kTransaction
    );
    Check(parsed.status == wincur::helper::ReservationParseStatus::Success &&
              parsed.reservation.has_value(),
          "abandoned reservation remains structurally valid");
    if (parsed.reservation.has_value()) {
        const auto interrupted = wincur::helper::MakeInterruptedResult(
            *parsed.reservation,
            std::wstring(kTimestamp)
        );
        Check(wincur::helper::FinalizeReservedTransaction(
                  recovery,
                  ApplyRequest(),
                  interrupted,
                  parsed.reservation->lifecycle,
                  wincur::helper::TransactionLifecycle::Interrupted,
                  std::wstring(kTimestamp)
              ) == wincur::helper::PersistStatus::Success,
              "recovery terminalizes without retrying the operation");
    }
}

void TestPartialWritesAndMalformedState() {
    const auto serialized =
        *wincur::helper::SerializeTransactionReservation(Reservation());
    for (std::size_t index = 0; index < serialized.size(); ++index) {
        auto shared = std::make_shared<SharedState>();
        MemoryLifecycleStorage storage(shared);
        storage.fail_write_call = index;
        Check(wincur::helper::ReserveTransaction(storage, Reservation()) ==
                  wincur::helper::ReservationStatus::PartialWrite,
              "each injected reservation write failure is partial");
        const auto values = storage.Values();
        const bool complete = std::any_of(
            values.begin(),
            values.end(),
            [](const auto& value) {
                return value.name == L"ReservationComplete";
            }
        );
        Check(!complete,
              "partial reservation write never publishes completion marker");
    }

    auto shared = std::make_shared<SharedState>();
    MemoryLifecycleStorage untrusted(shared);
    untrusted.begin_override = wincur::helper::StorageCreateStatus::Untrusted;
    Check(wincur::helper::ReserveTransaction(untrusted, Reservation()) ==
              wincur::helper::ReservationStatus::Untrusted,
          "untrusted protected state blocks reservation");

    MemoryLifecycleStorage malformed(shared);
    Check(wincur::helper::ReserveTransaction(malformed, Reservation()) ==
              wincur::helper::ReservationStatus::Success,
          "malformed fixture initially reserves");
    Check(malformed.Write({
              L"Lifecycle",
              wincur::helper::TransactionValueType::String,
              0,
              L"InventedState",
          }),
          "malformed lifecycle is injected");
    Check(wincur::helper::TransitionTransaction(
              malformed,
              ApplyRequest(),
              wincur::helper::TransactionLifecycle::Reserved,
              wincur::helper::TransactionLifecycle::Executing,
              std::wstring(kTimestamp)
          ) == wincur::helper::TransitionStatus::MalformedState,
          "malformed lifecycle cannot advance");

    const auto final_result = wincur::helper::MakeNotImplementedResult(
        ApplyRequest(),
        std::wstring(kTimestamp)
    );
    const std::size_t final_write_count =
        wincur::helper::SerializeTransactionResult(final_result)->size() + 2;
    for (std::size_t index = 0; index < final_write_count; ++index) {
        auto final_shared = std::make_shared<SharedState>();
        MemoryLifecycleStorage setup(final_shared);
        Check(wincur::helper::ReserveTransaction(setup, Reservation()) ==
                  wincur::helper::ReservationStatus::Success,
              "partial finalization fixture reserves");
        Check(wincur::helper::BindCapsuleToTransaction(
                  setup, ApplyRequest(), kCapsule,
                  std::wstring(kTimestamp)) ==
                  wincur::helper::CapsuleBindingStatus::Success,
              "partial finalization fixture binds capsule");
        Check(wincur::helper::TransitionTransaction(
                  setup,
                  ApplyRequest(),
                  wincur::helper::TransactionLifecycle::Reserved,
                  wincur::helper::TransactionLifecycle::AwaitingConfirmation,
                  std::wstring(kTimestamp)
              ) == wincur::helper::TransitionStatus::Success,
              "partial finalization fixture awaits confirmation");
        Check(wincur::helper::TransitionTransaction(
                  setup, ApplyRequest(),
                  wincur::helper::TransactionLifecycle::AwaitingConfirmation,
                  wincur::helper::TransactionLifecycle::Confirmed,
                  std::wstring(kTimestamp)) ==
                  wincur::helper::TransitionStatus::Success,
              "partial finalization fixture confirms");
        Check(wincur::helper::TransitionTransaction(
                  setup, ApplyRequest(),
                  wincur::helper::TransactionLifecycle::Confirmed,
                  wincur::helper::TransactionLifecycle::Executing,
                  std::wstring(kTimestamp)) ==
                  wincur::helper::TransitionStatus::Success,
              "partial finalization fixture executes");
        MemoryLifecycleStorage failing(final_shared);
        Check(failing.Open(kTransaction) ==
                  wincur::helper::StorageOpenStatus::Opened,
              "partial finalization fixture reopens");
        failing.fail_write_call = index;
        Check(wincur::helper::FinalizeReservedTransaction(
                  failing,
                  ApplyRequest(),
                  final_result,
                  wincur::helper::TransactionLifecycle::Executing,
                  wincur::helper::TransactionLifecycle::Failed,
                  std::wstring(kTimestamp)
              ) == wincur::helper::PersistStatus::PartialWrite,
              "injected finalization write failure is partial");
        const auto final_values = failing.Values();
        const bool complete = std::any_of(
            final_values.begin(),
            final_values.end(),
            [](const auto& value) { return value.name == L"Complete"; }
        );
        Check(!complete,
              "partial finalization never publishes result completion marker");
    }
}

}  // namespace

int main() {
    TestReservationAndReplay();
    TestConcurrentReservation();
    TestTransitionsAndBinding();
    TestProtectedCapsuleBindingAndMutationBoundary();
    TestCapsuleBindingPartialWrite();
    TestCancellationAndInterruption();
    TestPartialWritesAndMalformedState();

    if (failures != 0) {
        std::cerr << failures << " of " << checks
                  << " lifecycle checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " lifecycle checks passed.\n";
    return EXIT_SUCCESS;
}
