#include "wincur/helper/transaction.hpp"

#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::wstring_view kTransaction =
    L"123e4567-e89b-12d3-a456-426614174000";

int failures = 0;
int checks = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

class MemoryStorage final : public wincur::helper::TransactionStorage {
public:
    wincur::helper::StorageCreateStatus begin_status{
        wincur::helper::StorageCreateStatus::Created
    };
    std::size_t fail_write_index{static_cast<std::size_t>(-1)};
    std::set<std::wstring> existing;
    std::vector<wincur::helper::TransactionValue> writes;

    [[nodiscard]] wincur::helper::StorageCreateStatus Begin(
        const std::wstring_view transaction_id
    ) noexcept override {
        if (begin_status != wincur::helper::StorageCreateStatus::Created) {
            return begin_status;
        }
        try {
            if (!existing.emplace(transaction_id).second) {
                return wincur::helper::StorageCreateStatus::Duplicate;
            }
            writes.clear();
            return wincur::helper::StorageCreateStatus::Created;
        } catch (...) {
            return wincur::helper::StorageCreateStatus::Error;
        }
    }

    [[nodiscard]] bool Write(
        const wincur::helper::TransactionValue& value
    ) noexcept override {
        if (writes.size() == fail_write_index) {
            return false;
        }
        try {
            writes.push_back(value);
            return true;
        } catch (...) {
            return false;
        }
    }
};

[[nodiscard]] wincur::helper::TransactionResult ValidResult() {
    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Apply;
    request.transaction_id = std::wstring(kTransaction);
    request.action = wincur::helper::ActionId::DisableAutoRun;
    return wincur::helper::MakeNotImplementedResult(
        request,
        L"2026-11-01T23:59:58Z"
    );
}

void TestSchemaRoundTripAndCompleteLast() {
    const auto serialized =
        wincur::helper::SerializeTransactionResult(ValidResult());
    Check(serialized.has_value(), "valid result serializes");
    if (!serialized.has_value()) {
        return;
    }
    Check(!serialized->empty(), "serialized result has values");
    Check(serialized->back().name == L"Complete",
          "completion marker is serialized last");
    Check(serialized->back().type == wincur::helper::TransactionValueType::Dword &&
              serialized->back().dword_value == 1,
          "completion marker is DWORD one");

    const auto parsed =
        wincur::helper::ParseTransactionResult(*serialized, kTransaction);
    Check(parsed.status == wincur::helper::TransactionParseStatus::Success,
          "serialized result parses");
    Check(parsed.result.has_value() &&
              parsed.result->outcome == wincur::helper::TransactionOutcome::Failed,
          "explicit failed outcome is preserved");
    Check(parsed.result.has_value() &&
              parsed.result->message_code == L"NotImplemented",
          "explicit message code is preserved");
}

void TestIncompleteAndMalformedResults() {
    auto serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    serialized.pop_back();
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Incomplete,
        "missing completion marker is incomplete"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    serialized.back().dword_value = 0;
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Malformed,
        "zero completion marker is malformed"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    serialized.back().type = wincur::helper::TransactionValueType::String;
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Malformed,
        "wrong-type completion marker is malformed"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    serialized.erase(serialized.begin());
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Malformed,
        "missing required field is malformed"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    serialized.push_back({
        L"Unexpected",
        wincur::helper::TransactionValueType::String,
        0,
        L"value",
    });
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Malformed,
        "unknown field is malformed"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    serialized.push_back(serialized.front());
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Malformed,
        "duplicate field is malformed"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    for (auto& value : serialized) {
        if (value.name == L"Outcome") {
            value.string_value = L"SuccessMaybe";
        }
    }
    Check(
        wincur::helper::ParseTransactionResult(serialized, kTransaction).status ==
            wincur::helper::TransactionParseStatus::Malformed,
        "unknown outcome is malformed"
    );

    serialized = *wincur::helper::SerializeTransactionResult(ValidResult());
    Check(
        wincur::helper::ParseTransactionResult(
            serialized,
            L"93b9c3d1-8a62-4d96-b772-0b0768722e17"
        ).status == wincur::helper::TransactionParseStatus::Malformed,
        "transaction ID mismatch is malformed"
    );
}

void TestBoundsAndSemantics() {
    auto result = ValidResult();
    result.display_message.assign(
        wincur::helper::kMaximumDisplayMessageCharacters + 1,
        L'x'
    );
    Check(!wincur::helper::SerializeTransactionResult(result).has_value(),
          "overlong display message is rejected");

    result = ValidResult();
    result.verification_summary.assign(
        wincur::helper::kMaximumVerificationSummaryCharacters + 1,
        L'x'
    );
    Check(!wincur::helper::SerializeTransactionResult(result).has_value(),
          "overlong verification summary is rejected");

    result = ValidResult();
    result.display_message = std::wstring(L"safe\0unsafe", 11);
    Check(!wincur::helper::SerializeTransactionResult(result).has_value(),
          "embedded NUL is rejected");

    result = ValidResult();
    result.protocol_version = 2;
    Check(!wincur::helper::SerializeTransactionResult(result).has_value(),
          "unsupported protocol field is rejected");

    result = ValidResult();
    result.timestamp_utc = L"not-a-timestamp";
    Check(!wincur::helper::SerializeTransactionResult(result).has_value(),
          "malformed timestamp is rejected");

    result = ValidResult();
    result.rollback_id = L"93b9c3d1-8a62-4d96-b772-0b0768722e17";
    Check(!wincur::helper::SerializeTransactionResult(result).has_value(),
          "non-rollback operation cannot claim rollback ID");

    result = ValidResult();
    result.outcome = wincur::helper::TransactionOutcome::Partial;
    const auto partial = wincur::helper::SerializeTransactionResult(result);
    Check(partial.has_value(), "partial outcome remains explicit valid evidence");
    if (partial.has_value()) {
        const auto parsed =
            wincur::helper::ParseTransactionResult(*partial, kTransaction);
        Check(parsed.result.has_value() &&
                  parsed.result->outcome ==
                      wincur::helper::TransactionOutcome::Partial,
              "partial outcome cannot become succeeded");
    }

    result = ValidResult();
    result.outcome = wincur::helper::TransactionOutcome::Interrupted;
    const auto interrupted = wincur::helper::SerializeTransactionResult(result);
    Check(interrupted.has_value(),
          "interrupted outcome remains explicit valid evidence");
    if (interrupted.has_value()) {
        const auto parsed =
            wincur::helper::ParseTransactionResult(*interrupted, kTransaction);
        Check(parsed.result.has_value() &&
                  parsed.result->outcome ==
                      wincur::helper::TransactionOutcome::Interrupted,
              "interrupted outcome cannot become succeeded");
    }
}

void TestPersistenceOrderingAndFailures() {
    MemoryStorage storage;
    const auto result = ValidResult();
    Check(
        wincur::helper::PersistTransactionResult(storage, result) ==
            wincur::helper::PersistStatus::Success,
        "valid result persists"
    );
    Check(!storage.writes.empty() && storage.writes.back().name == L"Complete",
          "storage receives completion marker last");

    Check(
        wincur::helper::PersistTransactionResult(storage, result) ==
            wincur::helper::PersistStatus::Duplicate,
        "replayed transaction ID is rejected"
    );

    MemoryStorage duplicate;
    duplicate.begin_status = wincur::helper::StorageCreateStatus::Duplicate;
    Check(
        wincur::helper::PersistTransactionResult(duplicate, result) ==
            wincur::helper::PersistStatus::Duplicate && duplicate.writes.empty(),
        "preexisting transaction is not overwritten"
    );

    MemoryStorage untrusted;
    untrusted.begin_status = wincur::helper::StorageCreateStatus::Untrusted;
    Check(
        wincur::helper::PersistTransactionResult(untrusted, result) ==
            wincur::helper::PersistStatus::Untrusted && untrusted.writes.empty(),
        "untrusted parent blocks every write"
    );

    const auto values = *wincur::helper::SerializeTransactionResult(result);
    for (std::size_t fail_index = 0; fail_index < values.size(); ++fail_index) {
        MemoryStorage failing;
        failing.fail_write_index = fail_index;
        Check(
            wincur::helper::PersistTransactionResult(failing, result) ==
                wincur::helper::PersistStatus::PartialWrite,
            "injected write failure is partial"
        );
        const bool has_complete = !failing.writes.empty() &&
                                  failing.writes.back().name == L"Complete";
        Check(!has_complete, "failed transaction has no completion marker");
        Check(
            wincur::helper::ParseTransactionResult(
                failing.writes,
                kTransaction
            ).status == wincur::helper::TransactionParseStatus::Incomplete,
            "every interrupted write prefix parses as incomplete"
        );
    }
}

}  // namespace

int main() {
    TestSchemaRoundTripAndCompleteLast();
    TestIncompleteAndMalformedResults();
    TestBoundsAndSemantics();
    TestPersistenceOrderingAndFailures();

    if (failures != 0) {
        std::cerr << failures << " of " << checks << " transaction checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " transaction checks passed.\n";
    return EXIT_SUCCESS;
}
