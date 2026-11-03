#include "wincur/helper/protocol.hpp"
#include "wincur/helper/stub_backend.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using Arguments = std::vector<std::wstring>;

constexpr std::wstring_view kTransaction =
    L"123e4567-e89b-12d3-a456-426614174000";
constexpr std::wstring_view kRollback =
    L"93b9c3d1-8a62-4d96-b772-0b0768722e17";

int failures = 0;

void Check(const bool condition, const char* const description) {
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

[[nodiscard]] wincur::helper::ParseResult Parse(
    const Arguments& owned,
    const std::size_t command_line_length = 200
) {
    std::vector<std::wstring_view> views;
    views.reserve(owned.size());
    for (const std::wstring& value : owned) {
        views.emplace_back(value);
    }
    return wincur::helper::ParseArguments(views, command_line_length);
}

[[nodiscard]] Arguments ActionRequest(
    const std::wstring_view operation,
    const std::wstring_view action
) {
    return {
        L"--protocol",
        L"1",
        L"--operation",
        std::wstring(operation),
        L"--transaction",
        std::wstring(kTransaction),
        L"--action",
        std::wstring(action),
    };
}

[[nodiscard]] Arguments RollbackRequest() {
    return {
        L"--protocol",
        L"1",
        L"--operation",
        L"rollback",
        L"--transaction",
        std::wstring(kTransaction),
        L"--rollback-id",
        std::wstring(kRollback),
    };
}

void ExpectInvalid(Arguments arguments, const char* const description) {
    Check(
        Parse(arguments).status == wincur::helper::ParseStatus::InvalidArguments,
        description
    );
}

void TestValidRequests() {
    constexpr std::wstring_view actions[] = {
        L"disable-autorun",
        L"enable-powershell-logging",
        L"enable-firewall-profiles",
    };
    constexpr std::wstring_view operations[] = {L"preview", L"apply"};

    for (const std::wstring_view operation : operations) {
        for (const std::wstring_view action : actions) {
            const auto parsed = Parse(ActionRequest(operation, action));
            Check(parsed.status == wincur::helper::ParseStatus::Success,
                  "documented action request is accepted");
            Check(parsed.request.has_value(), "valid action request is returned");
            Check(parsed.request.has_value() && parsed.request->action.has_value(),
                  "valid action request contains action");
            Check(parsed.request.has_value() && !parsed.request->rollback_id.has_value(),
                  "valid action request has no rollback ID");
        }
    }

    const auto rollback = Parse(RollbackRequest());
    Check(rollback.status == wincur::helper::ParseStatus::Success,
          "documented rollback request is accepted");
    Check(rollback.request.has_value() && rollback.request->rollback_id.has_value(),
          "valid rollback contains rollback ID");
    Check(rollback.request.has_value() && !rollback.request->action.has_value(),
          "valid rollback has no caller action");
}

void TestStrictGrammar() {
    Arguments request = ActionRequest(L"apply", L"disable-autorun");

    Arguments missing = request;
    missing.pop_back();
    ExpectInvalid(std::move(missing), "missing argument is rejected");

    Arguments extra = request;
    extra.emplace_back(L"unexpected");
    ExpectInvalid(std::move(extra), "extra argument is rejected");

    Arguments duplicate = request;
    duplicate[6] = L"--transaction";
    ExpectInvalid(std::move(duplicate), "duplicate switch is rejected");

    Arguments reordered = request;
    std::swap(reordered[0], reordered[2]);
    ExpectInvalid(std::move(reordered), "reordered switches are rejected");

    Arguments unknown = request;
    unknown[6] = L"--unknown";
    ExpectInvalid(std::move(unknown), "unknown switch is rejected");

    Arguments abbreviated = request;
    abbreviated[0] = L"--proto";
    ExpectInvalid(std::move(abbreviated), "abbreviated switch is rejected");

    Arguments alternate = request;
    alternate[0] = L"/protocol";
    ExpectInvalid(std::move(alternate), "alternate switch form is rejected");

    Arguments joined = request;
    joined[0] = L"--protocol=1";
    ExpectInvalid(std::move(joined), "joined switch form is rejected");

    Arguments response = request;
    response[0] = L"@request.rsp";
    ExpectInvalid(std::move(response), "response-file argument is rejected");

    Arguments positional = request;
    positional[0] = L"preview";
    ExpectInvalid(std::move(positional), "positional argument is rejected");

    Arguments whitespace = request;
    whitespace[7] = L"disable autorun";
    ExpectInvalid(std::move(whitespace), "whitespace-bearing token is rejected");

    Arguments non_ascii = request;
    non_ascii[7] = L"disable-autorun\u00e9";
    ExpectInvalid(std::move(non_ascii), "non-ASCII token is rejected");

    Arguments embedded_nul = request;
    embedded_nul[7] = std::wstring(L"disable\0-autorun", 16);
    ExpectInvalid(std::move(embedded_nul), "embedded NUL is rejected");

    Check(
        Parse(request, wincur::helper::kMaximumCommandLineCodeUnits + 1).status ==
            wincur::helper::ParseStatus::InvalidArguments,
        "overlong complete command line is rejected"
    );
    Check(
        Parse(request, wincur::helper::kMaximumCommandLineCodeUnits).status ==
            wincur::helper::ParseStatus::Success,
        "maximum-length complete command line boundary is accepted"
    );
    Check(
        Parse(request, 0).status == wincur::helper::ParseStatus::InvalidArguments,
        "empty complete command line is rejected"
    );
}

void TestProtocolAndCatalog() {
    Arguments unsupported = ActionRequest(L"preview", L"disable-autorun");
    unsupported[1] = L"2";
    Check(
        Parse(unsupported).status == wincur::helper::ParseStatus::UnsupportedProtocol,
        "unsupported protocol has a distinct result"
    );

    Arguments malformed_protocol = ActionRequest(L"preview", L"disable-autorun");
    malformed_protocol[1] = L"01";
    Check(
        Parse(malformed_protocol).status ==
            wincur::helper::ParseStatus::UnsupportedProtocol,
        "noncanonical protocol value is unsupported"
    );

    Arguments bad_operation = ActionRequest(L"delete", L"disable-autorun");
    ExpectInvalid(std::move(bad_operation), "unknown operation is rejected");

    Arguments uppercase_operation = ActionRequest(L"Apply", L"disable-autorun");
    ExpectInvalid(std::move(uppercase_operation), "uppercase operation is rejected");

    Arguments bad_action = ActionRequest(L"apply", L"disable-everything");
    ExpectInvalid(std::move(bad_action), "unknown action is rejected");

    Arguments path_action = ActionRequest(L"apply", L"C:\\Windows\\System32");
    ExpectInvalid(std::move(path_action), "path-like action is rejected");

    constexpr std::wstring_view adversarial_actions[] = {
        L"\\\\server\\share",
        L"\\\\?\\C:\\Windows",
        L"..\\..\\target",
        L"file.txt:stream",
        L"%TEMP%",
        L"@request.rsp",
    };
    for (const std::wstring_view adversarial_action : adversarial_actions) {
        Arguments adversarial = ActionRequest(L"apply", adversarial_action);
        ExpectInvalid(std::move(adversarial),
                      "path, expansion, or response-like action is rejected");
    }

    Arguments rollback_with_action = RollbackRequest();
    rollback_with_action[6] = L"--action";
    rollback_with_action[7] = L"disable-autorun";
    ExpectInvalid(std::move(rollback_with_action),
                  "rollback caller-supplied action is rejected");

    Arguments apply_with_rollback = ActionRequest(L"apply", L"disable-autorun");
    apply_with_rollback[6] = L"--rollback-id";
    apply_with_rollback[7] = std::wstring(kRollback);
    ExpectInvalid(std::move(apply_with_rollback),
                  "apply caller-supplied rollback ID is rejected");
}

void TestUuidValidation() {
    Check(wincur::helper::IsCanonicalTransactionUuid(kTransaction),
          "canonical lowercase UUID is accepted");
    Check(!wincur::helper::IsCanonicalTransactionUuid(
              L"00000000-0000-0000-0000-000000000000"),
          "nil UUID is rejected");
    Check(!wincur::helper::IsCanonicalTransactionUuid(
              L"123E4567-E89B-12D3-A456-426614174000"),
          "uppercase UUID is rejected");
    Check(!wincur::helper::IsCanonicalTransactionUuid(
              L"{123e4567-e89b-12d3-a456-426614174000}"),
          "braced UUID is rejected");
    Check(!wincur::helper::IsCanonicalTransactionUuid(
              L"123e4567e89b12d3a456426614174000"),
          "UUID without hyphens is rejected");
    Check(!wincur::helper::IsCanonicalTransactionUuid(
              L"123e4567-e89b-12d3-a456-42661417400z"),
          "UUID with nonhex digit is rejected");

    Arguments bad_transaction = ActionRequest(L"apply", L"disable-autorun");
    bad_transaction[5] = L"00000000-0000-0000-0000-000000000000";
    ExpectInvalid(std::move(bad_transaction), "nil transaction UUID is rejected");

    Arguments bad_rollback = RollbackRequest();
    bad_rollback[7] = L"93B9C3D1-8A62-4D96-B772-0B0768722E17";
    ExpectInvalid(std::move(bad_rollback), "noncanonical rollback UUID is rejected");
}

void TestStubBackend() {
    const auto parsed = Parse(ActionRequest(L"apply", L"disable-autorun"));
    Check(parsed.request.has_value(), "stub test request parses");
    if (parsed.request.has_value()) {
        Check(
            wincur::helper::ExecuteStub(*parsed.request) ==
                wincur::helper::BackendOutcome::NotImplemented,
            "stub backend explicitly returns NotImplemented"
        );
    }
}

}  // namespace

int main() {
    TestValidRequests();
    TestStrictGrammar();
    TestProtocolAndCatalog();
    TestUuidValidation();
    TestStubBackend();

    if (failures != 0) {
        std::cerr << failures << " parser test(s) failed.\n";
        return EXIT_FAILURE;
    }

    std::cout << "All privileged-helper parser tests passed.\n";
    return EXIT_SUCCESS;
}
