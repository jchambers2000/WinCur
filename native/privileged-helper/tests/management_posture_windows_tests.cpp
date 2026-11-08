#include "wincur/helper/windows_management_posture.hpp"

#include <Windows.h>
#include <wbemidl.h>

#include <cstdlib>
#include <iostream>

namespace {

int checks = 0;
int failures = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

void TestEnumerationClassification() {
    using wincur::helper::ClassifyWmiEnumerationResult;
    using wincur::helper::WmiEnumerationDisposition;

    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_S_NO_ERROR), 1, true) ==
            WmiEnumerationDisposition::Object,
        "S_OK with one object is a valid item"
    );
    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_S_FALSE), 0, false) ==
            WmiEnumerationDisposition::NormalEnd,
        "WBEM_S_FALSE with no object is normal termination"
    );
    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_S_NO_ERROR), 0, false) ==
            WmiEnumerationDisposition::Malformed,
        "S_OK without the requested object is malformed"
    );
    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_S_FALSE), 1, true) ==
            WmiEnumerationDisposition::Malformed,
        "WBEM_S_FALSE with a full one-object request is malformed"
    );
    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_S_TIMEDOUT), 0, false) ==
            WmiEnumerationDisposition::Timeout,
        "WMI timeout remains distinct"
    );
    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_E_ACCESS_DENIED), 0, false) ==
            WmiEnumerationDisposition::Failure,
        "WMI access denial remains a failure"
    );
    Check(
        ClassifyWmiEnumerationResult(
            static_cast<std::uint32_t>(WBEM_S_NO_ERROR), 1, false) ==
            WmiEnumerationDisposition::Malformed,
        "reported object count without an object is malformed"
    );
}

}  // namespace

int main() {
    TestEnumerationClassification();
    if (failures != 0) {
        std::cerr << failures << " of " << checks
                  << " Windows posture diagnostic checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks
              << " Windows posture diagnostic checks passed.\n";
    return EXIT_SUCCESS;
}
