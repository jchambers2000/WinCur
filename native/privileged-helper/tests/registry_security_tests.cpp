#include "wincur/helper/registry_security.hpp"

#include <Sddl.h>

#include <cstdlib>
#include <iostream>

namespace {

int failures = 0;
int checks = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

[[nodiscard]] bool ValidateSddl(const wchar_t* const sddl) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const BOOL converted = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        &descriptor,
        nullptr
    );
    if (!converted) {
        return false;
    }
    const bool result =
        wincur::helper::ValidatePublicRegistrySecurityDescriptor(descriptor);
    LocalFree(descriptor);
    return result;
}

}  // namespace

int main() {
    Check(
        ValidateSddl(wincur::helper::kPublicRegistrySecurityDescriptor),
        "exact protected public ACL is accepted"
    );
    Check(!wincur::helper::ValidatePublicRegistrySecurityDescriptor(nullptr),
          "null descriptor is rejected");
    Check(
        !ValidateSddl(L"O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"),
        "inheritable DACL is rejected"
    );
    Check(
        !ValidateSddl(L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;BU)"),
        "ordinary-user full control is rejected"
    );
    Check(
        !ValidateSddl(L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KW;;;BU)"),
        "ordinary-user write access is rejected"
    );
    Check(
        !ValidateSddl(L"O:SYG:SYD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"),
        "wrong owner is rejected"
    );
    Check(
        !ValidateSddl(L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"),
        "missing standard-user read ACE is rejected"
    );
    Check(
        !ValidateSddl(
            L"O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"
            L"(A;CI;KR;;;WD)"
        ),
        "unexpected extra principal is rejected"
    );
    Check(
        !ValidateSddl(L"O:BAG:BAD:P(D;CI;KW;;;BU)(A;CI;KA;;;SY)"
                      L"(A;CI;KA;;;BA)(A;CI;KR;;;BU)"),
        "unexpected deny ACE is rejected"
    );

    if (failures != 0) {
        std::cerr << failures << " of " << checks << " ACL checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " ACL checks passed.\n";
    return EXIT_SUCCESS;
}
