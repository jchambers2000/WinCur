#include "wincur/helper/windows_uuid.hpp"

#include "wincur/helper/protocol.hpp"

#include <cstdlib>
#include <iostream>

int main() {
    const GUID known{
        0x01234567,
        0x89ab,
        0x4cde,
        {0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd},
    };
    const auto formatted =
        wincur::helper::FormatCanonicalTransactionUuid(known);
    if (formatted.status != wincur::helper::UuidGenerationStatus::Success ||
        formatted.formatted_characters != 39 ||
        formatted.value != L"01234567-89ab-4cde-8f01-23456789abcd" ||
        !wincur::helper::IsCanonicalTransactionUuid(formatted.value)) {
        std::cerr << "Known GUID formatting regression failed.\n";
        return EXIT_FAILURE;
    }
    const auto generated =
        wincur::helper::GenerateCanonicalTransactionUuid();
    if (generated.status != wincur::helper::UuidGenerationStatus::Success ||
        generated.formatted_characters != 39 ||
        !wincur::helper::IsCanonicalTransactionUuid(generated.value)) {
        std::cerr << "Generated UUID is not canonical.\n";
        return EXIT_FAILURE;
    }
    std::cout << "UUID formatting tests passed.\n";
    return EXIT_SUCCESS;
}
