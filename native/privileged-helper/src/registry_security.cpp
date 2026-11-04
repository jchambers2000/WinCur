#include "wincur/helper/registry_security.hpp"

#include <AclAPI.h>

#include <array>

namespace wincur::helper {
namespace {

enum class Principal {
    System,
    Administrators,
    Users,
};

[[nodiscard]] bool CreatePrincipalSid(
    const Principal principal,
    std::array<unsigned char, SECURITY_MAX_SID_SIZE>& storage,
    DWORD& size
) noexcept {
    WELL_KNOWN_SID_TYPE type = WinNullSid;
    switch (principal) {
        case Principal::System:
            type = WinLocalSystemSid;
            break;
        case Principal::Administrators:
            type = WinBuiltinAdministratorsSid;
            break;
        case Principal::Users:
            type = WinBuiltinUsersSid;
            break;
    }
    size = static_cast<DWORD>(storage.size());
    return CreateWellKnownSid(type, nullptr, storage.data(), &size) != FALSE;
}

[[nodiscard]] bool SidEqualsPrincipal(
    PSID sid,
    const Principal principal
) noexcept {
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> storage{};
    DWORD size = 0;
    return CreatePrincipalSid(principal, storage, size) &&
           EqualSid(sid, storage.data()) != FALSE;
}

}  // namespace

bool ValidatePublicRegistrySecurityDescriptor(
    PSECURITY_DESCRIPTOR security_descriptor
) noexcept {
    if (security_descriptor == nullptr ||
        !IsValidSecurityDescriptor(security_descriptor)) {
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(security_descriptor, &control, &revision) ||
        (control & SE_DACL_PROTECTED) == 0 ||
        (control & SE_DACL_AUTO_INHERITED) != 0) {
        return false;
    }

    PSID owner = nullptr;
    BOOL owner_defaulted = TRUE;
    if (!GetSecurityDescriptorOwner(
            security_descriptor,
            &owner,
            &owner_defaulted
        ) ||
        owner == nullptr || owner_defaulted != FALSE ||
        !SidEqualsPrincipal(owner, Principal::Administrators)) {
        return false;
    }

    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = TRUE;
    if (!GetSecurityDescriptorDacl(
            security_descriptor,
            &dacl_present,
            &dacl,
            &dacl_defaulted
        ) ||
        dacl_present == FALSE || dacl == nullptr || dacl_defaulted != FALSE) {
        return false;
    }

    ACL_SIZE_INFORMATION information{};
    if (!GetAclInformation(
            dacl,
            &information,
            sizeof(information),
            AclSizeInformation
        ) ||
        information.AceCount != 3) {
        return false;
    }

    bool found_system = false;
    bool found_administrators = false;
    bool found_users = false;
    for (DWORD index = 0; index < information.AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, index, &raw_ace) || raw_ace == nullptr) {
            return false;
        }
        const auto* const ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Header.AceFlags != CONTAINER_INHERIT_ACE) {
            return false;
        }
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        if (SidEqualsPrincipal(sid, Principal::System) &&
            ace->Mask == KEY_ALL_ACCESS && !found_system) {
            found_system = true;
        } else if (SidEqualsPrincipal(sid, Principal::Administrators) &&
                   ace->Mask == KEY_ALL_ACCESS && !found_administrators) {
            found_administrators = true;
        } else if (SidEqualsPrincipal(sid, Principal::Users) &&
                   ace->Mask == KEY_READ && !found_users) {
            found_users = true;
        } else {
            return false;
        }
    }
    return found_system && found_administrators && found_users;
}

bool ValidatePrivateRegistrySecurityDescriptor(
    PSECURITY_DESCRIPTOR security_descriptor
) noexcept {
    if (security_descriptor == nullptr ||
        !IsValidSecurityDescriptor(security_descriptor)) {
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(security_descriptor, &control, &revision) ||
        (control & SE_DACL_PROTECTED) == 0 ||
        (control & SE_DACL_AUTO_INHERITED) != 0) {
        return false;
    }
    PSID owner = nullptr;
    BOOL owner_defaulted = TRUE;
    if (!GetSecurityDescriptorOwner(
            security_descriptor,
            &owner,
            &owner_defaulted
        ) ||
        owner == nullptr || owner_defaulted != FALSE ||
        !SidEqualsPrincipal(owner, Principal::Administrators)) {
        return false;
    }
    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = TRUE;
    if (!GetSecurityDescriptorDacl(
            security_descriptor,
            &dacl_present,
            &dacl,
            &dacl_defaulted
        ) ||
        dacl_present == FALSE || dacl == nullptr || dacl_defaulted != FALSE) {
        return false;
    }
    ACL_SIZE_INFORMATION information{};
    if (!GetAclInformation(
            dacl,
            &information,
            sizeof(information),
            AclSizeInformation
        ) ||
        information.AceCount != 2) {
        return false;
    }
    bool found_system = false;
    bool found_administrators = false;
    for (DWORD index = 0; index < information.AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, index, &raw_ace) || raw_ace == nullptr) {
            return false;
        }
        const auto* const ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Header.AceFlags != CONTAINER_INHERIT_ACE ||
            ace->Mask != KEY_ALL_ACCESS) {
            return false;
        }
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        if (SidEqualsPrincipal(sid, Principal::System) && !found_system) {
            found_system = true;
        } else if (SidEqualsPrincipal(sid, Principal::Administrators) &&
                   !found_administrators) {
            found_administrators = true;
        } else {
            return false;
        }
    }
    return found_system && found_administrators;
}

}  // namespace wincur::helper
