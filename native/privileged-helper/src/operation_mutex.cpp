#include "wincur/helper/operation_mutex.hpp"

#include <Sddl.h>

namespace wincur::helper {
namespace {

constexpr wchar_t kMutexName[] =
    L"Global\\WinCur.PrivilegedHelper.Operation.v1";
constexpr wchar_t kMutexSecurityDescriptor[] =
    L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";

}  // namespace

OperationMutex::~OperationMutex() noexcept {
    if (owns_ && handle_ != nullptr) {
        ReleaseMutex(handle_);
    }
    if (handle_ != nullptr) {
        CloseHandle(handle_);
    }
}

MutexAcquireResult OperationMutex::Acquire() noexcept {
    if (handle_ != nullptr) {
        return owns_ ? MutexAcquireResult::Acquired : MutexAcquireResult::Error;
    }

    PSECURITY_DESCRIPTOR security_descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kMutexSecurityDescriptor,
            SDDL_REVISION_1,
            &security_descriptor,
            nullptr)) {
        return MutexAcquireResult::Error;
    }

    SECURITY_ATTRIBUTES security_attributes{};
    security_attributes.nLength = sizeof(security_attributes);
    security_attributes.lpSecurityDescriptor = security_descriptor;
    security_attributes.bInheritHandle = FALSE;

    handle_ = CreateMutexExW(
        &security_attributes,
        kMutexName,
        0,
        SYNCHRONIZE | MUTEX_MODIFY_STATE
    );
    LocalFree(security_descriptor);

    if (handle_ == nullptr) {
        return MutexAcquireResult::Error;
    }

    const DWORD wait_result = WaitForSingleObject(handle_, 0);
    if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED) {
        owns_ = true;
        return MutexAcquireResult::Acquired;
    }
    if (wait_result == WAIT_TIMEOUT) {
        return MutexAcquireResult::Busy;
    }
    return MutexAcquireResult::Error;
}

}  // namespace wincur::helper
