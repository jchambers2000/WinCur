#pragma once

#include <Windows.h>

namespace wincur::helper {

enum class MutexAcquireResult {
    Acquired,
    Busy,
    Error,
};

class OperationMutex final {
public:
    OperationMutex() noexcept = default;
    OperationMutex(const OperationMutex&) = delete;
    OperationMutex& operator=(const OperationMutex&) = delete;
    OperationMutex(OperationMutex&&) = delete;
    OperationMutex& operator=(OperationMutex&&) = delete;
    ~OperationMutex() noexcept;

    [[nodiscard]] MutexAcquireResult Acquire() noexcept;

private:
    HANDLE handle_{nullptr};
    bool owns_{false};
};

}  // namespace wincur::helper
