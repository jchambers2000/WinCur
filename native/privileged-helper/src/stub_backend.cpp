#include "wincur/helper/stub_backend.hpp"

namespace wincur::helper {

BackendOutcome ExecuteStub(const Request& request) noexcept {
    static_cast<void>(request);
    return BackendOutcome::NotImplemented;
}

}  // namespace wincur::helper
