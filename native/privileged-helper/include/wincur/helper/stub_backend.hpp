#pragma once

#include "wincur/helper/protocol.hpp"

namespace wincur::helper {

enum class BackendOutcome {
    NotImplemented,
};

// Phase 2A intentionally has no provider, configuration reader, registry
// writer, firewall client, rollback store, or external-process facility.
[[nodiscard]] BackendOutcome ExecuteStub(const Request& request) noexcept;

}  // namespace wincur::helper
