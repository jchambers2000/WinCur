#pragma once

#include "wincur/helper/confirmation.hpp"

namespace wincur::helper {

class WindowsConfirmationPresenter final : public ConfirmationPresenter {
public:
    [[nodiscard]] ConfirmationReceipt Present(
        const ConfirmationPrompt& prompt,
        std::uint64_t challenge
    ) noexcept override;
};

[[nodiscard]] std::uint64_t CreateConfirmationChallenge() noexcept;

}  // namespace wincur::helper
