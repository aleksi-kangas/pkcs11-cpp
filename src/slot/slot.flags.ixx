module;

#include <cstdint>

#include <core/core.h>

export module pkcs11:slot.flags;

import :bitmask;

namespace pkcs11 {
    export enum SlotFlags final : uint32_t {
        kNone = 0,
        /**
         * A token is present in the slot
         */
        kTokenPresent = CKF_TOKEN_PRESENT,
        /**
         * If the reader supports removable devices
         */
        kRemovableDevice = CKF_REMOVABLE_DEVICE,
        /**
         * If the slot is a hardware slot, as opposed to a software slot implementing a "soft token"
         */
        kHwSlot = CKF_HW_SLOT,
    };

    consteval bool enable_bitmask_operator_or(SlotFlags);
} // namespace pkcs11
