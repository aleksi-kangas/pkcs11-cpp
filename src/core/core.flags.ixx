module;

#include <cstdint>

export module pkcs11:core.flags;

import :core.bitmask;

namespace pkcs11 {
    /**
     * Flags indicating PKCS#11 capabilities. Reserved for future versions, must be zero for this version.
     */
    export enum class Pkcs11Flags : std::uint32_t {
        kNone = 0,
    };

    consteval bool enable_bitmask_operator_or(Pkcs11Flags);
} // namespace pkcs11
