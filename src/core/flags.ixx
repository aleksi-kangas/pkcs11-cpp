module;

#include <cstdint>

export module pkcs11:flags;

namespace pkcs11 {
    /**
     * Flags indicating PKCS#11 capabilities. Reserved for future versions, must be zero for this version.
     */
    export enum class Pkcs11Flags final : std::uint32_t {
        kNone = 0,
    };
} // namespace pkcs11
