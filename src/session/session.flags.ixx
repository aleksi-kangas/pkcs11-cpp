module;

#include <cstdint>

#include <core/core.h>

export module pkcs11:session.flags;

import :bitmask;

namespace pkcs11 {
    /**
     * Session type flags
     */
    export enum class SessionFlags final : std::uint32_t {
        kEmpty = 0,
        /**
         * If the session is read/write, otherwise read-only
         */
        kReadWriteSession = CKF_RW_SESSION,
        /**
         * For backward compatibility, and should always be set
         */
        kSerialSession = CKF_SERIAL_SESSION,
    };

    consteval bool enable_bitmask_operator_or(SessionFlags);
} // namespace pkcs11
