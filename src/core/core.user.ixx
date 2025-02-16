module;

#include <cstdint>

#include <core/core.h>

export module pkcs11:core.user;

namespace pkcs11 {
    /**
     * Types of Cryptoki users
     */
    export enum class UserType : std::uint32_t {
        kSecurityOfficer = CKU_SO,
        kUser = CKU_USER,
        kContextSpecific = CKU_CONTEXT_SPECIFIC,
    };
} // namespace pkcs11
