module;

#include <cstdint>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:user_type;

namespace pkcs11 {
    /**
     * Types of Cryptoki users
     */
    export enum class UserType final : std::uint32_t {
        kSecurityOfficer = CKU_SO,
        kUser = CKU_USER,
        kContextSpecific = CKU_CONTEXT_SPECIFIC,
    };
} // namespace pkcs11
