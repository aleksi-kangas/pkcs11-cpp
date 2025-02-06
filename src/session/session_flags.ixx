module;

#include <cstdint>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:session_flags;

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
} // namespace pkcs11
