module;

#include <cstdint>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:slot.flags;

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
} // namespace pkcs11
