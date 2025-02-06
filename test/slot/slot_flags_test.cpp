#include <gtest/gtest.h>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

import pkcs11;

TEST(SlotFlags, Mapping) {
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::SlotFlags::kTokenPresent), CKF_TOKEN_PRESENT);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::SlotFlags::kRemovableDevice), CKF_REMOVABLE_DEVICE);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::SlotFlags::kHwSlot), CKF_HW_SLOT);
}
