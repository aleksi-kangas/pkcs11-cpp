#include <gtest/gtest.h>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

import pkcs11;

TEST(SlotInfo, FirmwareVersion) {
    constexpr CK_SLOT_INFO ck_slot_info{.firmwareVersion = {.major = 2, .minor = 40}};
    const pkcs11::SlotInfo slot_info{ck_slot_info};
    EXPECT_EQ(slot_info.FirmwareVersion().Major(), ck_slot_info.firmwareVersion.major);
    EXPECT_EQ(slot_info.FirmwareVersion().Minor(), ck_slot_info.firmwareVersion.minor);
    EXPECT_EQ(slot_info.FirmwareVersion().ToString(), "2.40");
}

TEST(SlotInfo, HardwareVersion) {
    constexpr CK_SLOT_INFO ck_slot_info{.hardwareVersion = {.major = 1, .minor = 23}};
    const pkcs11::SlotInfo slot_info{ck_slot_info};
    EXPECT_EQ(slot_info.HardwareVersion().Major(), ck_slot_info.hardwareVersion.major);
    EXPECT_EQ(slot_info.HardwareVersion().Minor(), ck_slot_info.hardwareVersion.minor);
    EXPECT_EQ(slot_info.HardwareVersion().ToString(), "1.23");
}
