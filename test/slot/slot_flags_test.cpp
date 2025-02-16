#include <utility>

#include <gtest/gtest.h>

#include <core/core.h>

import pkcs11;

TEST(SlotFlags, Mapping) {
    EXPECT_EQ(std::to_underlying(pkcs11::SlotFlags::kTokenPresent), CKF_TOKEN_PRESENT);
    EXPECT_EQ(std::to_underlying(pkcs11::SlotFlags::kRemovableDevice), CKF_REMOVABLE_DEVICE);
    EXPECT_EQ(std::to_underlying(pkcs11::SlotFlags::kHwSlot), CKF_HW_SLOT);
}

TEST(SlotFlags, FromUnderlying) {
    constexpr int flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE;
    EXPECT_EQ(static_cast<pkcs11::SlotFlags>(flags),
              pkcs11::SlotFlags::kTokenPresent | pkcs11::SlotFlags::kRemovableDevice);
}

TEST(SlotFlags, ToUnderlying) {
    constexpr auto slot_flags = pkcs11::SlotFlags::kTokenPresent | pkcs11::SlotFlags::kRemovableDevice;
    EXPECT_EQ(static_cast<CK_FLAGS>(slot_flags),
              CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE);
}
