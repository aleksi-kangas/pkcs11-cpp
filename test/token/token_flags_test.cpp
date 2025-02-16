#include <utility>

#include <gtest/gtest.h>

#include <core/core.h>

import pkcs11;

TEST(TokenFlags, Mapping) {
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kRng), CKF_RNG);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kWriteProtected), CKF_WRITE_PROTECTED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kLoginRequired), CKF_LOGIN_REQUIRED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kUserPinInitialized), CKF_USER_PIN_INITIALIZED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kRestoreKeyNotNeeded), CKF_RESTORE_KEY_NOT_NEEDED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kClockOnToken), CKF_CLOCK_ON_TOKEN);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kProtectedAuthenticationPath), CKF_PROTECTED_AUTHENTICATION_PATH);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kDualCryptoOperationsParam), CKF_DUAL_CRYPTO_OPERATIONS);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kTokenInitialized), CKF_TOKEN_INITIALIZED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kSecondaryAuthentication), CKF_SECONDARY_AUTHENTICATION);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kUserPinCountLow), CKF_USER_PIN_COUNT_LOW);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kUserPinFinalTry), CKF_USER_PIN_FINAL_TRY);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kUserPinLocked), CKF_USER_PIN_LOCKED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kUserPinToBeChanged), CKF_USER_PIN_TO_BE_CHANGED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kSecurityOfficerPinCountLow), CKF_SO_PIN_COUNT_LOW);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kSecurityOfficerPinFinalTry), CKF_SO_PIN_FINAL_TRY);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kSecurityOfficerPinLocked), CKF_SO_PIN_LOCKED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kSecurityOfficerPinToBeChanged), CKF_SO_PIN_TO_BE_CHANGED);
    EXPECT_EQ(std::to_underlying(pkcs11::TokenFlags::kErrorState), CKF_ERROR_STATE);
}

TEST(TokenFlags, FromUnderlying) {
    constexpr int flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED;
    EXPECT_EQ(static_cast<pkcs11::TokenFlags>(flags),
              pkcs11::TokenFlags::kWriteProtected | pkcs11::TokenFlags::kTokenInitialized);
}

TEST(TokenFlags, ToUnderlying) {
    constexpr auto token_flags = pkcs11::TokenFlags::kWriteProtected | pkcs11::TokenFlags::kTokenInitialized;
    EXPECT_EQ(static_cast<CK_FLAGS>(token_flags),
              CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED);
}
