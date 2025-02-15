#include <gtest/gtest.h>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

import pkcs11;

TEST(TokenFlags, Mapping) {
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kRng),
              CKF_RNG);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kWriteProtected),
              CKF_WRITE_PROTECTED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kLoginRequired),
              CKF_LOGIN_REQUIRED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kUserPinInitialized),
              CKF_USER_PIN_INITIALIZED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kRestoreKeyNotNeeded),
              CKF_RESTORE_KEY_NOT_NEEDED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kClockOnToken),
              CKF_CLOCK_ON_TOKEN);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kProtectedAuthenticationPath),
              CKF_PROTECTED_AUTHENTICATION_PATH);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kDualCryptoOperationsParam),
              CKF_DUAL_CRYPTO_OPERATIONS);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kTokenInitialized),
              CKF_TOKEN_INITIALIZED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kSecondaryAuthentication),
              CKF_SECONDARY_AUTHENTICATION);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kUserPinCountLow),
              CKF_USER_PIN_COUNT_LOW);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kUserPinFinalTry),
              CKF_USER_PIN_FINAL_TRY);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kUserPinLocked),
              CKF_USER_PIN_LOCKED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kUserPinToBeChanged),
              CKF_USER_PIN_TO_BE_CHANGED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kSecurityOfficerPinCountLow),
              CKF_SO_PIN_COUNT_LOW);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kSecurityOfficerPinFinalTry),
              CKF_SO_PIN_FINAL_TRY);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kSecurityOfficerPinLocked),
              CKF_SO_PIN_LOCKED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kSecurityOfficerPinToBeChanged),
              CKF_SO_PIN_TO_BE_CHANGED);
    EXPECT_EQ(static_cast<CK_FLAGS>(pkcs11::TokenFlags::kErrorState),
              CKF_ERROR_STATE);
}
