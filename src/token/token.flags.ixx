module;

#include <cstdint>

#include <core/core.h>

export module pkcs11:token.flags;

namespace pkcs11 {
    export enum TokenFlags final : std::uint32_t {
        /**
         * If the token has its own random number generator.
         */
        kRng = CKF_RNG,
        /**
         * If the token is write-protected.
         */
        kWriteProtected = CKF_WRITE_PROTECTED,
        /**
         * If there are some cryptographic functions that a user MUST be logged in to perform.
         */
        kLoginRequired = CKF_LOGIN_REQUIRED,
        /**
         * If the normal user’s PIN has been initialized.
         */
        kUserPinInitialized = CKF_USER_PIN_INITIALIZED,
        /**
         * If a successful save of a session’s cryptographic operations state always contains all keys needed to restore the state of the session.
         */
        kRestoreKeyNotNeeded = CKF_RESTORE_KEY_NOT_NEEDED,
        /**
         * If token has its own hardware clock.
         */
        kClockOnToken = CKF_CLOCK_ON_TOKEN,
        /**
         * If token has a “protected authentication path”, whereby a user can log into the token without passing a PIN through the Cryptoki library.
         */
        kProtectedAuthenticationPath = CKF_PROTECTED_AUTHENTICATION_PATH,
        /**
         * If a single session with the token can perform dual cryptographic operations.
         */
        kDualCryptoOperationsParam = CKF_DUAL_CRYPTO_OPERATIONS,
        /**
         * If the token has been initialized using C_InitToken or an equivalent mechanism outside the scope of this standard.
         * Calling C_InitToken when this flag is set will cause the token to be reinitialized.
         */
        kTokenInitialized = CKF_TOKEN_INITIALIZED,
        /**
         * If the token supports secondary authentication for private key objects. (Deprecated; new implementations MUST NOT set this flag)
         * @deprecated
         */
        kSecondaryAuthentication = CKF_SECONDARY_AUTHENTICATION,
        /**
         * if an incorrect user login PIN has been entered at least once since the last successful authentication.
         */
        kUserPinCountLow = CKF_USER_PIN_COUNT_LOW,
        /**
         * If supplying an incorrect user PIN will cause it to become locked.
         */
        kUserPinFinalTry = CKF_USER_PIN_FINAL_TRY,
        /**
         * If the user PIN has been locked. User login to the token is not possible.
         */
        kUserPinLocked = CKF_USER_PIN_LOCKED,
        /**
         * If the user PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
         */
        kUserPinToBeChanged = CKF_USER_PIN_TO_BE_CHANGED,
        /**
         * if an incorrect SO login PIN has been entered at least once since the last successful authentication.
         */
        kSecurityOfficerPinCountLow = CKF_SO_PIN_COUNT_LOW,
        /**
         * If supplying an incorrect SO PIN will cause it to become locked.
         */
        kSecurityOfficerPinFinalTry = CKF_SO_PIN_FINAL_TRY,
        /**
         * If the SO PIN has been locked. SO login to the token is not possible.
         */
        kSecurityOfficerPinLocked = CKF_SO_PIN_LOCKED,
        /**
         * If the SO PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
         */
        kSecurityOfficerPinToBeChanged = CKF_SO_PIN_TO_BE_CHANGED,
        /**
         * If the token failed a FIPS 140-2 self-test and entered an error state.
         */
        kErrorState = CKF_ERROR_STATE,
    };
} // namespace pkcs11
