module;

#include <cstdint>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:mechanism_flags;

namespace pkcs11 {
    export enum class MechanismFlags final : std::uint32_t {
        /**
         * If the mechanism is performed by the device, otherwise the mechanism is performed in software.
         */
        kHardware = CKF_HW,
        /**
         * If the mechanism can be used with <code>C_MessageEncryptInit</code>.
         */
        kMessageEncrypt = CKF_MESSAGE_ENCRYPT,
        /**
         * If the mechanism can be used with <code>C_MessageDecryptInit</code>.
         */
        kMessageDecrypt = CKF_MESSAGE_DECRYPT,
        /**
         * If the mechanism can be used with <code>C_MessageSignInit</code>.
         */
        kMessageSign = CKF_MESSAGE_SIGN,
        /**
         * If the mechanism can be used with <code>C_MessageVerifyInit</code>.
         */
        kMessageVerify = CKF_MESSAGE_VERIFY,
        /**
         * If the mechanism can be used with <code>C_*MessageBegin</code>.
         * One of <code>kMessage*</code> (<code>CKF_MESSAGE_*</code>) flags must also be set.
         */
        kMultiMessage = CKF_MULTI_MESSAGE,
        /**
         * Can be passed as a parameter to <code>C_SessionCancel</code> to cancel an active object search operation.
         * Any other use of this flag is outside the scope of this standard.
         */
        kFindObjects = CKF_FIND_OBJECTS,
        /**
         * If the mechanism can be used with <code>C_EncryptInit</code>.
         */
        kEncrypt = CKF_ENCRYPT,
        /**
         * If the mechanism can be used with <code>C_DecryptInit</code>.
         */
        kDecrypt = CKF_DECRYPT,
        /**
         * If the mechanism can be used with <code>C_DigestInit</code>.
         */
        kDigest = CKF_DIGEST,
        /**
         * If the mechanism can be used with <code>C_SignInit</code>.
         */
        kSign = CKF_SIGN,
        /**
         * If the mechanism can be used with <code>C_SignRecoverInit</code>.
         */
        kSignRecover = CKF_SIGN_RECOVER,
        /**
         * If the mechanism can be used with <code>C_VerifyInit</code>.
         */
        kVerify = CKF_VERIFY,
        /**
         * If the mechanism can be used with <code>C_VerifyRecoverInit</code>.
         */
        kVerifyRecover = CKF_VERIFY_RECOVER,
        /**
         * If the mechanism can be used with <code>C_GenerateKey</code>.
         */
        kGenerateKey = CKF_GENERATE,
        /**
         * If the mechanism can be used with <code>C_GenerateKeyPair</code>.
         */
        kGenerateKeyPair = CKF_GENERATE_KEY_PAIR,
        /**
         * If the mechanism can be used with <code>C_WrapKey</code>.
         */
        kWrapKey = CKF_WRAP,
        /**
         * If the mechanism can be used with <code>C_UnwrapKey</code>.
         */
        kUnwrapKey = CKF_UNWRAP,
        /**
         * If the mechanism can be used with <code>C_DeriveKey</code>.
         */
        kDeriveKey = CKF_DERIVE,
        /**
         * If there is an extension to the flags, otherwise no extensions.
         * Must not be present for this version.
         */
        kExtension = CKF_EXTENSION,
    };
} // namespace pkcs11
