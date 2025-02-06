module;

#include <expected>
#include <vector>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <system_error>
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:encrypt;

import :session;

namespace pkcs11 {
    /**
     * Encrypts single-part data.
     *
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472673">C_Encrypt</a>
     * @param session session
     * @param mechanism mechanism to use for encryption
     * @param encryption_key handle of the encryption key
     * @param data data to encrypt
     * @return encrypted data, or error code
     */
    [[nodiscard]] std::expected<std::vector<unsigned char>, std::error_code> Encrypt(
        const Session& session,
        CK_MECHANISM_PTR mechanism,
        CK_OBJECT_HANDLE encryption_key,
        const std::vector<unsigned char>& data);

    std::expected<std::vector<unsigned char>, std::error_code> Encrypt(const Session& session,
                                                                       CK_MECHANISM_PTR mechanism,
                                                                       CK_OBJECT_HANDLE encryption_key,
                                                                       const std::vector<unsigned char>& data) {
        if (const CK_RV r = session.F()->C_EncryptInit(session, mechanism, encryption_key); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        CK_ULONG encrypted_data_size{0};
        if (const CK_RV r = session.F()->C_Encrypt(session,
                                                   const_cast<CK_BYTE_PTR>(data.data()),
                                                   static_cast<CK_ULONG>(data.size()),
                                                   nullptr,
                                                   &encrypted_data_size); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        std::vector<unsigned char> encrypted_data(encrypted_data_size, 0);
        if (const CK_RV r = session.F()->C_Encrypt(session,
                                                   const_cast<CK_BYTE_PTR>(data.data()),
                                                   static_cast<CK_ULONG>(data.size()),
                                                   encrypted_data.data(),
                                                   &encrypted_data_size); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return encrypted_data;
    }
} // namespace pkcs11
