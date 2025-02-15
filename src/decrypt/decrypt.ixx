module;

#include <expected>
#include <vector>

#include <core/core.h>

export module pkcs11:decrypt;

import :session;

namespace pkcs11 {
    /**
     * Decrypts encrypted data in a single part.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472684">C_Decrypt</a>
     * @param session session
     * @param mechanism mechanism to use for decryption
     * @param decryption_key handle of the decryption key
     * @param encrypted_data encrypted data to ecrypt
     * @return decrypted data, or error code
     */
    [[nodiscard]] std::expected<std::vector<unsigned char>, std::error_code> Decrypt(
        const Session& session,
        CK_MECHANISM_PTR mechanism,
        CK_OBJECT_HANDLE decryption_key,
        const std::vector<unsigned char>& encrypted_data);

    std::expected<std::vector<unsigned char>, std::error_code> Decrypt(const Session& session,
                                                                       CK_MECHANISM_PTR mechanism,
                                                                       CK_OBJECT_HANDLE decryption_key,
                                                                       const std::vector<unsigned char>&
                                                                       encrypted_data) {
        if (const CK_RV r = session.F()->C_DecryptInit(session, mechanism, decryption_key); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        CK_ULONG decrypted_data_size{0};
        if (const CK_RV r = session.F()->C_Decrypt(session,
                                                   const_cast<CK_BYTE_PTR>(encrypted_data.data()),
                                                   static_cast<CK_ULONG>(encrypted_data.size()),
                                                   nullptr,
                                                   &decrypted_data_size); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        std::vector<unsigned char> decrypted_data(decrypted_data_size, 0);
        if (const CK_RV r = session.F()->C_Decrypt(session,
                                                   const_cast<CK_BYTE_PTR>(encrypted_data.data()),
                                                   static_cast<CK_ULONG>(encrypted_data.size()),
                                                   decrypted_data.data(),
                                                   &decrypted_data_size); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return decrypted_data;
    }
} // namespace pkcs11
