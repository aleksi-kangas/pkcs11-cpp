module;

#include <expected>
#include <system_error>
#include <vector>

#include <core/core.h>

export module pkcs11:verify;

import :session;

namespace pkcs11 {
    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data.
     *
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472714">C_Verify</a>
     * @param session session
     * @param mechanism mechanism to use for verification
     * @param verification_key handle of the verification key
     * @param data data whose signature to verify
     * @param signature signature to verify
     * @return bool (true = valid, false = signature invalid), error code otherwise
     */
    export [[nodiscard]] std::expected<bool, std::error_code> Verify(const Session& session,
                                                                     CK_MECHANISM_PTR mechanism,
                                                                     CK_OBJECT_HANDLE verification_key,
                                                                     const std::vector<unsigned char>& data,
                                                                     const std::vector<unsigned char>& signature);


    std::expected<bool, std::error_code> Verify(const Session& session,
                                                CK_MECHANISM_PTR mechanism,
                                                CK_OBJECT_HANDLE verification_key,
                                                const std::vector<unsigned char>& data,
                                                const std::vector<unsigned char>& signature) {
        if (const CK_RV r = session.F()->C_VerifyInit(session, mechanism, verification_key); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        const CK_RV r = session.F()->C_Verify(session,
                                              const_cast<CK_BYTE_PTR>(data.data()),
                                              static_cast<CK_ULONG>(data.size()),
                                              const_cast<CK_BYTE_PTR>(signature.data()),
                                              static_cast<CK_ULONG>(signature.size()));
        if (r == CKR_OK) {
            return true;
        }
        const auto error = static_cast<Error>(r);
        if (error == Error::kSignatureInvalid || error == Error::kSignatureLenRange) {
            return false;
        }
        return std::unexpected{std::make_error_code(error)};
    }
} // namespace pkcs11
