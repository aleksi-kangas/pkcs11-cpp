module;

#include <cstdint>
#include <expected>
#include <iostream>
#include <ostream>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:session;

import :error;
import :exception;
import :functions;
import :mechanism.info;
import :session.info;
import :user;

namespace pkcs11 {
    /**
     * A session between an application and a token in a particular slot.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976622">Session Management</a>
     */
    export class Session final : public FunctionListProvider {
    public:
        /**
         * Opens a session to the token in the given slot.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472651">C_OpenSession</a>
         * @note Should not be called directly, instead use Slot::OpenSession.
         * @param f pointer to the PKCS#11 3.0 function list
         * @param slot_id ID of the slot
         * @throws {@link Pkcs11Exception}
         */
        Session(CK_FUNCTION_LIST_PTR f, std::uint32_t slot_id);

        /**
         * Closes the session.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472652">C_CloseSession</a>
         */
        ~Session();

        Session(const Session&) = delete;

        Session& operator=(const Session&) = delete;

        Session(Session&&) = default;

        Session& operator=(Session&&) = default;

        /**
         * Obtains information about the session.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976626">C_GetSessionInfo</a>
         * and <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976543">CK_SESSION_INFO</a>
         * @return information about the session
         */
        [[nodiscard]] std::expected<SessionInfo, std::error_code> GetInfo() const noexcept;

        /**
         * Logs a user into a token.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976630">C_Login</a>
         * @param user_type type of the user
         * @param pin user's PIN, the standard allows any valid UTF-8 character, but the token may impose subset restrictions
         * @param pin_length length of the PIN
         */
        std::expected<void, std::error_code> Login(UserType user_type, unsigned char pin[],
                                                   std::uint32_t pin_length) noexcept;

        /**
         * Logs a user out from a token.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976632">C_Logout</a>
         */
        std::expected<void, std::error_code> Logout() noexcept;

        /**
         * Conversion to the underlying <code>CK_SESSION_HANDLE</code>.
         */
        operator CK_SESSION_HANDLE() const noexcept;

    private:
        CK_SESSION_HANDLE session_handle_{};
    };

    Session::Session(CK_FUNCTION_LIST_PTR f, std::uint32_t slot_id) : FunctionListProvider{f} {
        if (const CK_RV r = F()->C_OpenSession(slot_id,
                                               static_cast<CK_FLAGS>(SessionFlags::kSerialSession),
                                               nullptr,
                                               nullptr,
                                               &session_handle_); r != CKR_OK) {
            throw Pkcs11Exception{static_cast<Error>(r)};
        }
    }

    Session::~Session() {
        if (session_handle_ != CK_INVALID_HANDLE) {
            if (const CK_RV r = F()->C_CloseSession(session_handle_); r != CKR_OK) {
                std::cerr << std::make_error_code(static_cast<Error>(r)) << std::endl;
            }
        }
    }

    std::expected<SessionInfo, std::error_code> Session::GetInfo() const noexcept {
        CK_SESSION_INFO session_info{};
        if (const CK_RV r = F()->C_GetSessionInfo(session_handle_, &session_info); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return SessionInfo{session_info};
    }

    std::expected<void, std::error_code> Session::Login(UserType user_type, unsigned char pin[],
                                                        std::uint32_t pin_length) noexcept {
        if (const CK_RV r = F()->C_Login(session_handle_,
                                         static_cast<CK_USER_TYPE>(user_type),
                                         pin,
                                         pin_length); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return {};
    }

    std::expected<void, std::error_code> Session::Logout() noexcept {
        if (const CK_RV r = F()->C_Logout(session_handle_); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return {};
    }

    Session::operator CK_SESSION_HANDLE() const noexcept {
        return session_handle_;
    }
} // namespace pkcs11
