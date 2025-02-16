module;

#include <format>
#include <stdexcept>
#include <system_error>

export module pkcs11:core.exception;

import :core.error;

namespace pkcs11 {
    export struct Pkcs11Exception final : std::exception {
        explicit Pkcs11Exception(Error error);

        [[nodiscard]] const char* what() const noexcept override;

        [[nodiscard]] std::error_code ErrorCode() const;

    private:
        Error error_;
        std::error_code error_code_;
        std::string error_string_;
    };

    Pkcs11Exception::Pkcs11Exception(const Error error) : error_{error},
                                                          error_code_{std::make_error_code(error)},
                                                          error_string_{error_code_.message()} {
    }

    const char* Pkcs11Exception::what() const noexcept {
        return error_string_.c_str();
    }

    std::error_code Pkcs11Exception::ErrorCode() const {
        return error_code_;
    }
} // namespace pkcs11
