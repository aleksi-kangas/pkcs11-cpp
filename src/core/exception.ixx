module;

#include <stdexcept>

export module pkcs11:exception;

import :error;

namespace pkcs11 {
    export struct Pkcs11Exception final : std::exception {
        explicit Pkcs11Exception(Error error);

        [[nodiscard]] const char* what() const override;

        [[nodiscard]] std::error_code ErrorCode() const;

    private:
        const Error error_;
    };

    Pkcs11Exception::Pkcs11Exception(const Error error) : error_{error} {
    }

    const char* Pkcs11Exception::what() const {
        return ErrorCode().message().c_str();
    }

    std::error_code Pkcs11Exception::ErrorCode() const {
        return std::make_error_code(error_);
    }
} // namespace pkcs11
