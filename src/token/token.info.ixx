module;

#include <cstdint>
#include <string>

#include <core/core.h>

export module pkcs11:token.info;

import :token.flags;
import :version;

namespace pkcs11 {
    /**
     * Provides information about a token.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976542">CK_TOKEN_INFO</a>
     */
    export class TokenInfo final {
    public:
        explicit TokenInfo(const CK_TOKEN_INFO& token_info);

        /**
         * @return application-defined label, assigned during token initialization
         */
        [[nodiscard]] std::string Label() const;

        /**
         * @return ID of the device manufacturer
         */
        [[nodiscard]] std::string ManufacturerId() const;

        /**
         * @return model of the device
         */
        [[nodiscard]] std::string Model() const;

        /**
         * @return character-string serial number of the device
         */
        [[nodiscard]] std::string SerialNumber() const;

        /**
         * @return flags indicating capabilities and status of the device
         */
        [[nodiscard]] TokenFlags Flags() const;

        /**
         * @return maximum number of sessions that can be opened with the token at one time by a single application
         */
        [[nodiscard]] std::uint32_t MaxSessionCount() const;

        /**
         * @return number of sessions that this application currently has open with the token
         */
        [[nodiscard]] std::uint32_t SessionCount() const;

        /**
         * @return maximum number of read/write sessions that can be opened with the token at one time by a single application
         */
        [[nodiscard]] std::uint32_t MaxRwSessionCount() const;

        /**
         * @return number of read/write sessions that this application currently has open with the token
         */
        [[nodiscard]] std::uint32_t SessionRwCount() const;

        /**
         * @return maximum length in bytes of the PIN
         */
        [[nodiscard]] std::uint32_t MaxPinLength() const;

        /**
         * @return minimum length in bytes of the PIN
         */
        [[nodiscard]] std::uint32_t MinPinLength() const;

        /**
         * @return the total amount of memory on the token in bytes in which public objects may be stored
         */
        [[nodiscard]] std::uint32_t TotalPublicMemory() const;

        /**
         * @return the amount of free (unused) memory on the token in bytes for public objects
         */
        [[nodiscard]] std::uint32_t FreePublicMemory() const;

        /**
         * @return the total amount of memory on the token in bytes in which private objects may be stored
         */
        [[nodiscard]] std::uint32_t TotalPrivateMemory() const;

        /**
         * @return the amount of free (unused) memory on the token in bytes for private objects
         */
        [[nodiscard]] std::uint32_t FreePrivateMemory() const;

        /**
         * @return version number of hardware
         */
        [[nodiscard]] Version HardwareVersion() const;

        /**
         * @return version number of firmware
         */
        [[nodiscard]] Version FirmwareVersion() const;

        /**
         * @return current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx (4 characters for the year;  2 characters each for the month, the day, the hour, the minute, and the second; and 2 additional reserved ‘0’ characters)
         * @note The value of this field only makes sense for tokens equipped with a clock, as indicated in the token information flags.
         */
        [[nodiscard]] std::string UtcTime() const;

    private:
        CK_TOKEN_INFO token_info_;
    };

    TokenInfo::TokenInfo(const CK_TOKEN_INFO& token_info) : token_info_{token_info} {
    }

    std::string TokenInfo::Label() const {
        return std::string{token_info_.label, token_info_.label + 32};
    }

    std::string TokenInfo::ManufacturerId() const {
        return std::string{token_info_.manufacturerID, token_info_.manufacturerID + 32};
    }

    std::string TokenInfo::Model() const {
        return std::string{token_info_.model, token_info_.model + 16};
    }

    std::string TokenInfo::SerialNumber() const {
        return std::string{token_info_.serialNumber, token_info_.serialNumber + 16};
    }

    TokenFlags TokenInfo::Flags() const {
        return static_cast<TokenFlags>(token_info_.flags);
    }

    std::uint32_t TokenInfo::MaxSessionCount() const {
        return token_info_.ulMaxSessionCount;
    }

    std::uint32_t TokenInfo::SessionCount() const {
        return token_info_.ulSessionCount;
    }

    std::uint32_t TokenInfo::MaxRwSessionCount() const {
        return token_info_.ulMaxRwSessionCount;
    }

    std::uint32_t TokenInfo::SessionRwCount() const {
        return token_info_.ulRwSessionCount;
    }

    std::uint32_t TokenInfo::MaxPinLength() const {
        return token_info_.ulMaxPinLen;
    }

    std::uint32_t TokenInfo::MinPinLength() const {
        return token_info_.ulMinPinLen;
    }

    std::uint32_t TokenInfo::TotalPublicMemory() const {
        return token_info_.ulTotalPublicMemory;
    }

    std::uint32_t TokenInfo::FreePublicMemory() const {
        return token_info_.ulFreePublicMemory;
    }

    std::uint32_t TokenInfo::TotalPrivateMemory() const {
        return token_info_.ulTotalPrivateMemory;
    }

    std::uint32_t TokenInfo::FreePrivateMemory() const {
        return token_info_.ulFreePrivateMemory;
    }

    Version TokenInfo::HardwareVersion() const {
        return Version{token_info_.hardwareVersion};
    }

    Version TokenInfo::FirmwareVersion() const {
        return Version{token_info_.firmwareVersion};
    }

    std::string TokenInfo::UtcTime() const {
        return std::string{token_info_.utcTime, token_info_.utcTime + 16};
    }
} // namespace pkcs11
