module;

#include <string>

#include <core/core.h>

export module pkcs11:core.info;

import :core.flags;
import :core.version;

namespace pkcs11 {
    /**
     *Provides general information about Cryptoki.
     *See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976541">CK_INFO</a>
     */
    export class Info {
    public:
        explicit Info(const CK_INFO& info);

        /**
         * @return Cryptoki interface version
         */
        [[nodiscard]] Version CryptokiVersion() const;

        /**
         * @return ID of the Cryptoki library manufacturer
         */
        [[nodiscard]] std::string ManufacturerId() const;

        /**
         * @return indicating PKCS#11 capabilities, reserved for future versions, must be zero for this version
         */
        [[nodiscard]] Pkcs11Flags Flags() const;

        /**
         * @return Cryptoki library description
         */
        [[nodiscard]] std::string LibraryDescription() const;

        /**
         * @return Cryptoki library version
         */
        [[nodiscard]] Version LibraryVersion() const;

    private:
        CK_INFO info_{};
    };

    Info::Info(const CK_INFO& info) : info_{info} {
    }

    Version Info::CryptokiVersion() const {
        return Version{info_.cryptokiVersion};
    }

    std::string Info::ManufacturerId() const {
        return std::string{info_.manufacturerID, info_.manufacturerID + 32};
    }

    Pkcs11Flags Info::Flags() const {
        return static_cast<Pkcs11Flags>(info_.flags);
    }

    std::string Info::LibraryDescription() const {
        return std::string{info_.manufacturerID, info_.manufacturerID + 32};
    }

    Version Info::LibraryVersion() const {
        return Version{info_.libraryVersion};
    }
} // namespace pkcs11
