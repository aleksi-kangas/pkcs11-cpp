module;

#include <cstdint>
#include <format>
#include <ostream>
#include <string>

#include <core/core.h>

export module pkcs11:core.version;

namespace pkcs11 {
    /**
     * Common Version information.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976541">CK_VERSION</a>
     */
    export class Version final {
    public:
        explicit Version(const CK_VERSION& version);

        /**
         * @return the major version
         */
        [[nodiscard]] std::uint8_t Major() const noexcept;

        /**
         * @return the minor version
         */
        [[nodiscard]] std::uint8_t Minor() const noexcept;

        /**
         * @return the string representation of the version, e.g "2.40"
         */
        [[nodiscard]] std::string ToString() const noexcept;

        friend std::ostream& operator<<(std::ostream& os, const Version& obj) {
            return os << obj.ToString();
        }

    private:
        CK_VERSION version_;
    };

    Version::Version(const CK_VERSION& version) : version_(version) {
    }

    std::uint8_t Version::Major() const noexcept {
        return version_.major;
    }

    std::uint8_t Version::Minor() const noexcept {
        return version_.minor;
    }

    std::string Version::ToString() const noexcept {
        return std::format("{}.{}", version_.major, version_.minor);
    }
} // namespace pkcs11
