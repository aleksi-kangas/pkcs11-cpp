module;

#include <cstdint>

#include <core/core.h>

export module pkcs11:session.info;

import :session.flags;
import :session.state;

namespace pkcs11 {
    /**
     * Provides information about a session.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976543">CK_SESSION_INFO</a>
     */
    export class SessionInfo final {
    public:
        explicit SessionInfo(const CK_SESSION_INFO& session_info) : session_info_{session_info} {
        }

        /**
         * @return ID of the slot that interfaces with the token
         */
        [[nodiscard]] std::uint32_t SlotId() const;

        /**
         * @return the state of the session
         */
        [[nodiscard]] SessionState State() const;

        /**
         * @return flags which define the type of the session
         */
        [[nodiscard]] SessionFlags Flags() const;

        /**
         * @return an error code defined by the cryptographic device, used for errors not covered by Cryptoki
         */
        [[nodiscard]] std::uint32_t DeviceError() const;

    private:
        CK_SESSION_INFO session_info_;
    };

    std::uint32_t SessionInfo::SlotId() const {
        return session_info_.slotID;
    }

    SessionState SessionInfo::State() const {
        return static_cast<SessionState>(session_info_.state);
    }

    SessionFlags SessionInfo::Flags() const {
        return static_cast<SessionFlags>(session_info_.flags);
    }

    std::uint32_t SessionInfo::DeviceError() const {
        return session_info_.ulDeviceError;
    }
} // namespace pkcs11
