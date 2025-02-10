module;

#include <string>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:slot.info;

import :slot.flags;
import :version;

namespace pkcs11 {
    /**
     * Provides information about a slot.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976542">CK_SLOT_INFO</a>
     */
    export class SlotInfo final {
    public:
        explicit SlotInfo(const CK_SLOT_INFO& info);

        /**
         * @return description of the slot
         */
        [[nodiscard]] std::string SlotDescription() const;

        /**
         * @return ID of the slot manufacturer
         */
        [[nodiscard]] std::string ManufacturerId() const;

        /**
         * @return flags indicating capabilities of the slot
         */
        [[nodiscard]] SlotFlags Flags() const;

        /**
         * @return hardware version of the slot
         */
        [[nodiscard]] Version HardwareVersion() const;

        /**
         * @return firmware version of the slot
         */
        [[nodiscard]] Version FirmwareVersion() const;

    private:
        CK_SLOT_INFO info_;
    };

    SlotInfo::SlotInfo(const CK_SLOT_INFO& info) : info_{info} {
    }

    std::string SlotInfo::SlotDescription() const {
        return std::string{info_.slotDescription, info_.slotDescription + 64};
    }

    std::string SlotInfo::ManufacturerId() const {
        return std::string{info_.manufacturerID, info_.manufacturerID + 32};
    }

    SlotFlags SlotInfo::Flags() const {
        return static_cast<SlotFlags>(info_.flags);
    }

    Version SlotInfo::HardwareVersion() const {
        return Version{info_.hardwareVersion};
    }

    Version SlotInfo::FirmwareVersion() const {
        return Version{info_.firmwareVersion};
    }
} // namespace pkcs11
