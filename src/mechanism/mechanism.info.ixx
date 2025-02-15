module;

#include <cstdint>

#include <core/core.h>

export module pkcs11:mechanism.info;

import :mechanism.flags;

namespace pkcs11 {
    export class MechanismInfo final {
    public:
        explicit MechanismInfo(CK_MECHANISM_INFO mechanism_info);

        [[nodiscard]] std::uint32_t MinimumKeySize() const;

        [[nodiscard]] std::uint32_t MaximumKeySize() const;

        [[nodiscard]] MechanismFlags Flags() const;

    private:
        CK_MECHANISM_INFO mechanism_info_;
    };

    MechanismInfo::MechanismInfo(CK_MECHANISM_INFO mechanism_info) : mechanism_info_{mechanism_info} {
    }

    std::uint32_t MechanismInfo::MinimumKeySize() const {
        return mechanism_info_.ulMinKeySize;
    }

    std::uint32_t MechanismInfo::MaximumKeySize() const {
        return mechanism_info_.ulMaxKeySize;
    }

    MechanismFlags MechanismInfo::Flags() const {
        return static_cast<MechanismFlags>(mechanism_info_.flags);
    }
} // namespace pkcs11
