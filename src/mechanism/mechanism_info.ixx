module;

#include <cstdint>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:mechanism_info;

import :mechanism_flags;

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
