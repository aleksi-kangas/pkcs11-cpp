module;

#include <cstdint>
#include <expected>
#include <memory>
#include <vector>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:slot;

import :error;
import :exception;
import :functions;
import :mechanism.info;
import :session;
import :slot.info;
import :version;

namespace pkcs11 {
    /**
     * A slot which may contain a token.
     */
    export class Slot final : public FunctionListProvider {
    public:
        /**
         * Instantiates a slot wrapper.
         * @param f pointer to the PKCS#11 function list
         * @param slot_id ID of the slot
         */
        Slot(CK_FUNCTION_LIST_PTR f, CK_SLOT_ID slot_id);

        /**
         * @return ID of the slot
         */
        [[nodiscard]] std::uint32_t GetSlotId() const;

        /**
         * Obtains information about the slot.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976614">C_GetSlotInfo</a>
         * and <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976542">CK_SLOT_INFO</a>
         * @return information about the slot
         */
        [[nodiscard]] std::expected<SlotInfo, std::error_code> GetSlotInfo() const noexcept;

        /**
         * Opens a session between the application and the token in the slot.
         * @return a session
         */
        [[nodiscard]] std::expected<std::unique_ptr<Session>, std::error_code> OpenSession() noexcept;

        /**
         * Obtains a list of mechanism types supported by the token.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472645">C_GetMechanismList</a>
         * @return list of mechanism types supported by the token
         */
        [[nodiscard]] std::expected<std::vector<CK_MECHANISM_TYPE>, std::error_code> GetMechanismList() const noexcept;

        /**
         * Obtains information about a particular mechanism possibly supported by the token.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472646">C_GetMechanismInfo</a>
         * @param mechanism_type type of the mechanism
         * @return information about the mechanism
         */
        [[nodiscard]] std::expected<MechanismInfo, std::error_code> GetMechanismInfo(
            CK_MECHANISM_TYPE mechanism_type) const noexcept;

    private:
        CK_SLOT_ID slot_id_;
    };

    Slot::Slot(CK_FUNCTION_LIST_PTR f, const CK_SLOT_ID slot_id) : FunctionListProvider{f}, slot_id_{slot_id} {
    }

    std::uint32_t Slot::GetSlotId() const {
        return slot_id_;
    }

    std::expected<SlotInfo, std::error_code> Slot::GetSlotInfo() const noexcept {
        CK_SLOT_INFO slot_info{};
        if (const CK_RV r = F()->C_GetSlotInfo(slot_id_, &slot_info); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return SlotInfo{slot_info};
    }

    std::expected<std::unique_ptr<Session>, std::error_code> Slot::OpenSession() noexcept {
        try {
            return std::make_unique<Session>(F(), slot_id_);
        } catch (const Pkcs11Exception& e) {
            return std::unexpected{e.ErrorCode()};
        }
    }

    std::expected<std::vector<CK_MECHANISM_TYPE>, std::error_code> Slot::GetMechanismList() const noexcept {
        CK_ULONG mechanism_count{0};
        if (const CK_RV r = F()->C_GetMechanismList(slot_id_, nullptr, &mechanism_count); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        std::vector<CK_MECHANISM_TYPE> mechanism_types{};
        mechanism_types.resize(mechanism_count);
        if (const CK_RV r = F()->C_GetMechanismList(slot_id_, mechanism_types.data(), &mechanism_count); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return mechanism_types;
    }

    std::expected<MechanismInfo, std::error_code> Slot::GetMechanismInfo(
        const CK_MECHANISM_TYPE mechanism_type) const noexcept {
        CK_MECHANISM_INFO mechanism_info{};
        if (const CK_RV r = F()->C_GetMechanismInfo(slot_id_, mechanism_type, &mechanism_info); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return MechanismInfo{mechanism_info};
    }
} // namespace pkcs11
