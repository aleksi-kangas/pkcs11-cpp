module;

#include <algorithm>
#include <expected>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <vector>

#include <windows.h>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:core;

export import :flags;
export import :info;

import :error;
import :exception;
import :slot;

namespace pkcs11 {
    /**
     * The main PKCS#11 module.
     * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html">PKCS#11 3.0 standard</a>.
     */
    export class Pkcs11 final {
    public:
        /**
         * Instantiates the main PKCS#11 module.
         * @param library_path path to the PKCS#11 implementation
         */
        explicit Pkcs11(const std::filesystem::path& library_path);

        ~Pkcs11();

        Pkcs11(const Pkcs11&) = delete;

        Pkcs11& operator=(const Pkcs11&) = delete;

        Pkcs11(Pkcs11&&) = delete;

        Pkcs11& operator=(Pkcs11&&) = delete;

        /**
         * Obtains general information about Cryptoki.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976608">C_GetInfo</a>
         * @return general information about Cryptoki
         */
        [[nodiscard]] std::expected<Info, std::error_code> GetInfo() const noexcept;

        /**
         * Obtains a list of slots in the system.
         * See: <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html#_Toc29976613">C_GetSlotList</a>
         * @param withTokenPresent whether the list obtained includes only those slots with a token present
         * @return a list of slots in the system
         * @see C_GetSlotList
         */
        [[nodiscard]] std::expected<std::vector<Slot>, std::error_code> GetSlotList(
            bool withTokenPresent) const noexcept;

    private:
        HMODULE library_{nullptr};

        CK_FUNCTION_LIST_PTR f_{nullptr};

        void Initialize() const;

        void Finalize() const;
    };


    Pkcs11::Pkcs11(const std::filesystem::path& library_path) {
        library_ = LoadLibraryW(library_path.c_str());
        if (library_ == nullptr) {
            throw std::runtime_error("Failed to load PKCS11 libray");
        }
        const auto f = reinterpret_cast<CK_C_GetFunctionList>(GetProcAddress(library_, "C_GetFunctionList"));
        if (f == nullptr) {
            throw std::runtime_error("Failed to get address of C_GetFunctionList");
        }
        if (const CK_RV result = f(&f_); result != CKR_OK) {
            throw Pkcs11Exception{static_cast<Error>(result)};
        }
        Initialize();
    }

    Pkcs11::~Pkcs11() {
        if (library_ != nullptr) {
            try {
                Finalize();
                FreeLibrary(library_);
            } catch (const Pkcs11Exception& e) {
                std::cerr << e.what() << std::endl;
            }
        }
    }

    std::expected<Info, std::error_code> Pkcs11::GetInfo() const noexcept {
        CK_INFO info{};
        if (const CK_RV r = f_->C_GetInfo(&info); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        return Info{info};
    }

    std::expected<std::vector<Slot>, std::error_code> Pkcs11::GetSlotList(const bool withTokenPresent) const noexcept {
        CK_ULONG slot_count{0};
        if (const CK_RV r = f_->C_GetSlotList(withTokenPresent, nullptr, &slot_count); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        if (slot_count == 0) {
            return {};
        }
        std::vector<CK_SLOT_ID> slot_ids(slot_count);
        if (const CK_RV r = f_->C_GetSlotList(withTokenPresent, slot_ids.data(), &slot_count); r != CKR_OK) {
            return std::unexpected{std::make_error_code(static_cast<Error>(r))};
        }
        std::vector<Slot> slots{};
        slots.reserve(slot_count);
        std::ranges::transform(slot_ids, std::back_inserter(slots),
                               [this](const CK_SLOT_ID slot_id) -> Slot { return Slot{f_, slot_id}; });
        return slots;
    }

    void Pkcs11::Initialize() const {
        if (const CK_RV r = f_->C_Initialize(nullptr); r != CKR_OK) {
            throw Pkcs11Exception{static_cast<Error>(r)};
        }
    }

    void Pkcs11::Finalize() const {
        if (const CK_RV r = f_->C_Finalize(nullptr); r != CKR_OK) {
            throw Pkcs11Exception{static_cast<Error>(r)};
        }
    }
} // namespace pkcs11
