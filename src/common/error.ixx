module;

#include <cstdint>
#include <system_error>
#include <type_traits>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

#define ERROR_TO_STRING(e) case e: return #e

export module pkcs11:error;

namespace pkcs11 {
    export enum class Error final : std::uint64_t {
        kCancel = CKR_CANCEL,
        kHostMemory = CKR_HOST_MEMORY,
        kSlotIdInvalid = CKR_SLOT_ID_INVALID,

        kGeneralError = CKR_GENERAL_ERROR,
        kFunctionFailed = CKR_FUNCTION_FAILED,

        kArgumentsBad = CKR_ARGUMENTS_BAD,
        kNoEvent = CKR_NO_EVENT,
        kNeedToCreateThreads = CKR_NEED_TO_CREATE_THREADS,
        kCantLock = CKR_CANT_LOCK,

        kAttributeReadOnly = CKR_ATTRIBUTE_READ_ONLY,
        kAttributeSensitive = CKR_ATTRIBUTE_SENSITIVE,
        kAttributeTypeInvalid = CKR_ATTRIBUTE_TYPE_INVALID,
        kAttributeValueInvalid = CKR_ATTRIBUTE_VALUE_INVALID,

        kActionProhibited = CKR_ACTION_PROHIBITED,

        kDataInvalid = CKR_DATA_INVALID,
        kDataLenRange = CKR_DATA_LEN_RANGE,
        kDeviceError = CKR_DEVICE_ERROR,
        kDeviceMemory = CKR_DEVICE_MEMORY,
        kDeviceRemoved = CKR_DEVICE_REMOVED,
        kEncryptedDataInvalid = CKR_ENCRYPTED_DATA_INVALID,
        kEncryptedDataLenRange = CKR_ENCRYPTED_DATA_LEN_RANGE,
        KAeadDecryptFailed = CKR_AEAD_DECRYPT_FAILED,
        kFunctionCanceled = CKR_FUNCTION_CANCELED,
        kFunctionNotParallel = CKR_FUNCTION_NOT_PARALLEL,

        kFunctionNotSupported = CKR_FUNCTION_NOT_SUPPORTED,

        kKeyHandleInvalid = CKR_KEY_HANDLE_INVALID,

        kKeySizeRange = CKR_KEY_SIZE_RANGE,
        kKeyTypeInconsistent = CKR_KEY_TYPE_INCONSISTENT,

        kKeyNotNeeded = CKR_KEY_NOT_NEEDED,
        kKeyChanged = CKR_KEY_CHANGED,
        kKeyNeeded = CKR_KEY_NEEDED,
        kKeyIndigestible = CKR_KEY_INDIGESTIBLE,
        kKeyFunctionNotPermitted = CKR_KEY_FUNCTION_NOT_PERMITTED,
        kKeyNotWrappable = CKR_KEY_NOT_WRAPPABLE,
        kKeyUnextractable = CKR_KEY_UNEXTRACTABLE,

        KMechanismInvalid = CKR_MECHANISM_INVALID,
        kMechanismParamInvalid = CKR_MECHANISM_PARAM_INVALID,

        kObjectHandleInvalid = CKR_OBJECT_HANDLE_INVALID,
        kOperationActive = CKR_OPERATION_ACTIVE,
        kOperationNotInitialized = CKR_OPERATION_NOT_INITIALIZED,
        kPinIncorrect = CKR_PIN_INCORRECT,
        kPinInvalid = CKR_PIN_INVALID,
        kPinLenRange = CKR_PIN_LEN_RANGE,

        kPinExpired = CKR_PIN_EXPIRED,
        kPinLocked = CKR_PIN_LOCKED,

        kSessionClosed = CKR_SESSION_CLOSED,
        kSessionCount = CKR_SESSION_COUNT,
        kSessionHandleInvalid = CKR_SESSION_HANDLE_INVALID,
        kSessionParallelNotSupported = CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        kSessionReadOnly = CKR_SESSION_READ_ONLY,
        kSessionExists = CKR_SESSION_EXISTS,

        kSessionReadOnlyExists = CKR_SESSION_READ_ONLY_EXISTS,
        kSessionReadWriteSecurityOfficerExists = CKR_SESSION_READ_WRITE_SO_EXISTS,

        kSignatureInvalid = CKR_SIGNATURE_INVALID,
        kSignatureLenRange = CKR_SIGNATURE_LEN_RANGE,
        kTemplateIncomplete = CKR_TEMPLATE_INCOMPLETE,
        kTemplateInconsistent = CKR_TEMPLATE_INCONSISTENT,
        kTokenNotPresent = CKR_TOKEN_NOT_PRESENT,
        kTokenNotRecognized = CKR_TOKEN_NOT_RECOGNIZED,
        kTokenWriteProtected = CKR_TOKEN_WRITE_PROTECTED,
        kUnwrappingKeyHandleInvalid = CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        kUnwrappingKeySizeRange = CKR_UNWRAPPING_KEY_SIZE_RANGE,
        kUnwrappingKeyTypeInconsistent = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        kUserAlreadyLoggedIn = CKR_USER_ALREADY_LOGGED_IN,
        kUserNotLoggedIn = CKR_USER_NOT_LOGGED_IN,
        kUserPinNotInitialized = CKR_USER_PIN_NOT_INITIALIZED,
        kUserTypeInvalid = CKR_USER_TYPE_INVALID,

        kUserAnotherAlreadyLoggedIn = CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        kUserTooManyTypes = CKR_USER_TOO_MANY_TYPES,

        kWrappedKeyInvalid = CKR_WRAPPED_KEY_INVALID,
        kWrappedKeyLenRange = CKR_WRAPPED_KEY_LEN_RANGE,
        kWrappingKeyHandleInvalid = CKR_WRAPPING_KEY_HANDLE_INVALID,
        kWrappingKeySizeRange = CKR_WRAPPING_KEY_SIZE_RANGE,
        kWrappingKeyTypeInconsistent = CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        kRandomSeedNotSupported = CKR_RANDOM_SEED_NOT_SUPPORTED,

        kRandomNoRng = CKR_RANDOM_NO_RNG,

        kDomainParamsInvalid = CKR_DOMAIN_PARAMS_INVALID,

        kCurveNotSupported = CKR_CURVE_NOT_SUPPORTED,

        kBufferTooSmall = CKR_BUFFER_TOO_SMALL,
        kSavedStateInvalid = CKR_SAVED_STATE_INVALID,
        kInformationSensitive = CKR_INFORMATION_SENSITIVE,
        kStateUnsaveable = CKR_STATE_UNSAVEABLE,

        kCryptokiNotInitialized = CKR_CRYPTOKI_NOT_INITIALIZED,
        kCryptokiAlreadyInitialized = CKR_CRYPTOKI_ALREADY_INITIALIZED,
        kMutexBad = CKR_MUTEX_BAD,
        kMutexNotLocked = CKR_MUTEX_NOT_LOCKED,

        kNewPinMode = CKR_NEW_PIN_MODE,
        kNextOtp = CKR_NEXT_OTP,

        kExceededMaxIterations = CKR_EXCEEDED_MAX_ITERATIONS,
        kFipsSelfTestFailed = CKR_FIPS_SELF_TEST_FAILED,
        kLibraryLoadFailed = CKR_LIBRARY_LOAD_FAILED,
        kPinTooWeak = CKR_PIN_TOO_WEAK,
        kPublicKeyInvalid = CKR_PUBLIC_KEY_INVALID,

        kFunctionRejected = CKR_FUNCTION_REJECTED,
        kTokenResourceExceeded = CKR_TOKEN_RESOURCE_EXCEEDED,
        kOperationCancelFailed = CKR_OPERATION_CANCEL_FAILED,

        kVendorDefined = CKR_VENDOR_DEFINED,
    };

    export struct ErrorCategory final : std::error_category {
        [[nodiscard]] const char* name() const noexcept override;

        [[nodiscard]] std::string message(int condition) const override;
    };

    export constexpr ErrorCategory error_category{};
} // namespace pkcs11

namespace std {
    export template<>
    struct is_error_code_enum<pkcs11::Error> : std::true_type {
    };

    export std::error_code make_error_code(pkcs11::Error e);
} // namespace std

const char* pkcs11::ErrorCategory::name() const noexcept {
    return "pkcs11";
}

std::string pkcs11::ErrorCategory::message(const int condition) const {
    switch (static_cast<Error>(condition)) {
        ERROR_TO_STRING(Error::kCancel);
        ERROR_TO_STRING(Error::kHostMemory);
        ERROR_TO_STRING(Error::kSlotIdInvalid);

        ERROR_TO_STRING(Error::kGeneralError);
        ERROR_TO_STRING(Error::kFunctionFailed);

        ERROR_TO_STRING(Error::kArgumentsBad);
        ERROR_TO_STRING(Error::kNoEvent);
        ERROR_TO_STRING(Error::kNeedToCreateThreads);
        ERROR_TO_STRING(Error::kCantLock);

        ERROR_TO_STRING(Error::kAttributeReadOnly);
        ERROR_TO_STRING(Error::kAttributeSensitive);
        ERROR_TO_STRING(Error::kAttributeTypeInvalid);
        ERROR_TO_STRING(Error::kAttributeValueInvalid);

        ERROR_TO_STRING(Error::kActionProhibited);

        ERROR_TO_STRING(Error::kDataInvalid);
        ERROR_TO_STRING(Error::kDataLenRange);
        ERROR_TO_STRING(Error::kDeviceError);
        ERROR_TO_STRING(Error::kDeviceMemory);
        ERROR_TO_STRING(Error::kDeviceRemoved);
        ERROR_TO_STRING(Error::kEncryptedDataInvalid);
        ERROR_TO_STRING(Error::kEncryptedDataLenRange);
        ERROR_TO_STRING(Error::KAeadDecryptFailed);
        ERROR_TO_STRING(Error::kFunctionCanceled);
        ERROR_TO_STRING(Error::kFunctionNotParallel);

        ERROR_TO_STRING(Error::kFunctionNotSupported);

        ERROR_TO_STRING(Error::kKeyHandleInvalid);

        ERROR_TO_STRING(Error::kKeySizeRange);
        ERROR_TO_STRING(Error::kKeyTypeInconsistent);

        ERROR_TO_STRING(Error::kKeyNotNeeded);
        ERROR_TO_STRING(Error::kKeyChanged);
        ERROR_TO_STRING(Error::kKeyNeeded);
        ERROR_TO_STRING(Error::kKeyIndigestible);
        ERROR_TO_STRING(Error::kKeyFunctionNotPermitted);
        ERROR_TO_STRING(Error::kKeyNotWrappable);
        ERROR_TO_STRING(Error::kKeyUnextractable);

        ERROR_TO_STRING(Error::KMechanismInvalid);
        ERROR_TO_STRING(Error::kMechanismParamInvalid);

        ERROR_TO_STRING(Error::kObjectHandleInvalid);
        ERROR_TO_STRING(Error::kOperationActive);
        ERROR_TO_STRING(Error::kOperationNotInitialized);
        ERROR_TO_STRING(Error::kPinIncorrect);
        ERROR_TO_STRING(Error::kPinInvalid);
        ERROR_TO_STRING(Error::kPinLenRange);

        ERROR_TO_STRING(Error::kPinExpired);
        ERROR_TO_STRING(Error::kPinLocked);

        ERROR_TO_STRING(Error::kSessionClosed);
        ERROR_TO_STRING(Error::kSessionCount);
        ERROR_TO_STRING(Error::kSessionHandleInvalid);
        ERROR_TO_STRING(Error::kSessionParallelNotSupported);
        ERROR_TO_STRING(Error::kSessionReadOnly);
        ERROR_TO_STRING(Error::kSessionExists);

        ERROR_TO_STRING(Error::kSessionReadOnlyExists);
        ERROR_TO_STRING(Error::kSessionReadWriteSecurityOfficerExists);

        ERROR_TO_STRING(Error::kSignatureInvalid);
        ERROR_TO_STRING(Error::kSignatureLenRange);
        ERROR_TO_STRING(Error::kTemplateIncomplete);
        ERROR_TO_STRING(Error::kTemplateInconsistent);
        ERROR_TO_STRING(Error::kTokenNotPresent);
        ERROR_TO_STRING(Error::kTokenNotRecognized);
        ERROR_TO_STRING(Error::kTokenWriteProtected);
        ERROR_TO_STRING(Error::kUnwrappingKeyHandleInvalid);
        ERROR_TO_STRING(Error::kUnwrappingKeySizeRange);
        ERROR_TO_STRING(Error::kUnwrappingKeyTypeInconsistent);
        ERROR_TO_STRING(Error::kUserAlreadyLoggedIn);
        ERROR_TO_STRING(Error::kUserNotLoggedIn);
        ERROR_TO_STRING(Error::kUserPinNotInitialized);
        ERROR_TO_STRING(Error::kUserTypeInvalid);

        ERROR_TO_STRING(Error::kUserAnotherAlreadyLoggedIn);
        ERROR_TO_STRING(Error::kUserTooManyTypes);

        ERROR_TO_STRING(Error::kWrappedKeyInvalid);
        ERROR_TO_STRING(Error::kWrappedKeyLenRange);
        ERROR_TO_STRING(Error::kWrappingKeyHandleInvalid);
        ERROR_TO_STRING(Error::kWrappingKeySizeRange);
        ERROR_TO_STRING(Error::kWrappingKeyTypeInconsistent);
        ERROR_TO_STRING(Error::kRandomSeedNotSupported);

        ERROR_TO_STRING(Error::kRandomNoRng);

        ERROR_TO_STRING(Error::kDomainParamsInvalid);

        ERROR_TO_STRING(Error::kCurveNotSupported);

        ERROR_TO_STRING(Error::kBufferTooSmall);
        ERROR_TO_STRING(Error::kSavedStateInvalid);
        ERROR_TO_STRING(Error::kInformationSensitive);
        ERROR_TO_STRING(Error::kStateUnsaveable);

        ERROR_TO_STRING(Error::kCryptokiNotInitialized);
        ERROR_TO_STRING(Error::kCryptokiAlreadyInitialized);
        ERROR_TO_STRING(Error::kMutexBad);
        ERROR_TO_STRING(Error::kMutexNotLocked);

        ERROR_TO_STRING(Error::kNewPinMode);
        ERROR_TO_STRING(Error::kNextOtp);

        ERROR_TO_STRING(Error::kExceededMaxIterations);
        ERROR_TO_STRING(Error::kFipsSelfTestFailed);
        ERROR_TO_STRING(Error::kLibraryLoadFailed);
        ERROR_TO_STRING(Error::kPinTooWeak);
        ERROR_TO_STRING(Error::kPublicKeyInvalid);

        ERROR_TO_STRING(Error::kFunctionRejected);
        ERROR_TO_STRING(Error::kTokenResourceExceeded);
        ERROR_TO_STRING(Error::kOperationCancelFailed);

        ERROR_TO_STRING(Error::kVendorDefined);

        default:
            return "Unknown error";
    }
}

std::error_code std::make_error_code(const pkcs11::Error e) {
    return {static_cast<int>(e), pkcs11::error_category};
}
