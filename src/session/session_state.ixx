module;

#include <cstdint>

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:session_state;

namespace pkcs11 {
    /**
     * Holds the session state.
     *
     * Access to different types of objects by different types of sessions:
     * |---------------------------------------------------------------------------------|
     * |                        |                   Type of Session                      |
     * |                        |--------------------------------------------------------|
     * |     Type of Object     | R/O Public | R/W Public | R/O User | R/W User | R/W SO |
     * |------------------------|------------|------------|----------|----------|--------|
     * | Public Session Object  | R/W        | R/W        | R/W      | R/W      | R/W    |
     * | Private Session Object |            |            | R/W      | R/W      |        |
     * | Public Token Object    | R/O        | R/W        | R/O      | R/W      | R/W    |
     * | Private Token Object   |            |            | R/O      | R/W      |        |
     * |------------------------|------------|------------|----------|----------|--------|
     */
    export enum class SessionState final : std::uint32_t {
        /**
         * The application has opened a read-only session.
         * The application has read-only access to public token objects and read/write access to public session objects.
         */
        kReadOnlyPublicSession = CKS_RO_PUBLIC_SESSION,
        /**
         * The normal user has been authenticated to the token.
         * The application has read-only access to all token objects (public or private) and read/write access to all session objects (public or private).
         */
        kReadOnlyUserFunctions = CKS_RO_USER_FUNCTIONS,
        /**
         * The application has opened a read/write session.
         * The application has read/write access to all public objects.
         */
        kReadWritePublicSession = CKS_RW_PUBLIC_SESSION,
        /**
         * The normal user has been authenticated to the token.
         * The application has read/write access to all objects.
         */
        kReadWriteUserFunctions = CKS_RW_USER_FUNCTIONS,
        /**
         * The Security Officer (SO) has been authenticated to the token.
         * The application has read/write access only to public objects on the token, not to private objects.
         * The SO can set the normal user’s PIN.
         */
        kReadWriteSecurityOfficerFunctions = CKS_RW_SO_FUNCTIONS,
    };
} // namespace pkcs11
