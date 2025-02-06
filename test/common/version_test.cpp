#include <gtest/gtest.h>

#pragma pack(push, cryptoki, 1)

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) \
returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
returnType (* name)

#include <pkcs11/pkcs11t.h>

#pragma pack(pop, cryptoki)

import pkcs11;

TEST(Version, Major) {
    constexpr CK_VERSION ck_version{.major = 1, .minor = 23};
    const pkcs11::Version version{ck_version};
    EXPECT_EQ(version.Major(), ck_version.major);
}

TEST(Version, Minor) {
    constexpr CK_VERSION ck_version{.major = 1, .minor = 23};
    const pkcs11::Version version{ck_version};
    EXPECT_EQ(version.Minor(), ck_version.minor);
}

TEST(Version, ToString) {
    constexpr CK_VERSION ck_version{.major = 1, .minor = 23};
    const pkcs11::Version version{ck_version};
    EXPECT_EQ(version.ToString(), "1.23");
}
