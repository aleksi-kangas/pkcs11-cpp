#include <gtest/gtest.h>

#include <core/core.h>

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
