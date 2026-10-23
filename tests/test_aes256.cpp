#include <gtest/gtest.h>

#include <Components/Encryption/AES-256.h>

#include <string>

namespace {

void checkStringCBC(const std::string& sample, const std::string& key) {
    auto encStr = Encryption::aes256_cbc_encrypt(sample, key);
    ASSERT_TRUE(encStr.has_value());

    auto decStr = Encryption::aes256_cbc_decrypt(encStr.value(), key);
    ASSERT_TRUE(encStr.has_value());

    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);
}

void checkStringGCM(const std::string& sample, const std::string& key) {
    auto encStr = Encryption::aes256_gcm_encrypt(sample, key);
    ASSERT_TRUE(encStr.has_value());
    auto decStr = Encryption::aes256_gcm_decrypt(encStr.value(), key);
    ASSERT_TRUE(encStr.has_value());

    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    auto invalidDecStr = Encryption::aes256_gcm_decrypt(encStr.value(), key, Encryption::generateBytes(29));
    ASSERT_FALSE(invalidDecStr.has_value());

    // ======================== //

    const std::string aad {Encryption::generateBytes(163)};
    encStr = Encryption::aes256_gcm_encrypt(sample, key, aad);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::aes256_gcm_decrypt(encStr.value(), key, aad);
    ASSERT_TRUE(encStr.has_value());

    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    invalidDecStr = Encryption::aes256_gcm_decrypt(encStr.value(), key, Encryption::generateBytes(29));
    ASSERT_FALSE(invalidDecStr.has_value());
}

}

// ============================================== //

TEST(Components_Encryption, AES256_KeySetup) {
    auto key = Encryption::generateBytes(32);
    ASSERT_NE(key, Encryption::generateBytes(32)) << "Key creates dublicates";

    key = Encryption::generateBytes(10);
    Encryption::aes256_fixKeySize(key);
    ASSERT_EQ(key.size(), 32);

    key = Encryption::generateBytes(32);
    Encryption::aes256_fixKeySize(key);
    ASSERT_EQ(key, key) << "Same size key trim failed";
    ASSERT_EQ(key.size(), 32);

    key = Encryption::generateBytes(4096);
    Encryption::aes256_fixKeySize(key);
    ASSERT_EQ(key.size(), 32);
}

TEST(Components_Encryption, AES256_CBC_StringSizes) {
    auto key = Encryption::generateBytes(32);

    checkStringCBC(Encryption::generateBytes(21), key);
    checkStringCBC(Encryption::generateBytes(32), key);
    checkStringCBC(Encryption::generateBytes(231), key);
    checkStringCBC(Encryption::generateBytes(1931), key);
}

TEST(Components_Encryption, AES256_GCM_StringSizes) {
    auto key = Encryption::generateBytes(32);

    checkStringGCM(Encryption::generateBytes(21), key);
    checkStringGCM(Encryption::generateBytes(32), key);
    checkStringGCM(Encryption::generateBytes(231), key);
    checkStringGCM(Encryption::generateBytes(1931), key);
}
