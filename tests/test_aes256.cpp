#include <gtest/gtest.h>

#include <Components/Encryption/AES-256.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <random>
#include <string>

#ifdef QT_CORE_LIB
#include <QByteArray>
#endif

namespace {

std::string randomBytes(std::size_t len) {
    static std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, 255);
    std::string s(len, '\0');
    std::generate(s.begin(), s.end(),
                  [&] { return static_cast<char>(dist(rng)); });
    return s;
}

// TODO: Check if work
#ifdef QT_CORE_LIB
QString qtRandomBytes(std::size_t len) {
    static std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, 255);
    std::string s(len, '\0');
    std::generate(s.begin(), s.end(),
                  [&] { return static_cast<char>(dist(rng)); });
    return s;
}
#endif // QT_CORE_LIB

}

TEST(Encryption, AES256_Init) {
    auto key = Encryption::generateKey(32);
    ASSERT_NE(key, Encryption::generateKey(32)) << "Key creates dublicates";

    key = Encryption::generateKey(10);
    auto trimmedKey = Encryption::fixKey(key);
    ASSERT_NE(key, trimmedKey) << "Small key trim failed";
    ASSERT_EQ(trimmedKey.size(), 32);

    key = Encryption::generateKey(32);
    trimmedKey = Encryption::fixKey(key);
    ASSERT_EQ(key, trimmedKey) << "Same size key trim failed";
    ASSERT_EQ(trimmedKey.size(), 32);

    key = Encryption::generateKey(4096);
    trimmedKey = Encryption::fixKey(key);
    ASSERT_NE(key, trimmedKey) << "Huge key trim failed";
    ASSERT_EQ(trimmedKey.size(), 32);
}

TEST(Encryption, AES256_StringSizes) {
    auto key = Encryption::generateKey(32);

    // Small strings
    auto sample = randomBytes(5);
    auto encStr = Encryption::aes256encrypt(sample, key);
    auto decStr = Encryption::aes256decrypt(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Zero strings
    sample = {};
    encStr = Encryption::aes256encrypt(sample, key);
    decStr = Encryption::aes256decrypt(encStr, key);
    ASSERT_TRUE(encStr.empty());
    ASSERT_EQ(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Regular strings
    sample = randomBytes(27);
    encStr = Encryption::aes256encrypt(sample, key);
    decStr = Encryption::aes256decrypt(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Key-size strings
    sample = randomBytes(32);
    encStr = Encryption::aes256encrypt(sample, key);
    decStr = Encryption::aes256decrypt(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Big strings
    sample = randomBytes(2048);
    encStr = Encryption::aes256encrypt(sample, key);
    decStr = Encryption::aes256decrypt(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);
}

#ifdef QT_CORE_LIB
TEST(Encryption, AES256_StringSizes) {
    auto key = Encryption::generateKey(32);

    // Small strings
    auto sample = qtRandomBytes(5);
    auto encStr = Encryption::qtEncryptAes256Cbc(sample, key);
    auto decStr = Encryption::qtEncryptAes256Cbc(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Zero strings
    sample = {};
    encStr = Encryption::qtEncryptAes256Cbc(sample, key);
    decStr = Encryption::qtEncryptAes256Cbc(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Regular strings
    sample = qtRandomBytes(27);
    encStr = Encryption::qtEncryptAes256Cbc(sample, key);
    decStr = Encryption::qtEncryptAes256Cbc(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Key-size strings
    sample = qtRandomBytes(32);
    encStr = Encryption::qtEncryptAes256Cbc(sample, key);
    decStr = Encryption::qtEncryptAes256Cbc(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Big strings
    sample = qtRandomBytes(2048);
    encStr = Encryption::qtEncryptAes256Cbc(sample, key);
    decStr = Encryption::qtEncryptAes256Cbc(encStr, key);
    ASSERT_FALSE(encStr.empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);
}
#endif // QT_CORE_LIB