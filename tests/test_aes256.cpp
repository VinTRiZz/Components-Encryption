#include <gtest/gtest.h>

#include <Components/Encryption/AES-256.h>
#include <Components/Filework/Common.h>
#include <Components/Filework/TemporaryFile.h>

#include <string>
#include <vector>

namespace {

constexpr std::size_t AES_GCM_OVERHEAD = 12 + 16;

void writeFile(Filework::TemporaryFile& file, const std::string& data) {
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    file.flush();
}

std::string readFile(const std::string& path) {
    std::string result;
    const auto readResult = Filework::Common::readFileData(path, result);
    EXPECT_TRUE(readResult.isOk()) << readResult.getDetailText();
    return result;
}

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
    ASSERT_TRUE(encStr.has_value()) << Encryption::getEncryptionErrorText();
    auto decStr = Encryption::aes256_gcm_decrypt(encStr.value(), key);
    ASSERT_TRUE(decStr.has_value()) << Encryption::getEncryptionErrorText();

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

TEST(Components_Encryption, AES256_GCM_FileRoundTrip) {
    const auto key = Encryption::generateBytes(32);
    const std::vector<std::size_t> sizes {
        0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 8191, 8192, 8193, 16384
    };

    for (const auto size : sizes) {
        const auto sample = Encryption::generateBytes(size);
        Filework::TemporaryFile file;
        writeFile(file, sample);
        const std::string path(file.getFilename());

        const auto encryptResult = Encryption::aes256_gcm_encryptFile(path, key);
        ASSERT_TRUE(encryptResult.isOk())
            << "Size: " << size << ", error: " << Encryption::getEncryptionErrorText();

        const auto encrypted = readFile(path);
        EXPECT_NE(sample, encrypted);
        EXPECT_EQ(sample.size() + AES_GCM_OVERHEAD, encrypted.size());

        const auto decryptResult = Encryption::aes256_gcm_decryptFile(path, key);
        ASSERT_TRUE(decryptResult.isOk())
            << "Size: " << size << ", error: " << Encryption::getEncryptionErrorText();

        const auto restored = readFile(path);
        EXPECT_EQ(sample, restored) << "Size: " << size;
    }
}

TEST(Components_Encryption, AES256_GCM_FileWithAAD) {
    const auto key = Encryption::generateBytes(32);
    const std::string aad = Encryption::generateBytes(64);
    const std::string sample = Encryption::generateBytes(4096);

    Filework::TemporaryFile file;
    writeFile(file, sample);
    const std::string path(file.getFilename());

    ASSERT_TRUE(Encryption::aes256_gcm_encryptFile(path, key, aad).isOk())
        << Encryption::getEncryptionErrorText();

    ASSERT_FALSE(Encryption::aes256_gcm_decryptFile(path, key, "wrong AAD").isOk());
    EXPECT_NE(sample, readFile(path));

    ASSERT_TRUE(Encryption::aes256_gcm_decryptFile(path, key, aad).isOk())
        << Encryption::getEncryptionErrorText();
    EXPECT_EQ(sample, readFile(path));
}

TEST(Components_Encryption, AES256_GCM_FileInvalidInput) {
    const auto key = Encryption::generateBytes(32);
    const std::string sample = Encryption::generateBytes(1024);

    Filework::TemporaryFile file;
    writeFile(file, sample);
    const std::string path(file.getFilename());

    EXPECT_FALSE(Encryption::aes256_gcm_encryptFile(path, Encryption::generateBytes(31)).isOk());
    EXPECT_EQ(sample, readFile(path));

    ASSERT_TRUE(Encryption::aes256_gcm_encryptFile(path, key).isOk())
        << Encryption::getEncryptionErrorText();

    const auto encrypted = readFile(path);
    EXPECT_FALSE(Encryption::aes256_gcm_decryptFile(path, Encryption::generateBytes(32)).isOk());
    EXPECT_EQ(encrypted, readFile(path));

    EXPECT_FALSE(Encryption::aes256_gcm_encryptFile("nonexistent_file_for_aes_gcm_test.bin", key).isOk());
    EXPECT_FALSE(Encryption::aes256_gcm_decryptFile("nonexistent_file_for_aes_gcm_test.bin", key).isOk());
}
