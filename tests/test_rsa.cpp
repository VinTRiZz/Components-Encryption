#include <gtest/gtest.h>

#include <Components/Encryption/RSA.h>
#include <Components/Filework/Common.h>
#include <Components/Filework/TemporaryFile.h>

#include <filesystem>
#include <algorithm>
#include <cstddef>
#include <random>
#include <string>

#include <openssl/pem.h>

namespace {

std::string randomBytes(std::size_t len) {
    static std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, 255);
    std::string s(len, '\0');
    std::generate(s.begin(), s.end(),
                  [&] { return static_cast<char>(dist(rng)); });
    return s;
}

}

TEST(Encryption, RSA_Init) {
    auto key = Encryption::rsaGenerateKeys();
    ASSERT_NE(key, nullptr);
}

TEST(Encryption, RSA_StringSizes) {
    auto key = Encryption::rsaGenerateKeys();

    // Small strings
    auto sample = randomBytes(5);
    auto encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    auto decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Zero strings
    encStr = Encryption::rsaEncryptString(key, {});
    ASSERT_FALSE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, {});
    ASSERT_FALSE(encStr.has_value());

    // Regular strings
    sample = randomBytes(79);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Chunk-size strings
    sample = randomBytes(256);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Big unaligned strings
    sample = randomBytes(1733);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Big strings
    sample = randomBytes(2048);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);
}

TEST(Encryption, RSA_KeySaveRestore) {
    auto key = Encryption::rsaGenerateKeys();

    // Regular save test
    auto testPrivKeyFile = std::filesystem::temp_directory_path() / "enctest_privkey.pem";
    ASSERT_TRUE(Encryption::rsaSavePrivateKey(key, testPrivKeyFile));
    ASSERT_TRUE(std::filesystem::exists(testPrivKeyFile) &&
                std::filesystem::file_size(testPrivKeyFile) != 0);

    // Encrypted save test
    const std::string encryptionPassphrase = "example password to be sure";
    auto testPrivEncKeyFile = std::filesystem::temp_directory_path() / "enctest_privkey_enc.pem";
    ASSERT_TRUE(Encryption::rsaSavePrivateKey(key, testPrivEncKeyFile, encryptionPassphrase));
    ASSERT_TRUE(std::filesystem::exists(testPrivEncKeyFile) &&
                std::filesystem::file_size(testPrivEncKeyFile) != 0);

    // Check encryption is invalid
    std::string keyData;
    ASSERT_TRUE(Filework::Common::readFileData(testPrivKeyFile, keyData));
    std::string encKeyData;
    ASSERT_TRUE(Filework::Common::readFileData(testPrivEncKeyFile, encKeyData));
    ASSERT_NE(keyData, encKeyData);

    // Public save test
    auto testPubKeyFile = std::filesystem::temp_directory_path() / "enctest_pubkey.pem";
    ASSERT_TRUE(Encryption::rsaSavePublicKey(key, testPubKeyFile));
    ASSERT_TRUE(std::filesystem::exists(testPrivKeyFile) &&
                std::filesystem::file_size(testPrivKeyFile) != 0);

    // Reading keys
    auto pubKey = Encryption::rsaReadPublicKey(testPubKeyFile);
    ASSERT_NE(pubKey, nullptr);
    std::filesystem::remove(testPubKeyFile);

    auto privKey = Encryption::rsaReadPrivateKey(testPrivKeyFile);
    ASSERT_NE(privKey, nullptr);
    std::filesystem::remove(testPrivKeyFile);

    auto privEncKey = Encryption::rsaReadPrivateKey(testPrivEncKeyFile, encryptionPassphrase);
    ASSERT_NE(privEncKey, nullptr);
    std::filesystem::remove(testPrivEncKeyFile);

    // Check if read keys are correct
    ASSERT_TRUE(EVP_PKEY_eq(key.get(), privKey.get())) << "Loaded private key is invalid";
    ASSERT_TRUE(EVP_PKEY_eq(pubKey.get(), privKey.get())) << "Loaded public key is invalid";
    ASSERT_TRUE(EVP_PKEY_eq(key.get(), privEncKey.get())) << "Loaded encrypted key is invalid";
}

TEST(Encryption, RSA_FileEncrypt) {
    auto key = Encryption::rsaGenerateKeys();

    const auto testFileSource = std::filesystem::temp_directory_path() / "enctest_samplefile_source.bin";
    std::string testData;
    testData = randomBytes(76411); // Must be enough for test
    {
        std::ofstream srcFile(testFileSource, std::ios_base::out | std::ios_base::trunc);
        srcFile << testData;
        srcFile.flush();
    }

    { // Check if data really written
        std::string tmpd;
        ASSERT_TRUE(Filework::Common::readFileData(testFileSource, tmpd));
        ASSERT_FALSE(tmpd.empty());
        ASSERT_EQ(testData, tmpd);
    }

    // Create file to work with
    const auto testFile = std::filesystem::temp_directory_path() / "enctest_samplefile.bin";
    if (std::filesystem::exists(testFile)) {
        // remove existing one (only for correct test)
        std::filesystem::remove(testFile);
    }
    std::filesystem::copy_file(testFileSource, testFile);

    // Check encrypting of file
    ASSERT_TRUE(Encryption::rsaEncryptFile(testFile, key));
    {
        std::string tmpd;
        ASSERT_TRUE(Filework::Common::readFileData(testFile, tmpd));
        ASSERT_FALSE(tmpd.empty());
        ASSERT_NE(testData, tmpd);
    }

    // Check encrypting of file
    ASSERT_TRUE(Encryption::rsaDecryptFile(testFile, key));
    {
        std::string tmpd;
        ASSERT_TRUE(Filework::Common::readFileData(testFile, tmpd));
        ASSERT_FALSE(tmpd.empty());
        ASSERT_EQ(testData, tmpd);
    }
}
