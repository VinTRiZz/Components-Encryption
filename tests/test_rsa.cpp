#include <gtest/gtest.h>

#ifdef COMPONENTS_SW_encryption_rsa

#include <Components/Encryption/RSA.h>
#include <Components/Filework/Common.h>
#include <Components/Filework/TemporaryFile.h>

#include <filesystem>
#include <string>

#include <openssl/pem.h>

TEST(Components_Encryption, RSA_Init) {
    auto key = Encryption::rsaGenerateKeys();
    ASSERT_NE(key, nullptr);
}

TEST(Components_Encryption, RSA_StringSizes) {
    auto key = Encryption::rsaGenerateKeys();

    // Small strings
    auto sample = Encryption::generateBytes(5);
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
    sample = Encryption::generateBytes(79);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Chunk-size strings
    sample = Encryption::generateBytes(256);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Big unaligned strings
    sample = Encryption::generateBytes(1733);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);

    // Big strings
    sample = Encryption::generateBytes(2048);
    encStr = Encryption::rsaEncryptString(key, sample);
    ASSERT_TRUE(encStr.has_value());
    decStr = Encryption::rsaDecryptString(key, *encStr);
    ASSERT_FALSE(encStr->empty());
    ASSERT_NE(sample, encStr);
    ASSERT_EQ(sample, decStr);
}

TEST(Components_Encryption, RSA_KeySaveRestore) {
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

TEST(Components_Encryption, RSA_FileEncrypt) {
    auto key = Encryption::rsaGenerateKeys();

    std::string testData;
    const auto BUFF_SIZE = 7641; // Must be enough for test
    testData = Encryption::generateBytes(BUFF_SIZE);

    Filework::TemporaryFile srcFile;
    srcFile.write(testData.c_str(), testData.size());
    srcFile.flush();
    srcFile.accept();

    // Encrypt file data
    ASSERT_TRUE(Encryption::rsaEncryptFile(std::string(srcFile.getFilename()), key)) << "ERROR TEXT: " << Encryption::getEncryptionErrorText();

    // Read what encrypted
    char readBuffer[BUFF_SIZE * 2];
    srcFile.seekg(0, std::ios_base::beg);
    std::fill_n(readBuffer, BUFF_SIZE * 2, '\0');
    auto readCnt = srcFile.readsome(readBuffer, BUFF_SIZE * 2);
    ASSERT_GT(readCnt, BUFF_SIZE); // Must be 256*N, more that source
    ASSERT_NE(testData, readBuffer);

    // Check encrypting of file
    ASSERT_TRUE(Encryption::rsaDecryptFile(std::string(srcFile.getFilename()), key)) << "ERROR TEXT: " << Encryption::getEncryptionErrorText();

    // Read what decrypted
    readCnt = 0;
    srcFile.seekg(0, std::ios_base::beg);
    std::fill_n(readBuffer, BUFF_SIZE * 2, '\0');
    readCnt = srcFile.readsome(readBuffer, BUFF_SIZE * 2);
    ASSERT_EQ(BUFF_SIZE, readCnt); // Must be equal with source size
    ASSERT_EQ(testData, std::string(readBuffer, readCnt));
}

#endif // COMPONENTS_SW_encryption_rsa
