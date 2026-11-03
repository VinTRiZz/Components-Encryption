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
    Filework::TemporaryFile privFreeTmp;
    ASSERT_TRUE(Encryption::rsaSaveKey(key, std::string(privFreeTmp.getFilename()), false));
    ASSERT_TRUE(std::filesystem::exists(privFreeTmp.getFilename()) &&
                std::filesystem::file_size(privFreeTmp.getFilename()) != 0);

    // Encrypted save test
    const std::string encryptionPassphrase = Encryption::generateSymbols(100);
    Filework::TemporaryFile privEncrTmp;
    ASSERT_TRUE(Encryption::rsaSaveKey(key, std::string(privEncrTmp.getFilename()), false, encryptionPassphrase));
    ASSERT_TRUE(std::filesystem::exists(privEncrTmp.getFilename()) &&
                std::filesystem::file_size(privEncrTmp.getFilename()) != 0);

    // Check encryption is invalid
    std::string keyData;
    ASSERT_TRUE(Filework::Common::readFileData(std::string(privFreeTmp.getFilename()), keyData));
    std::string encKeyData;
    ASSERT_TRUE(Filework::Common::readFileData(std::string(privEncrTmp.getFilename()), encKeyData));
    ASSERT_NE(keyData, encKeyData);

    // Public save test
    Filework::TemporaryFile pubTmp;
    ASSERT_TRUE(Encryption::rsaSaveKey(key, std::string(pubTmp.getFilename())));
    ASSERT_TRUE(std::filesystem::exists(privFreeTmp.getFilename()) &&
                std::filesystem::file_size(privFreeTmp.getFilename()) != 0);

    // Reading keys
    auto pubKey = Encryption::rsaReadKey(std::string(pubTmp.getFilename()));
    ASSERT_NE(pubKey, nullptr);

    auto privKey = Encryption::rsaReadKey(std::string(privFreeTmp.getFilename()), false);
    ASSERT_NE(privKey, nullptr);

    auto privEncKey = Encryption::rsaReadKey(std::string(privEncrTmp.getFilename()), false, encryptionPassphrase);
    ASSERT_NE(privEncKey, nullptr);

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

    const std::string path(srcFile.getFilename());

    // Encrypt file data
    ASSERT_TRUE(Encryption::rsaEncryptFile(path, key)) << "ERROR TEXT: " << Encryption::getEncryptionErrorText();

    // Read what encrypted
    std::string encryptedData;
    ASSERT_TRUE(Filework::Common::readFileData(path, encryptedData));
    ASSERT_GT(encryptedData.size(), testData.size()); // Must be 256*N, more that source
    ASSERT_NE(testData, encryptedData);

    // Check encrypting of file
    ASSERT_TRUE(Encryption::rsaDecryptFile(path, key)) << "ERROR TEXT: " << Encryption::getEncryptionErrorText();

    // Read what decrypted
    std::string decryptedData;
    ASSERT_TRUE(Filework::Common::readFileData(path, decryptedData));
    ASSERT_EQ(testData, decryptedData);
}


TEST(Components_Encryption, RSA_FileHybridEncrypt) {
    auto key = Encryption::rsaGenerateKeys();
    auto aesKey = Encryption::generateBytes(32);

    std::string testData;
    const auto BUFF_SIZE = 7641; // Must be enough for test
    testData = Encryption::generateBytes(BUFF_SIZE);

    Filework::TemporaryFile srcFile;
    srcFile.write(testData.c_str(), testData.size());
    srcFile.flush();
    srcFile.accept();

    const std::string path(srcFile.getFilename());

    // Encrypt file data
    ASSERT_TRUE(Encryption::rsaHybridEncryptFile(path, aesKey, key)) << "ERROR TEXT: " << Encryption::getEncryptionErrorText();

    // Read what encrypted
    std::string encryptedData;
    ASSERT_TRUE(Filework::Common::readFileData(path, encryptedData));
    ASSERT_GT(encryptedData.size(), testData.size()); // Must be 256*N, more that source
    ASSERT_NE(testData, encryptedData);

    ASSERT_FALSE(Encryption::rsaHybridDecryptFile(path, Encryption::generateBytes(32), key).isOk());
    std::string stillEncrypted;
    ASSERT_TRUE(Filework::Common::readFileData(path, stillEncrypted));
    ASSERT_EQ(encryptedData, stillEncrypted);

    // Check encrypting of file
    ASSERT_TRUE(Encryption::rsaHybridDecryptFile(path, aesKey, key)) << "ERROR TEXT: " << Encryption::getEncryptionErrorText();

    // Read what decrypted
    std::string decryptedData;
    ASSERT_TRUE(Filework::Common::readFileData(path, decryptedData));
    ASSERT_EQ(testData, decryptedData);
}

#endif // COMPONENTS_SW_encryption_rsa
