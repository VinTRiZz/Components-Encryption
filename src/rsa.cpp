#include "rsa.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <algorithm>
#include <filesystem>

#include <Components/Filework/TemporaryFile.h>
#include <Components/ExtraClasses/DataFragmentator.h>

#include <iostream>

namespace Encryption
{

// Returns the maximum size of plaintext (in bytes) that can fit in a single chunk
static std::optional<size_t> getDataChunkLength(const RSAKeysPtr& key, int padding) {
    if (!key) { return std::nullopt; }

    int keySize = EVP_PKEY_get_size(key.get());
    if (keySize <= 0) { return std::nullopt; }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        // PKCS#1 v1.5 padding requires at least 11 bytes of overhead
        if (keySize <= 11) return std::nullopt;
        return static_cast<size_t>(keySize - 11);

    case RSA_NO_PADDING:
        // No padding: the entire modulus can be used
        return static_cast<size_t>(keySize);

    case RSA_PKCS1_OAEP_PADDING: {
        // Default OAEP hash in OpenSSL is SHA-1 (20 bytes)
        // If you explicitly set a different OAEP hash, adjust this value accordingly.
        const int sha1Size = 20;
        // OAEP overhead = 2 * hashLen + 2
        if (keySize <= 2 * sha1Size + 2) return std::nullopt;
        return static_cast<size_t>(keySize - 2 * sha1Size - 2);
    }
    }
    // Unsupported padding mode for encryption
    return std::nullopt;
}

RSAKeysPtr rsaGenerateKeys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        global_encryptionErrorText = "Failed to create EVP_PKEY_CTX";
        return {};
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        global_encryptionErrorText = "Failed to initialize keygen";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        global_encryptionErrorText = "Failed to set key length";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        global_encryptionErrorText = "Failed to generate key pair";
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return RSAKeysPtr(key, &EVP_PKEY_free);
}

bool rsaSavePublicKey(const RSAKeysPtr& pkey, const std::string& filename) {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        global_encryptionErrorText = std::string("[SAVEPUBK] ") + strerror(errno);
        return false;
    }

    auto writeByteCount = PEM_write_PUBKEY(fp, pkey.get());
    fclose(fp);
    if (writeByteCount == 0) {
        global_encryptionErrorText = std::string("[SAVEPUBK] ") + strerror(errno);
        return false;
    }
    return true;
}

bool rsaSavePrivateKey(const RSAKeysPtr& pkey, const std::string& filename, const std::string &passphrase)
{
    FILE* pkey_file = fopen(filename.c_str(), "wb");
    if (!pkey_file) {
        global_encryptionErrorText = std::string("[SAVEPK] ") + strerror(errno);
        return false;
    }

    // Save password NOT in legacy format
    int writeByteCount = PEM_write_PKCS8PrivateKey(
        pkey_file,
        pkey.get(),
        EVP_aes_256_cbc(),
        passphrase.c_str(),
        passphrase.size(),
        nullptr,
        nullptr
        );

    fclose(pkey_file);
    if (writeByteCount == 0) {
        global_encryptionErrorText = std::string("[SAVEPK] ") + strerror(errno);
        return false;
    }
    return true;
}


RSAKeysPtr rsaReadPublicKey(const std::string &filename) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        global_encryptionErrorText = std::string("[LOADPUBK] ") + strerror(errno);
        return nullptr;
    }
    auto pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        global_encryptionErrorText = std::string("[LOADPUBK] ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }
    return RSAKeysPtr(pkey, &EVP_PKEY_free);
}

RSAKeysPtr rsaReadPrivateKey(const std::string &filename, const std::string &passphrase) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        global_encryptionErrorText = std::string("[LOADPK] ") + strerror(errno);
        return nullptr;
    }
    // Pass passphrase if the key is encrypted
    auto pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)passphrase.data());
    fclose(fp);
    if (!pkey) {
        global_encryptionErrorText = std::string("[LOADPK] ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }
    return RSAKeysPtr(pkey, &EVP_PKEY_free);
}

std::optional<std::string> rsaEncryptString(const RSAKeysPtr& publicKey, const std::string &plaintext) {
    if (plaintext.empty()) {
        global_encryptionErrorText = "Empty text to encrypt";
        return {};
    }

    const auto paddingType = RSA_PKCS1_OAEP_PADDING;

    auto chunkLength = getDataChunkLength(publicKey, paddingType);
    if (!chunkLength) {
        global_encryptionErrorText = std::string("[ENCS-SZ] Failed to determine RSA chunk size: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }
    if (plaintext.size() > *chunkLength) {
        auto splittedData = ExtraClasses::DataInfo::split(plaintext, chunkLength.value());
        std::string resH;
        for (auto& pt : splittedData) {
            auto res = Encryption::rsaEncryptString(publicKey, pt);
            if (!res.has_value()) { return {}; }
            resH += *res;
        }
        return resH;
    }

    auto deleter = [](EVP_PKEY_CTX* ctx){
        if (nullptr != ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
    };
    std::unique_ptr<EVP_PKEY_CTX, decltype(deleter)> pCtx { EVP_PKEY_CTX_new(publicKey.get(), NULL), deleter };
    if (!pCtx || EVP_PKEY_encrypt_init(pCtx.get()) <= 0) {
        return {};
    }

    // Set padding - OAEP padding is recommended for new applications :cite[1]
    if (EVP_PKEY_CTX_set_rsa_padding(pCtx.get(), paddingType) <= 0) {
        return {};
    }

    // Determine buffer size
    size_t ciphertext_len {0};
    if (EVP_PKEY_encrypt(pCtx.get(),
                         NULL,
                         &ciphertext_len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.size()) <= 0) {
        return {};
    }

    // Perform encryption
    std::string result;
    result.resize(ciphertext_len);
    if (EVP_PKEY_encrypt(
                pCtx.get(),
                reinterpret_cast<unsigned char*>(result.data()),
                &ciphertext_len,
                reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                plaintext.size()) <= 0) {
        return {};
    }
    return result;
}

std::optional<std::string> rsaDecryptString(const RSAKeysPtr& privateKey, const std::string &ciphertext) {
    if (ciphertext.empty()) {
        global_encryptionErrorText = "Empty text to encrypt";
        return {};
    }

    const auto paddingType = RSA_PKCS1_OAEP_PADDING;

    // 256 is RSA chunk size
    if (ciphertext.size() > 256) {
        auto splittedData = ExtraClasses::DataInfo::split(ciphertext, 256);
        std::string res;
        for (auto& pt : splittedData) {
            auto decPt = Encryption::rsaDecryptString(privateKey, pt);
            if (!decPt.has_value()) {
                return {};
            }
            res += *decPt;
        }
        return res;
    }

    auto deleter = [](EVP_PKEY_CTX* ctx){
        if (nullptr != ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
    };
    std::unique_ptr<EVP_PKEY_CTX, decltype(deleter)> pCtx { EVP_PKEY_CTX_new(privateKey.get(), NULL), deleter };
    if (!pCtx || EVP_PKEY_decrypt_init(pCtx.get()) <= 0) {
        return {};
    }

    // Set padding - MUST match the padding used during encryption
    if (EVP_PKEY_CTX_set_rsa_padding(pCtx.get(), paddingType) <= 0) {
        return {};
    }

    // Determine buffer size
    size_t plaintext_len {0};
    if (EVP_PKEY_decrypt(
                pCtx.get(),
                NULL,
                &plaintext_len,
                reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                ciphertext.size()) <= 0) {
        return {};
    }

    // Perform decryption
    std::string result;
    result.resize(plaintext_len);
    if (EVP_PKEY_decrypt(
                pCtx.get(),
                reinterpret_cast<unsigned char*>(result.data()),
                &plaintext_len,
                reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                ciphertext.size()) <= 0) {
        return {};
    }

    result.resize(plaintext_len); // Adjust to the actual decrypted size
    return result;
}

std::string rsaKeyToString(const RSAKeysPtr& pubKey)
{
    BIO *bio = BIO_new(BIO_s_mem()); // Create a memory BIO
    char *pem_string = NULL;

    std::string res;
    if (PEM_write_bio_PUBKEY(bio, pubKey.get())) {
        long pem_length = BIO_get_mem_data(bio, &pem_string);
        res.reserve(pem_length);
        std::copy(pem_string, pem_string + pem_length, std::back_inserter(res));
    } else {
        global_encryptionErrorText = std::string("[TOSTR] ") + ERR_error_string(ERR_get_error(), nullptr);
    }

    BIO_free(bio);
    return res;
}

RSAKeysPtr rsaKeyFromString(const std::string& pubKey) {
    BIO* bio = BIO_new_mem_buf(pubKey.data(), static_cast<int>(pubKey.size()));
    if (!bio) {
        global_encryptionErrorText = std::string("[FROMSTR] ") + ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    auto pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        global_encryptionErrorText = std::string("[FROMSTR] ") + ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        global_encryptionErrorText = std::string("[FROMSTR] ") + ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }
    return RSAKeysPtr(pkey, &EVP_PKEY_free);
}

bool rsaEncryptFile(const std::string &targetFile, const RSAKeysPtr &pubkey)
{    
    std::ifstream inputFile(targetFile, std::ios::binary);
    if (!inputFile) {
        global_encryptionErrorText = std::string("Failed to open target file: ") + strerror(errno);
        return false;
    }
    Filework::TemporaryFile tmpFile(targetFile, false);

    const auto BUFF_SIZE {9128}; // Idk what value is best
    char buffer [BUFF_SIZE];
    while (inputFile) {
        auto readCnt = inputFile.readsome(buffer, BUFF_SIZE);
        if (readCnt <= 0) { break; }
        auto encData = rsaEncryptString(pubkey, std::string(buffer, readCnt));
        if (!encData.has_value()) { return false; }
        tmpFile.write(encData->c_str(), encData->size());
        tmpFile.flush();
    }

    if (inputFile.bad()) {
        global_encryptionErrorText = "I/O error while reading file";
        return false;
    }

    tmpFile.accept();
    return true;
}

bool rsaEncryptFile(const std::string &targetFile, const std::string &pubkeyPath)
{
    if (!std::filesystem::exists(targetFile)) {
        global_encryptionErrorText = "Invalid file";
        return false;
    }
    auto rsaPublicKey = rsaReadPublicKey(pubkeyPath);
    if (NULL == rsaPublicKey) {
        global_encryptionErrorText = "Failed to load public key";
        return false;
    }
    return rsaEncryptFile(targetFile, rsaPublicKey);
}

bool rsaDecryptFile(const std::string &targetFile, const RSAKeysPtr &privkey)
{
    std::ifstream inputFile(targetFile, std::ios::binary);
    if (!inputFile) {
        global_encryptionErrorText = std::string("Failed to open target file: ") + strerror(errno);
        return false;
    }
    Filework::TemporaryFile tmpFile(targetFile, false);

    const auto BUFF_SIZE {10240}; // Idk what value is best
    char buffer [BUFF_SIZE];
    while (inputFile) {
        auto readCnt = inputFile.readsome(buffer, BUFF_SIZE);
        if (readCnt <= 0) { break; }
        auto encData = rsaDecryptString(privkey, std::string(buffer, readCnt));
        if (!encData.has_value()) { return false; }
        tmpFile.write(encData->c_str(), encData->size());
        tmpFile.flush();
    }

    if (inputFile.bad()) {
        global_encryptionErrorText = "I/O error while reading file";
        return false;
    }

    tmpFile.accept();
    return true;
}

bool rsaDecryptFile(const std::string &targetFile, const std::string &privkeyPath, const std::string &pass)
{
    if (!std::filesystem::exists(targetFile)) {
        global_encryptionErrorText = "Invalid file";
        return false;
    }
    auto rsaPublicKey = rsaReadPrivateKey(privkeyPath, pass);
    if (NULL == rsaPublicKey) {
        global_encryptionErrorText = "Failed to load public key";
        return false;
    }
    return rsaDecryptFile(targetFile, rsaPublicKey);
}

}
