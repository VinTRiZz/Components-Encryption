#include "rsa.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <algorithm>
#include <fstream>
#include <vector>

#include <Components/Filework/Common.h>
#include "encoding.hpp"

namespace Encryption
{

EVP_PKEY *rsaGenerateKeys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        global_encryptionErrorText = "Failed to create EVP_PKEY_CTX";
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        global_encryptionErrorText = "Failed to initialize keygen";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        global_encryptionErrorText = "Failed to set key length";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        global_encryptionErrorText = "Failed to generate key pair";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

bool rsaSavePublicKey(EVP_PKEY *pkey, const std::string& filename) {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        global_encryptionErrorText = std::string("[SAVEPUBK] ") + strerror(errno);
        return false;
    }

    auto writeByteCount = PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    if (writeByteCount == 0) {
        global_encryptionErrorText = std::string("[SAVEPUBK] ") + strerror(errno);
        return false;
    }
    return true;
}

bool rsaSavePrivateKey(EVP_PKEY *pkey, const std::string& filename)
{
    FILE* pkey_file = fopen(filename.c_str(), "wb");
    if (!pkey_file) {
        global_encryptionErrorText = std::string("[SAVEPK] ") + strerror(errno);
        return false;
    }

    auto writeByteCount = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);
    if (writeByteCount == 0) {
        global_encryptionErrorText = std::string("[SAVEPK] ") + strerror(errno);
        return false;
    }
    return true;
}


EVP_PKEY *rsaReadPublicKey(const std::string &filename) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        global_encryptionErrorText = std::string("[LOADPUBK] ") + strerror(errno);
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

EVP_PKEY *rsaReadPrivateKey(const std::string &filename, const std::string &passphrase) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        global_encryptionErrorText = std::string("[LOADPK] ") + strerror(errno);
        return nullptr;
    }
    // Pass passphrase if the key is encrypted
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)passphrase.c_str());
    fclose(fp);
    return pkey;
}


std::optional<std::string> rsaEncryptString(EVP_PKEY *publicKey, const std::string &plaintext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        global_encryptionErrorText = std::string("[ENCS-I] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Set padding - OAEP padding is recommended for new applications :cite[1]
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        global_encryptionErrorText = std::string("[ENCS-P] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Determine buffer size
    size_t ciphertext_len {0};
    if (EVP_PKEY_encrypt(ctx,
                         NULL,
                         &ciphertext_len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.size()) <= 0) {
        global_encryptionErrorText = std::string("[ENCS-BS] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Perform encryption
    std::string result;
    result.resize(ciphertext_len);
    if (EVP_PKEY_encrypt(
                ctx,
                reinterpret_cast<unsigned char*>(result.data()),
                &ciphertext_len,
                reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                plaintext.size()) <= 0) {
        global_encryptionErrorText = std::string("[ENCS-D] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    if (result.size() % 256) {
        std::fill_n(std::back_inserter(result), result.size() % 256, 0x0);
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

std::optional<std::string> rsaDecryptString(EVP_PKEY *privateKey, const std::string &ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        global_encryptionErrorText = std::string("[DECS-I] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Set padding - MUST match the padding used during encryption
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        global_encryptionErrorText = std::string("[DECS-P] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Determine buffer size
    size_t plaintext_len {0};
    if (EVP_PKEY_decrypt(
                ctx,
                NULL,
                &plaintext_len,
                reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                ciphertext.size()) <= 0) {
        global_encryptionErrorText = std::string("[DECS-BS] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // Perform decryption
    std::string result;
    result.resize(plaintext_len);
    if (EVP_PKEY_decrypt(
                ctx,
                reinterpret_cast<unsigned char*>(result.data()),
                &plaintext_len,
                reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                ciphertext.size()) <= 0) {
        global_encryptionErrorText = std::string("[DECS-D] ") + ERR_error_string(ERR_get_error(), nullptr);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    result.resize(plaintext_len); // Adjust to the actual decrypted size
    EVP_PKEY_CTX_free(ctx);
    return result;
}

std::string rsaKeyToString(EVP_PKEY *pubKey)
{
    BIO *bio = BIO_new(BIO_s_mem()); // Create a memory BIO
    char *pem_string = NULL;

    std::string res;
    if (PEM_write_bio_PUBKEY(bio, pubKey)) {
        long pem_length = BIO_get_mem_data(bio, &pem_string);
        res.reserve(pem_length);
        std::copy(pem_string, pem_string + pem_length, std::back_inserter(res));
    } else {
        global_encryptionErrorText = std::string("[TOSTR] ") + ERR_error_string(ERR_get_error(), nullptr);
    }

    BIO_free(bio);
    return res;
}

EVP_PKEY* rsaKeyFromString(const std::string& pubKey) {
    BIO* bio = BIO_new_mem_buf(pubKey.data(), static_cast<int>(pubKey.size()));
    if (!bio) {
        global_encryptionErrorText = std::string("[FROMSTR] ") + ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
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
    return pkey;
}

bool rsaEncryptFile(const std::string &targetFile, const std::string &pubkeyPath)
{
    std::string fileData;
    if (!Filework::Common::readFileData(targetFile, fileData)) {
        global_encryptionErrorText = "Failed to read file data";
        return false;
    }

    auto rsaPublicKey = rsaReadPublicKey(pubkeyPath);
    if (NULL == rsaPublicKey) {
        global_encryptionErrorText = "Failed to load public key";
        return false;
    }

    std::string res;
    const int blockSize = 211;
    for (auto currentPos = fileData.begin(); currentPos < fileData.end(); currentPos += blockSize) {
        auto block = rsaEncryptString(rsaPublicKey, std::string(currentPos, currentPos + blockSize));
        if (!block.has_value()) {
            return false;
        }
        res += block.value();
    }

    if (!Filework::Common::replaceFileData(targetFile, encodeHex(res))) {
        global_encryptionErrorText = "Failed to write file data";
        return false;
    }

    return true;
}

bool rsaDecryptFile(const std::string &targetFile, const std::string &privkeyPath, const std::string &pass)
{
    std::string fileData;
    if (!Filework::Common::readFileData(targetFile, fileData)) {
        global_encryptionErrorText = "Failed to read file data";
        return false;
    }
    fileData = decodeHex(fileData);

    auto rsaPrivateKey = rsaReadPrivateKey(privkeyPath, pass);
    if (NULL == rsaPrivateKey) {
        global_encryptionErrorText = "Failed to load private key";
        return false;
    }

    std::string res;
    const int blockSize = 256;
    for (auto currentPos = fileData.begin(); currentPos < fileData.end(); currentPos += blockSize) {
        auto block = rsaDecryptString(rsaPrivateKey, std::string(currentPos, currentPos + blockSize));
        if (!block.has_value()) {
            return false;
        }
        res += block.value();
    }

    if (!Filework::Common::replaceFileData(targetFile, res)) {
        global_encryptionErrorText = "Failed to write file data";
        return false;
    }

    return true;
}

}
