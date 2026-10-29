#include "aes256.hpp"

#include <openssl/aes.h>  // Для AES_BLOCK_SIZE
#include <openssl/evp.h>
#include <openssl/err.h>

namespace Encryption {

bool aes256_cbc_encryptHelper(const std::string& plaintext,
                              const std::string& key,
                              const std::string& iv,
                              std::string& ciphertext)
{
    if (key.size() != 32) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalInvalidValue,
                           "[AES256-CBC] key size",
                           "Key size is invalid (expected 32 bytes)");
        return false;
    }

    const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-cbc");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncryptionFailed,
                           "[AES256-CBC] EVP_CIPHER_CTX_new",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key.c_str(),
                           (const unsigned char*)iv.c_str()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncryptionFailed,
                           "[AES256-CBC] EVP_EncryptInit_ex",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    const int plaintextLength = plaintext.length();
    const int maxCiphertextLength =
        plaintextLength + EVP_CIPHER_block_size(cipher);
    unsigned char* ciphertextBytes = new unsigned char[maxCiphertextLength];
    int ciphertextLength           = 0;
    if (EVP_EncryptUpdate(ctx, ciphertextBytes, &ciphertextLength,
                          (const unsigned char*)plaintext.c_str(),
                          plaintextLength) != 1)
    {
        delete[] ciphertextBytes;
        EVP_CIPHER_CTX_free(ctx);
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncryptionFailed,
                           "[AES256-CBC] EVP_EncryptUpdate",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    int ciphertextFinalLength = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertextBytes + ciphertextLength,
                            &ciphertextFinalLength) != 1)
    {
        delete[] ciphertextBytes;
        EVP_CIPHER_CTX_free(ctx);
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncryptionFailed,
                           "[AES256-CBC] EVP_EncryptFinal_ex",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    ciphertextLength += ciphertextFinalLength;
    ciphertext.assign((const char*)ciphertextBytes, ciphertextLength);
    delete[] ciphertextBytes;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool aes256_cbc_decryptHelper(std::string& ciphertext,
                              const std::string& key,
                              const std::string& iv,
                              std::string& plaintext)
{
    if (key.size() != 32) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalInvalidValue,
                           "[AES256-CBC] key size",
                           "Key size is invalid (expected 32 bytes)");
        return false;
    }

    // Указываем параметры алгоритма шифрования
    const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-cbc");

    // Дешифруем текст
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key.c_str(),
                           (const unsigned char*)iv.c_str()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        setEncryptionError(ExtraClasses::ErrorCode::LogicalDecryptionFailed,
                           "[AES256-CBC] EVP_DecryptInit_ex",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    const int ciphertextLength = ciphertext.length();
    const int maxPlaintextLength =
        ciphertextLength + EVP_CIPHER_block_size(cipher);
    unsigned char* plaintextBytes = new unsigned char[maxPlaintextLength];
    int plaintextLength           = 0;
    if (EVP_DecryptUpdate(ctx, plaintextBytes, &plaintextLength,
                          (const unsigned char*)ciphertext.c_str(),
                          ciphertextLength) != 1)
    {
        delete[] plaintextBytes;
        EVP_CIPHER_CTX_free(ctx);
        setEncryptionError(ExtraClasses::ErrorCode::LogicalDecryptionFailed,
                           "[AES256-CBC] EVP_DecryptUpdate",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    int plaintextFinalLength = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintextBytes + plaintextLength,
                            &plaintextFinalLength) != 1)
    {
        delete[] plaintextBytes;
        EVP_CIPHER_CTX_free(ctx);
        setEncryptionError(ExtraClasses::ErrorCode::LogicalDecryptionFailed,
                           "[AES256-CBC] EVP_DecryptFinal_ex",
                           ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    plaintextLength += plaintextFinalLength;
    plaintext.assign((const char*)plaintextBytes, plaintextLength);
    delete[] plaintextBytes;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

std::optional<std::string> aes256_cbc_encrypt(const std::string &input, const std::string &key)
{
    if (input.empty()) { return {}; }

    std::string encryptedPacket;
    std::string iv = generateBytes_CSPRNG(64);

    if (aes256_cbc_encryptHelper(input, key, iv, encryptedPacket)) {
        std::string output = iv;
        output.append(encryptedPacket);
        return output;
    }
    return {};
}

std::optional<std::string> aes256_cbc_decrypt(const std::string &input, const std::string &key)
{
    if (input.empty()) { return {}; }

    auto encryptedPacket = input;
    std::string iv = encryptedPacket.substr(0, 64);
    encryptedPacket.erase(0, 64);

    std::string output;
    if (aes256_cbc_decryptHelper(encryptedPacket, key, iv, output)) {
        return output;
    }
    return {};
}

}  // namespace Encryption
