#include "aes256.hpp"

#include <openssl/aes.h>  // Для AES_BLOCK_SIZE
#include <openssl/evp.h>
#include <openssl/err.h>

namespace Encryption {

static const auto BLOB_IV_LENGTH  = 12;  // GCM IV size recommended
static const auto BLOB_TAG_LENGTH = 16;  // GCM tag length
static const auto BLOB_LENGTH = BLOB_IV_LENGTH + BLOB_TAG_LENGTH;

// =================================================== //
// Pack in order: IV || TAG || CIPHERTEXT
std::optional<std::string> packGcmBlob(const std::string& iv,
                        const std::string& tag,
                        const std::string& ciphertext)
{
    if (iv.size() != BLOB_IV_LENGTH || tag.size() != BLOB_TAG_LENGTH) {
        global_encryptionErrorText = "Invalid size of AES-256-GCM blob part";
        return {};
    }

    std::string blob;
    blob.reserve(iv.size() + tag.size() + ciphertext.size());
    blob.append(iv);
    blob.append(tag);
    blob.append(ciphertext);
    return blob;
}

// =================================================== //
// Pack in order: IV (12) | TAG (16) | CIPHERTEXT
bool unpackGcmBlob(const std::string& blob,
                   std::string& iv,
                   std::string& tag,
                   std::string& ciphertext)
{
    const auto BLOB_IV_LENGTH  = 12;  // GCM IV size recommended
    const auto BLOB_TAG_LENGTH = 16;  // GCM tag length

    if (blob.size() < BLOB_IV_LENGTH + BLOB_TAG_LENGTH) {
        global_encryptionErrorText = "Invalid size of AES-256-GCM blob part";
        return false;
    }
    iv.assign(blob.data(), BLOB_IV_LENGTH);
    tag.assign(blob.data() + BLOB_IV_LENGTH, BLOB_TAG_LENGTH);
    ciphertext.assign(blob.data() + BLOB_IV_LENGTH + BLOB_TAG_LENGTH,
                      blob.size() - BLOB_IV_LENGTH - BLOB_TAG_LENGTH);
    return true;
}


// =================================================== //
// =================================================== //
// =================================================== //
bool aes256_gcm_encryptHelper(const std::string& plaintext,
                            const std::string& key,
                            const std::string& iv,
                            const std::string& aad,
                            std::string& ciphertext,
                            std::string& tag)
{
    if (key.size() != 32 || iv.empty()) {
        global_encryptionErrorText = "Invalid key or IV length for AES-256-GCM";
        return false;
    }

    const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-gcm");
    if (cipher == NULL) {
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                           reinterpret_cast<const unsigned char*>(key.c_str()),
                           reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (!aad.empty())
    {
        int aadLength = 0;
        if (EVP_EncryptUpdate(ctx, NULL, &aadLength,
                              reinterpret_cast<const unsigned char*>(aad.c_str()),
                              static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
            return false;
        }
    }

    const int plaintextLength = plaintext.length();
    const int maxCiphertextLength =
        plaintextLength + EVP_CIPHER_block_size(cipher);

    unsigned char* ciphertextBytes = new unsigned char[maxCiphertextLength];
    int ciphertextLength = 0;

    if (EVP_EncryptUpdate(ctx, ciphertextBytes, &ciphertextLength,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                          plaintextLength) != 1)
    {
        delete[] ciphertextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    int ciphertextFinalLength = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertextBytes + ciphertextLength,
                            &ciphertextFinalLength) != 1)
    {
        delete[] ciphertextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }
    ciphertextLength += ciphertextFinalLength;

    unsigned char tagBytes[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(sizeof(tagBytes)), tagBytes) != 1)
    {
        delete[] ciphertextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    ciphertext.assign(reinterpret_cast<const char*>(ciphertextBytes), ciphertextLength);
    tag.assign(reinterpret_cast<const char*>(tagBytes), sizeof(tagBytes));

    delete[] ciphertextBytes;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

// =================================================== //
// =================================================== //
// =================================================== //
bool aes256_gcm_decryptHelper(std::string& ciphertext,
                            const std::string& key,
                            const std::string& iv,
                            const std::string& aad,
                            const std::string& tag,
                            std::string& plaintext)
{
    plaintext.clear();

    if (key.size() != 32 || iv.empty() || tag.size() != 16)
    {
        global_encryptionErrorText = "Invalid key, IV or tag length for AES-256-GCM";
        return false;
    }

    // Указываем параметры алгоритма шифрования
    const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-gcm");
    if (cipher == NULL)
    {
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    // Дешифруем текст
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL,
                           reinterpret_cast<const unsigned char*>(key.c_str()),
                           reinterpret_cast<const unsigned char*>(iv.c_str())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (!aad.empty())
    {
        int aadLength = 0;
        if (EVP_DecryptUpdate(ctx, NULL, &aadLength,
                              reinterpret_cast<const unsigned char*>(aad.c_str()),
                              static_cast<int>(aad.size())) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
            return false;
        }
    }

    const int ciphertextLength = ciphertext.length();
    const int maxPlaintextLength =
        ciphertextLength + EVP_CIPHER_block_size(cipher);

    unsigned char* plaintextBytes = new unsigned char[maxPlaintextLength];
    int plaintextLength = 0;

    if (EVP_DecryptUpdate(ctx, plaintextBytes, &plaintextLength,
                          reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                          ciphertextLength) != 1)
    {
        delete[] plaintextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            (void*)tag.data()) != 1) // will be too large cast otherwise
    {
        delete[] plaintextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    int plaintextFinalLength = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintextBytes + plaintextLength,
                            &plaintextFinalLength) != 1)
    {
        // Тег не сошёлся — данные подделаны или AAD/ключ/IV неверны.
        delete[] plaintextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }
    plaintextLength += plaintextFinalLength;

    plaintext.assign(reinterpret_cast<const char*>(plaintextBytes), plaintextLength);

    delete[] plaintextBytes;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}



std::optional<std::string> aes256_gcm_encrypt(const std::string& input, const std::string& key, const std::string& aad) {
    auto iv = generateBytes(BLOB_IV_LENGTH);
    std::string tag;
    std::string ciphertext;
    if (aes256_gcm_encryptHelper(input, key, iv, aad, ciphertext, tag)) {
        auto packedResult = packGcmBlob(iv, tag, ciphertext);
        return packedResult;
    }
    return {};
}


std::optional<std::string> aes256_gcm_decrypt(const std::string& input, const std::string& key, const std::string& aad) {

    std::string iv;
    std::string tag;
    std::string ciphertext;
    if (!unpackGcmBlob(input, iv, tag, ciphertext)) {
        return {};
    }

    std::string result;
    if (aes256_gcm_decryptHelper(ciphertext, key, iv, aad, tag, result)) {
        return result;
    }
    return {};
}

}
