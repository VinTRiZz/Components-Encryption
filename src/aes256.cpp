#include "aes256.hpp"

#include <openssl/aes.h>  // Для AES_BLOCK_SIZE
#include <openssl/err.h>
#include <openssl/evp.h>

#include <QByteArray>
#include <QDebug>
#include <iomanip>
#include <random>

namespace Encryption {

std::string global_encryptionErrorText;

std::string generateKey(size_t lengthByte)
{
    std::string result;
    char test_symbol;

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(0, 255);

    for (int8_t i = 0; result.size() < lengthByte; i++)
    {
        test_symbol = uni(rng);
        if ((test_symbol > 32) || (test_symbol < 0))
        {
            result += test_symbol;
        }
    }

    return result;
}

bool aes256encryptHelper(const std::string& plaintext,
                                       const std::string& key,
                                       const std::string& iv,
                                       std::string& ciphertext)
{
    const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-cbc");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key.c_str(),
                           (const unsigned char*)iv.c_str()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
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
    ciphertext.assign((const char*)ciphertextBytes, ciphertextLength);
    delete[] ciphertextBytes;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool aes256decryptHelper(std::string& ciphertext,
                                       const std::string& key,
                                       const std::string& iv,
                                       std::string& plaintext)
{
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
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
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
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }
    int plaintextFinalLength = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintextBytes + plaintextLength,
                            &plaintextFinalLength) != 1)
    {
        delete[] plaintextBytes;
        EVP_CIPHER_CTX_free(ctx);
        global_encryptionErrorText = ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }
    plaintextLength += plaintextFinalLength;
    plaintext.assign((const char*)plaintextBytes, plaintextLength);
    delete[] plaintextBytes;
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

std::string aes256encrypt(const std::string &input, const std::string &key)
{
    std::string encryptedPacket;
    std::string iv = generateKey(key.size());

    if (aes256encryptHelper(input, key, iv, encryptedPacket)) {
        std::string output = iv;
        output.append(encryptedPacket);
        return output;
    }
    return {};
}

std::string aes256decrypt(const std::string &input, const std::string &key)
{
    std::string encryptedPacket = input;

    std::string iv = encryptedPacket.substr(0, key.size());
    encryptedPacket.erase(0, key.size());

    std::string output;
    if (aes256decryptHelper(encryptedPacket, key, iv, output)) {
        return output;
    }
    return {};
}

std::string getEncryptionErrorText()
{
    return global_encryptionErrorText;
}

#ifdef QT_CORE_LIB
QByteArray encryptAes256Cbc(const QByteArray& plainText, QByteArray key) {
    return QByteArray::fromStdString(aes256encrypt(plainText.toStdString(), key.toStdString()));
}

QByteArray decryptAes256Cbc(const QByteArray& cipherText, QByteArray key) {
    return QByteArray::fromStdString(aes256decrypt(cipherText.toStdString(), key.toStdString()));
}
#endif // QT_CORE_LIB

}  // namespace Encryption
