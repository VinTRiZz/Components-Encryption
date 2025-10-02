#include "rsa.hpp"

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <fstream>

namespace Encryption
{

void generate_rsa_keypair(RSA** rsa_key)
{
    *rsa_key = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(*rsa_key, 2048, e, NULL);
    BN_free(e);
}

std::string rsa_public_key_to_string(RSA* rsa_key)
{
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa_key);
    char* buffer = NULL;
    long key_size = BIO_get_mem_data(bio, &buffer);
    std::string key_str(buffer, key_size);
    BIO_free(bio);
    return key_str;
}

RSA* rsa_public_key_from_string(std::string & public_key_str)
{
    const char* public_key_cstr = public_key_str.c_str();
    BIO* bio = BIO_new_mem_buf((void*)public_key_cstr, -1);
    RSA* rsa_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (rsa_key == NULL)
    {
        return NULL;
    }
    BIO_free(bio);
    return rsa_key;
}

bool savePrivateKey(RSA* rsa_key, const std::string& filename)
{
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp)
    {
        return false;
    }

    int ret = PEM_write_RSAPrivateKey(fp, rsa_key, nullptr, nullptr, 0, nullptr, nullptr);
    if (ret != 1)
    {
        fclose(fp);
        return false;
    }

    fclose(fp);

    return true;
}

RSA* loadPrivateKey(const std::string& filename)
{
    RSA* rsa_key = nullptr;

    FILE* fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        return nullptr;
    }

    rsa_key = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    if (!rsa_key)
    {
        fclose(fp);
        return nullptr;
    }

    fclose(fp);

    return rsa_key;
}

RSA* loadPublicKey(const std::string& filename)
{
    RSA* rsa_key = nullptr;

    FILE* fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        return nullptr;
    }

    rsa_key = PEM_read_RSAPublicKey(fp, nullptr, nullptr, nullptr);
    if (!rsa_key)
    {
        fclose(fp);
        return nullptr;
    }

    fclose(fp);

    return rsa_key;
}

bool savePublicKey(RSA* rsa_key, const std::string& filename)
{
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp)
    {
        return false;
    }

    int ret = PEM_write_RSAPublicKey(fp, rsa_key);
    if (ret != 1)
    {
        fclose(fp);
        return false;
    }

    fclose(fp);

    return true;
}

bool rsa_encrypt(const std::string & message, RSA* rsa_key, std::string & encryptedMessage)
{
    int rsa_len = RSA_size(rsa_key);
    unsigned char* rsa_encrypted = new unsigned char[rsa_len];
    int encrypted_len = RSA_public_encrypt(message.length(), (unsigned char*)message.c_str(), rsa_encrypted, rsa_key, RSA_PKCS1_PADDING);
    if (encrypted_len == -1)
    {
        return false;
    }
    encryptedMessage = std::string((const char*)rsa_encrypted, encrypted_len);
    delete[] rsa_encrypted;
    return true;
}

bool rsa_encrypt(const std::vector<char> message, RSA* rsa_key, char * encryptedMessage)
{
    int rsa_len = RSA_size(rsa_key);
    unsigned char* rsa_encrypted = new unsigned char[rsa_len];
    int encrypted_len = RSA_public_encrypt(message.size(), (unsigned char*)message.data(), rsa_encrypted, rsa_key, RSA_PKCS1_PADDING);
    if (encrypted_len == -1)
    {
        return false;
    }
    memcpy(encryptedMessage, rsa_encrypted, encrypted_len);
    delete[] rsa_encrypted;
    return true;
}

bool rsa_decrypt(const std::string & encryptedMessage, RSA* rsa_key, std::string & decryptedMessage)
{
    int rsa_len = RSA_size(rsa_key);
    unsigned char* rsa_decrypted = new unsigned char[rsa_len];
    int decrypted_len = RSA_private_decrypt(encryptedMessage.length(), (unsigned char*)encryptedMessage.c_str(), rsa_decrypted, rsa_key, RSA_PKCS1_PADDING);
    if (decrypted_len == -1)
    {
        return false;
    }
    decryptedMessage = std::string((const char*)rsa_decrypted, decrypted_len);
    delete[] rsa_decrypted;
    return true;
}

bool rsa_decrypt(const std::vector<char> encryptedMessage, RSA* rsa_key, char * decryptedMessage)
{
    int rsa_len = RSA_size(rsa_key);
    unsigned char* rsa_decrypted = new unsigned char[rsa_len];
    int decrypted_len = RSA_private_decrypt(encryptedMessage.size(), (unsigned char*)encryptedMessage.data(), rsa_decrypted, rsa_key, RSA_PKCS1_PADDING);
    if (decrypted_len == -1)
    {
        return false;
    }
    memcpy(decryptedMessage, rsa_decrypted, decrypted_len);
    delete[] rsa_decrypted;
    return true;
}

void encryptFileRSA(const std::string & inputPath, const std::string & outputPath, const std::string & pubKeyPath, const std::string & privKeyPath)
{
    std::fstream inputFile(inputPath, std::ios_base::in | std::ios_base::binary), outputFile(outputPath, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);

    if (!inputFile.is_open() || !outputFile.is_open())
    {
        return;
    }

    RSA * keys;
    generate_rsa_keypair(&keys);
    if (!savePrivateKey(keys, privKeyPath) || !savePublicKey(keys, pubKeyPath))
    {
        return;
    }

    const size_t bufSize = RSA_size(keys) - 11;
    const size_t resultSize = RSA_size(keys);
    char bufferChar[ bufSize ];
    std::vector<char> bufCharVect;
    char encryptResult[ resultSize ];

    while (!inputFile.eof())
    {
        if (inputFile.read(bufferChar, bufSize).gcount() <= 0)
        {
            break;
        }

        bufCharVect.resize(bufSize);
        std::copy(bufferChar, bufferChar + bufSize, bufCharVect.begin());

        if (rsa_encrypt(bufCharVect, keys, encryptResult))
        {
            outputFile.write(encryptResult, resultSize);

            // Clear buffers
            bufCharVect.clear();
            std::fill(bufferChar, bufferChar + bufSize, '\0');
            std::fill(encryptResult, encryptResult + resultSize, '\0');
        }
    }

    RSA_free(keys);

    inputFile.close();
    outputFile.close();
}

void decryptFileRSA(const std::string & inputPath, const std::string & outputPath, const std::string & privKeyPath)
{
    std::fstream inputFile(inputPath, std::ios_base::in | std::ios_base::binary), outputFile(outputPath, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);

    if (!inputFile.is_open() || !outputFile.is_open())
    {
        return;
    }

    RSA * loadedPrivKey;
    loadedPrivKey = loadPrivateKey(privKeyPath);
    if (loadedPrivKey == nullptr)
    {
        return;
    }

    const size_t bufSize = RSA_size(loadedPrivKey);
    const size_t resultSize = RSA_size(loadedPrivKey) - 11;
    char bufferChar[ bufSize ];
    std::vector<char> bufCharVect;
    char decryptResult[ resultSize ];
    char suffix[8] = {0x00};

    while (!inputFile.eof())
    {
        if (inputFile.read(bufferChar, bufSize).gcount() < bufSize)
        {
            break;
        }

        bufCharVect.resize(bufSize);
        std::copy(bufferChar, bufferChar + bufSize, bufCharVect.begin());

        if (rsa_decrypt(bufCharVect, loadedPrivKey, decryptResult))
        {
            if (inputFile.read(bufferChar, bufSize).gcount() < bufSize)
            {
                char * garbagePos_begin = std::search(decryptResult, decryptResult + resultSize, suffix, suffix + 7);

                if (garbagePos_begin < (decryptResult + resultSize))
                {
                    outputFile.write(decryptResult, garbagePos_begin - decryptResult);
                }
                else
                {
                    outputFile.write(decryptResult, resultSize);
                }
            }
            else
            {
                inputFile.seekg(-256, std::ios_base::cur);

                outputFile.write(decryptResult, resultSize);
            }

            // Clear buffers
            bufCharVect.clear();
            std::fill(bufferChar, bufferChar + bufSize, '\0');
            std::fill(decryptResult, decryptResult + resultSize, '\0');
        }
    }

    RSA_free(loadedPrivKey);

    inputFile.close();
    outputFile.close();
}

}
