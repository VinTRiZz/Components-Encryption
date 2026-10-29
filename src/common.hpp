#pragma once

#include <string>

namespace Encryption
{

// Used to get error text
thread_local inline std::string global_encryptionErrorText {};

inline std::string getEncryptionErrorText() {
    return global_encryptionErrorText;
}

/**
 * @brief generateBytes_CSPRNG  Generates bytes using CSPRNG (for salt, keys, etc.)
 * @param lengthByte            Size of a string to generate
 * @return
 */
std::string generateBytes_CSPRNG(const std::size_t lengthByte);

/**
 * @brief generateBytes Generates bytes using std::uniform_distribution
 * @param lengthByte    Size of a string to generate
 * @return
 */
std::string generateBytes(const std::size_t lengthByte);

/**
 * @brief generateSybmols   Generate symbols with no escape sequences using std::uniform_distribution
 * @param lengthByte        Size of a string to generate
 * @return
 */
std::string generateSymbols(const std::size_t lengthByte);

/**
 * @brief aes256_fixKeySize Resize key to correct (32 byte) size of AES-256
 * @param key               Key to fix, will be filled with 0x00 or cut
 * @note                    Function is NOT cryptosafe, key creating is user's responsibility
 */
void aes256_fixKeySize(std::string &key);

}

