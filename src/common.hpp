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
 * @brief generateBytes Generates bytes using std::uniform_distribution
 * @param lengthByte    Size of a string to generate
 * @return
 */
std::string generateBytes(const size_t lengthByte);

/**
 * @brief generateSybmols   Generate symbols with no escape sequences
 * @param lengthByte        Size of a string to generate
 * @return
 */
std::string generateSymbols(const size_t lengthByte);

/**
 * @brief aes256_fixKeySize Resize key to correct (32 byte) size of AES-256
 * @param key               Key to resize. Exceed bytes will be XOR'ed to correct ones
 * @return
 */
void aes256_fixKeySize(std::string &key);

}

