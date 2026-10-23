#pragma once

#include <string>

namespace Encryption
{

inline std::string global_encryptionErrorText;

std::string getEncryptionErrorText();

std::string generateBytes(const size_t lengthByte);
std::string generateSybmols(const size_t lengthByte);

/**
 * @brief aes256_fixKeySize Resize key to correct (32 byte) size of AES-256
 * @param key               Key to resize
 * @return
 */
void aes256_fixKeySize(std::string &key);

}

