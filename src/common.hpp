#pragma once

#include <string>

namespace Encryption
{

inline std::string global_encryptionErrorText;

std::string getEncryptionErrorText();

std::string generateBytes(const size_t lengthByte);
std::string generateSybmols(const size_t lengthByte);

}


