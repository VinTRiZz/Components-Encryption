#pragma once

#include <string>

#include "common.hpp"

namespace Encryption
{

std::string encodeBase64(const std::string& input);
std::string decodeBase64(const std::string& input);

std::string encodeHex(const std::string& input);
std::string decodeHex(const std::string& input);

}
