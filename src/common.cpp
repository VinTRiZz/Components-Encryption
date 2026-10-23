#include "common.hpp"

#include <random>
#include <algorithm>

namespace Encryption
{

std::string getEncryptionErrorText()
{
    return global_encryptionErrorText;
}

std::string generateBytes(const size_t lengthByte)
{
    std::string result;
    result.reserve(lengthByte);

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(0, 255);

    std::generate_n(std::back_inserter(result), lengthByte, [&](){ return uni(rng); });

    return result;
}

std::string generateSybmols(const size_t lengthByte)
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

}
