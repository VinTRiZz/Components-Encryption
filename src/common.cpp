#include "common.hpp"

#include <random>
#include <algorithm>

namespace Encryption
{

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

std::string generateSymbols(const size_t lengthByte)
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(0, 255);

    std::string result;
    for (int8_t i = 0; result.size() < lengthByte; i++) {
        char test_symbol = uni(rng);
        if (((test_symbol >= '0') && (test_symbol <= '9')) ||
            ((test_symbol >= 'a') && (test_symbol <= 'z')) ||
            ((test_symbol >= 'A') && (test_symbol <= 'Z'))) {
            result += test_symbol;
        }
    }

    return result;
}

void aes256_fixKeySize(std::string &key)
{
    if (key.size() > 32) {
        for (int i = 32; i < key.size() - 32; ++i) {
            key[i % 32] ^= key[i];
        }
        key.erase(key.begin() + 32, key.end());
    } else if (key.size() < 32) {
        std::fill_n(std::back_inserter(key), 32 - key.size(), 0x00);
    }
}

}
