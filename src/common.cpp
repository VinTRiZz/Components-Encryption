#include "common.hpp"

#include <random>
#include <algorithm>
#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
#endif

namespace Encryption
{

static void fillArrayCSPRNG(uint8_t* buffer, const std::size_t lengthByte) {
    if (lengthByte == 0) return;

#if defined(_WIN32)
    // Использование Windows CNG API
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer,
        static_cast<ULONG>(lengthByte),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Windows BCryptGenRandom failed.");
    }

#elif defined(__linux__)
    if (lengthByte > 33'000'000) { // Linux core's generating issues
        throw std::invalid_argument("Invalid array size to generate random one (> 33 000 000)");
    }

    // (Linux 3.17+)
    std::size_t bytes_generated = 0;
    while (bytes_generated < lengthByte) {
        ssize_t result = getrandom(
            buffer + bytes_generated,
            lengthByte - bytes_generated,
            0
            );
        if (result < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("Byte generation failed");
        }
        bytes_generated += result;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    // Использование безопасного arc4random_buf на macOS/BSD
    arc4random_buf(buffer, lengthByte);

#else
    throw std::runtime_error("Unknown OS, cound not determine cryptosafe byte source");
#endif
}

std::string generateBytes_CSPRNG(const std::size_t lengthByte)
{
    std::string result;
    result.resize(lengthByte);
    fillArrayCSPRNG(reinterpret_cast<uint8_t*>(result.data()), lengthByte);
    return result;
}

std::string generateBytes(const std::size_t lengthByte)
{
    std::string result;
    result.reserve(lengthByte);

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(0, 255);

    std::generate_n(std::back_inserter(result), lengthByte, [&](){ return uni(rng); });

    return result;
}

std::string generateSymbols(const std::size_t lengthByte)
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
