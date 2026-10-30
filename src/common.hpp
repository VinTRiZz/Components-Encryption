#pragma once

#include <cstring>
#include <string>

#include <Components/ExtraClasses/Error.h>

namespace Encryption
{

// Encryption processes error
thread_local inline ExtraClasses::ErrorObject g_error {};

inline void setEncryptionError(
    ExtraClasses::ErrorCode errCode,
    const std::string& errLocation,
    const std::string& openSSLdescr) {
    g_error = ExtraClasses::ErrorObject(errCode,
                                      errLocation + " : " + openSSLdescr);
}

inline std::string getEncryptionErrorText() {
    return g_error.getDetailText();
}

inline ExtraClasses::ErrorObject getEncryptionError() {
    return g_error;
}

/**
 * @brief secureClearMemory Used to avoid Dead Store Elimination
 * @param ptr               Pointer to array
 * @param size              Size of memory pointer holds
 */
template <typename T>
void secureClearMemory(T* ptr, std::size_t size) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#elif defined(__linux__)
    explicit_bzero(ptr, size);
#elif defined(__GNUC__) || defined(__clang__)
    std::memset(ptr, 0, count * sizeof(T));
    asm volatile("" : : "r"(ptr) : "memory"); // Assembler barrier for compiler
#else
    throw std::runtime_error("Can not secure clear memory (not implemented for current circumstances)");
#endif
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

