#pragma once

#include <cstring>
#include <string>

#include <Components/ExtraClasses/Error.h>

namespace Encryption
{

// ===================================================== //

// Inlines for compiler optimisation potential (assuming lib can build in shared mode)

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


// ===================================================== //

/**
 * @brief secureClearMemory Clean memory with avoiding Dead Store Elimination
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
 * @brief The SafeString class RAII to use secure clear memory
 */
class SafeString
{
public:
    SafeString() = default;
    ~SafeString() { secureClearMemory(m_value.data(), m_value.size()); }

    SafeString(const std::string& iStr) : m_value {iStr} {}
    SafeString(std::string&& iStr) : m_value {std::move(iStr)} {}

    inline SafeString& operator=(const std::string& iStr) {
        secureClearMemory(m_value.data(), m_value.size());
        m_value = iStr;
        return *this;
    }

    inline SafeString& operator=(std::string&& iStr) {
        secureClearMemory(m_value.data(), m_value.size());
        m_value = std::move(iStr);
        return *this;
    }

    std::string& value() { return m_value; }
    const std::string& value() const { return m_value; }

private:
    std::string m_value;
};


/**
 * @brief generateBytes_CSPRNG  Generates bytes using CSPRNG (for salt, keys, etc.)
 * @param lengthByte            Size of a string to generate
 * @return
 * @throws                      std::runtime_error or std::invalid_argument on errors
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

