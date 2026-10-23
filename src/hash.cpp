#include "hash.hpp"

#ifdef QT_CORE_LIB
#include <QByteArray>
#include <QDebug>
#endif // QT_CORE_LIB

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <iomanip>
#include <fstream>
#include <memory>
#include <filesystem>

// OpenSSL engine implementation
#define OPENSSL_ENGINE NULL

namespace Encryption {

std::optional<std::string> sha256(const std::string_view &input)
{
    if (input.empty()) {
        global_encryptionErrorText = "Empty input";
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        global_encryptionErrorText = std::string("Failed to create context of SHA-256") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    if (EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}



std::optional<std::string> sha256file(const std::string_view &filepath)
{
    if (!std::filesystem::exists(filepath)) {
        global_encryptionErrorText = std::string("SHA-256 sum failed: No such file or directory: ") + filepath.data();
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        global_encryptionErrorText = std::string("Failed to create EVP_MD_CTX") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    std::ifstream inputFile(filepath.data());
    const auto bufsize = 1024;
    char readbuf[bufsize] {};
    auto readCnt = inputFile.readsome(readbuf, bufsize);
    while (readCnt > 0) {
        if (EVP_DigestUpdate(context.get(), readbuf, readCnt) != 1) {
            global_encryptionErrorText = std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr);
            return {};
        }
        readCnt = inputFile.readsome(readbuf, bufsize);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

}  // namespace Encryption
