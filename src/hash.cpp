#include "hash.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <sstream>
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
        setEncryptionError(ExtraClasses::ErrorCode::LogicalInvalidValue,
                           "[SHA-256] input",
                           "Empty input");
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_MD_CTX_new",
                           std::string("Failed to create context of SHA-256: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestInit_ex",
                           std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    if (EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestUpdate",
                           std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestFinal_ex",
                           std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr));
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
        setEncryptionError(ExtraClasses::ErrorCode::SystemFileError,
                           "[SHA-256] file",
                           std::string("SHA-256 sum failed: No such file or directory: ") + filepath.data());
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_MD_CTX_new",
                           std::string("Failed to create EVP_MD_CTX: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestInit_ex",
                           std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    std::ifstream inputFile(filepath.data());
    const auto bufsize = 1024;
    char readbuf[bufsize] {};
    auto readCnt = inputFile.readsome(readbuf, bufsize);
    while (readCnt > 0) {
        if (EVP_DigestUpdate(context.get(), readbuf, readCnt) != 1) {
            setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestUpdate",
                           std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr));
            return {};
        }
        readCnt = inputFile.readsome(readbuf, bufsize);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestFinal_ex",
                           std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}



SensitiveDataHash hashSensitiveData(std::string &&sensitiveData)
{
    if (sensitiveData.empty()) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SensitiveDataHash] Init",
                           "Empty input");
        return {};
    }

    const size_t SDH_SALT_SIZE = 16;
    const size_t SDH_HASH_SIZE = 32; // 256 bit
    const uint32_t SDH_ITERATION_COUNT = 600000; // OWASP recomendation

    // Setup KDF context
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "PBKDF2", nullptr);
    auto pCtx = std::shared_ptr<EVP_KDF_CTX>{
        EVP_KDF_CTX_new(kdf),
        [](EVP_KDF_CTX* ctx){
            EVP_KDF_CTX_free(ctx);
        }
    };
    EVP_KDF_free(kdf);

    if (!pCtx) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SensitiveDataHash] Init",
                           std::string("KDF context setup failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    // Configure OpenSSL for hashing with PBKDF2
    auto salt = generateBytes_CSPRNG(SDH_SALT_SIZE);
    OSSL_PARAM osslParameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(sensitiveData.data()), sensitiveData.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, const_cast<uint32_t*>(&SDH_ITERATION_COUNT)),
        OSSL_PARAM_construct_end()
    };

    // Get key
    std::string derivedKey;
    derivedKey.resize(SDH_HASH_SIZE);
    auto deriveRes = EVP_KDF_derive(pCtx.get(), reinterpret_cast<uint8_t*>(derivedKey.data()), derivedKey.size(), osslParameters);
    if (deriveRes <= 0) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SensitiveDataHash] Derive",
                           std::string("PBKDF2 calc failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    secureClearMemory(sensitiveData.data(), sensitiveData.size());
    return { std::move(salt), std::move(derivedKey) };
}

}  // namespace Encryption
