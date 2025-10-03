#include "hash.hpp"

#ifdef QT_CORE_LIB
#include <QByteArray>
#include <QDebug>
#endif // QT_CORE_LIB

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <iomanip>
#include <random>

#include <Components/Filework/Common.h>

// OpenSSL engine implementation
#define OPENSSL_ENGINE NULL

namespace Encryption {

#ifdef QT_CORE_LIB
QByteArray qtSha256(QByteArray txt) {
    return sha256(txt.toStdString()).c_str();
}
#endif // QT_CORE_LIB

std::string sha256(const std::string& input)
{
    if (input.empty()) {
        return "";
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx)
            EVP_MD_CTX_free(ctx);
    });
    if (!context)
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("EVP_DigestInit_ex failed");

    if (EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1)
        throw std::runtime_error("EVP_DigestUpdate failed");

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1)
        throw std::runtime_error("EVP_DigestFinal_ex failed");

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str().c_str();
}

std::string sha256file(const std::string &filepath)
{
    std::string fileData;

    if (!Filework::Common::readFileData(filepath, fileData)) {
        throw std::invalid_argument("sha256file: Invalid filepath");
        return {};
    }

    return sha256(fileData);
}

}  // namespace Encryption
