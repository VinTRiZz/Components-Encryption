#include "aes256.hpp"

#include <openssl/aes.h>  // Для AES_BLOCK_SIZE
#include <openssl/err.h>
#include <openssl/evp.h>

#include <QByteArray>
#include <QDebug>
#include <iomanip>
#include <random>

namespace Encryption {

QByteArray sha256(QByteArray txt) {
    auto input = txt.toStdString();
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

}  // namespace Encryption
