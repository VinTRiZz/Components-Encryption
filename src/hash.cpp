#include "hash.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <QByteArray>
#include <QDebug>
#include <iomanip>
#include <random>

// OpenSSL engine implementation
#define OPENSSL_ENGINE NULL

namespace Encryption {

QByteArray qtSha256(QByteArray txt) {
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

std::string sha256(const std::string& input)
{
    if (input.empty()) {
        return "";
    }

    // Create a buffer to hold the hash
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Compute the SHA-256 hash
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(),
           hash);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << static_cast<int>(hash[i]);
    }
    return ss.str();

    //    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Create a new context
    //    const EVP_MD *md = EVP_sha256(); // Get the SHA-256 algorithm
    //    std::vector<unsigned char> hash(EVP_MD_size(md)); // Prepare a vector
    //    to hold the hash

    //    if (mdctx == nullptr || md == nullptr ||
    //        EVP_DigestInit_ex(mdctx, md, nullptr) != 1 || // Initialize the
    //        digest EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1
    //        ||
    //        // Update the digest with the input EVP_DigestFinal_ex(mdctx,
    //        hash.data(), nullptr) != 1) { // Finalize the digest

    //        // Handle errors here (e.g. throw an exception or return an error
    //        code) EVP_MD_CTX_free(mdctx); LOG_ERROR("Failed to compute hash");
    //        return "";
    //    }

    //    EVP_MD_CTX_free(mdctx); // Clean up the context

    //    // Convert the hash to a hex string
    //    std::stringstream ss;
    //    for (unsigned char byte : hash) {
    //        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    //    }

    //    return ss.str();
}

}  // namespace Encryption
