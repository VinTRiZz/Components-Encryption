#pragma once

/// **************************************************************************** ///
/// *********************** Rivest-Shamir-Adleman (RSA) ************************ ///
/// **************************************************************************** ///

#include <string>
#include <optional>

#include "common.hpp"

struct rsa_st;
using RSA = rsa_st;

typedef struct evp_pkey_st EVP_PKEY; // For OpenSSL RSA

namespace Encryption
{

EVP_PKEY* rsaGenerateKeys();
bool rsaSavePublicKey(EVP_PKEY* pkey, const std::string& filename);
bool rsaSavePrivateKey(EVP_PKEY* pkey, const std::string& filename);

EVP_PKEY* rsaReadPublicKey(const std::string& filename);
EVP_PKEY* rsaReadPrivateKey(const std::string& filename, const std::string& passphrase = {});

std::optional<std::string> rsaEncryptString(EVP_PKEY* publicKey, const std::string& plaintext);
std::optional<std::string> rsaDecryptString(EVP_PKEY* privateKey, const std::string& ciphertext);

// PEM format only
std::string rsaKeyToString(EVP_PKEY* pubKey);
EVP_PKEY* rsaKeyFromString(const std::string& pubKey);

bool rsaEncryptFile(const std::string& targetFile, const std::string& pubkeyPath);
bool rsaDecryptFile(const std::string& targetFile, const std::string& privkeyPath, const std::string& pass = {});

}

