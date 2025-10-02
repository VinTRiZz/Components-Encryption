#pragma once

/// **************************************************************************** ///
/// *********************** Rivest-Shamir-Adleman (RSA) ************************ ///
/// **************************************************************************** ///

#include <string>
#include <vector>

#include "common.hpp"

struct rsa_st;
using RSA = rsa_st;

typedef struct evp_pkey_st EVP_PKEY; // For OpenSSL RSA

namespace Encryption
{

EVP_PKEY* rsaGenerateKeys();
bool rsaSavePublicKey(EVP_PKEY* pkey, const std::string& filename);
bool rsaSavePrivateKey(EVP_PKEY* pkey, const std::string& filename);

EVP_PKEY* rsaLoadPublicKey(const std::string& filename);
EVP_PKEY* rsaLoadPrivateKey(const std::string& filename, const std::string& passphrase);

bool rsaEncryptString(EVP_PKEY* publicKey, const std::string& plaintext, std::string& result);
bool rsaDecryptString(EVP_PKEY* privateKey, const std::string& ciphertext, std::string& result);

std::string rsaKeyToString(EVP_PKEY* privateKey);

bool rsaEncryptFile(const std::string& targetFile, const std::string& pubkeyPath);
bool rsaDecryptFile(const std::string& targetFile, const std::string& privkeyPath, const std::string& pass);

}

