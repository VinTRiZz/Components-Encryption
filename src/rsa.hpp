#pragma once

/// **************************************************************************** ///
/// *********************** Rivest-Shamir-Adleman (RSA) ************************ ///
/// **************************************************************************** ///

#include <string>
#include <memory>
#include <optional>

#include "common.hpp"

struct rsa_st;
using RSA = rsa_st;

typedef struct evp_pkey_st EVP_PKEY; // For OpenSSL RSA

namespace Encryption
{

using RSAKeysPtr = std::shared_ptr<EVP_PKEY>;

// Key generating
RSAKeysPtr rsaGenerateKeys();

// Key save / load functions
bool rsaSavePublicKey(const RSAKeysPtr& pkey, const std::string& filename);
bool rsaSavePrivateKey(const RSAKeysPtr& pkey, const std::string& filename, const std::string& passphrase = {});
RSAKeysPtr rsaReadPublicKey(const std::string& filename);
RSAKeysPtr rsaReadPrivateKey(const std::string& filename, const std::string& passphrase = {});

// Encryption
std::optional<std::string> rsaEncryptString(const RSAKeysPtr& publicKey, const std::string& plaintext);
std::optional<std::string> rsaDecryptString(const RSAKeysPtr& privateKey, const std::string& ciphertext);

// PEM format only
std::string rsaKeyToString(const RSAKeysPtr& pubKey);
RSAKeysPtr rsaKeyFromString(const std::string& pubKey);

// File encryption
bool rsaEncryptFile(const std::string& targetFile, const RSAKeysPtr& pubkey);
bool rsaEncryptFile(const std::string& targetFile, const std::string& pubkeyPath);

// File decryption
bool rsaDecryptFile(const std::string& targetFile, const RSAKeysPtr& privkey);
bool rsaDecryptFile(const std::string& targetFile, const std::string& privkeyPath, const std::string& pass = {});

}

