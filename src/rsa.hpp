#pragma once

/// **************************************************************************** ///
/// *********************** Rivest-Shamir-Adleman (RSA) ************************ ///
/// **************************************************************************** ///

#include <string>
#include <vector>

struct rsa_st;
using RSA = rsa_st;

namespace Encryption
{

/** @brief Generates RSA keypair
 *
 * @param rsa_key RSA**
 * @return void
 *
 */
void generate_rsa_keypair(RSA** rsa_key);

/** @brief Makes string with public key from generated key
 *
 * @param rsa_key RSA*
 * @return std::string
 *
 */
std::string rsa_public_key_to_string(RSA* rsa_key);

/** @brief Gets RSA public key from string
 *
 * @param public_key_str std::string&
 * @return RSA*
 *
 */
RSA* rsa_public_key_from_string(std::string & public_key_str);

/** @brief Saves RSA private key to file
 *
 * @param rsa_key RSA*
 * @param filename const std::string&
 * @return bool
 *
 */
bool savePrivateKey(RSA* rsa_key, const std::string& filename);

/** @brief Loads RSA public key from file
 *
 * @param filename const std::string&
 * @return RSA*
 *
 */
RSA* loadPublicKey(const std::string& filename);

/** @brief Saves RSA public key to file
 *
 * @param rsa_key RSA*
 * @param filename const std::string&
 * @return bool
 *
 */
bool savePublicKey(RSA* rsa_key, const std::string& filename);

/** @brief Loads RSA private key from file
 *
 * @param filename const std::string&
 * @return RSA*
 *
 */
RSA* loadPrivateKey(const std::string& filename);

/** @brief Encrypts string using RSA algorithm
 *
 * @param message const std::string&
 * @param rsa_key RSA*
 * @param encryptedMessage std::string&
 * @return bool
 *
 */
bool rsa_encrypt(const std::string & message, RSA* rsa_key, std::string & encryptedMessage);

/** @brief Encrypts string using RSA algorithm
 *
 * @param message const std::vector<char>
 * @param rsa_key RSA*
 * @param encryptedMessage char*
 * @return bool
 *
 */
bool rsa_encrypt(const std::vector<char> message, RSA* rsa_key, char * encryptedMessage);

/** @brief Decrypts message from encrypted by RSA
 *
 * @param encrypted_message const std::string&
 * @param rsa_key RSA*
 * @param decryptedMessage std::string&
 * @return bool
 *
 */
bool rsa_decrypt(const std::string & encrypted_message, RSA* rsa_key, std::string & decryptedMessage);

/** @brief Decrypts message from encrypted by RSA
 *
 * @param encryptedMessage const std::vector<char>
 * @param rsa_key RSA*
 * @param decryptedMessage char*
 * @return bool
 *
 */
bool rsa_decrypt(const std::vector<char> encryptedMessage, RSA* rsa_key, char * decryptedMessage);

/** @brief Encrypts file and creates 2 files .pem with keys
 *
 * @param inputPath const std::string&
 * @param outputPath const std::string&
 * @param pubKeyPath const std::string&
 * @param privKeyPath const std::string&
 * @return void
 *
 */
void encryptFileRSA(const std::string & inputPath, const std::string & outputPath, const std::string & pubKeyPath, const std::string & privKeyPath);

/** @brief Decrypts file using private key .pem file
 *
 * @param inputPath const std::string&
 * @param outputPath const std::string&
 * @param privKeyPath const std::string&
 * @return void
 *
 */
void decryptFileRSA(const std::string & inputPath, const std::string & outputPath, const std::string & privKeyPath);

}

