#pragma once

/// **************************************************************************** ///
/// ******************* Advanced Encryption Standard (AES) ********************* ///
/// **************************************************************************** ///

#include <string>
#include <optional>

#include "common.hpp"

namespace Encryption {

/**
 * @brief aes256encrypt     Зашифровать текст с помощью AES-256-CBC
 * @param input             Текст для шифрования
 * @param key               Ключ для дешифрования, 32 байт
 * @return                  Зашифрованный текст или пустая std::string при ошибке
 */
std::optional<std::string> aes256_cbc_encrypt(const std::string& input, const std::string& key);

/**
 * @brief aes256decrypt     Дешифровать зашифрованный с помощью AES-256-CBC текст
 * @param input             Текст для дешифровки
 * @param key               Ключ для дешифрования, 32 байт
 * @return                  Зашифрованный текст или пустая std::string при ошибке
 */
std::optional<std::string> aes256_cbc_decrypt(const std::string& input, const std::string& key);


/**
 * @brief aes256encrypt     Зашифровать текст с помощью AES-256-GCM
 * @param input             Текст для шифрования
 * @param key               Ключ для дешифрования, 32 байт
 * @param aad               Additional Authenticated Data (AAD)
 * @return                  Зашифрованный текст или пустая std::string при ошибке
 */
std::optional<std::string> aes256_gcm_encrypt(const std::string& input, const std::string& key, const std::string& aad = {});

/**
 * @brief aes256decrypt     Дешифровать зашифрованный с помощью AES-256-GCM текст
 * @param input             Текст для дешифровки
 * @param key               Ключ для дешифрования, 32 байт
 * @param aad               Additional Authenticated Data (AAD)
 * @return                  Зашифрованный текст или пустая std::string при ошибке
 */
std::optional<std::string> aes256_gcm_decrypt(const std::string& input, const std::string& key, const std::string& aad = {});

}  // namespace Encryption
