#pragma once

/// **************************************************************************** ///
/// ******************* Advanced Encryption Standard (AES) ********************* ///
/// **************************************************************************** ///

#ifdef QT_CORE_LIB
#include <QByteArray>
#endif // QT_CORE_LIB

#include <string>

#include "common.hpp"

namespace Encryption {

std::string generateKey(size_t lengthByte);

std::string fixKey(const std::string& key);

/**
 * @brief aes256encrypt     Зашифровать текст с помощью AES-256
 * @param input             Текст для шифрования
 * @param key               Ключ для дешифрования, 32 байт
 * @return                  Зашифрованный текст или пустая std::string при ошибке
 */
std::string aes256encrypt(const std::string& input, const std::string& key);

/**
 * @brief aes256decrypt     Дешифровать зашифрованный с помощью AES-256 текст
 * @param input             Текст для дешифровки
 * @param key               Ключ для дешифрования, 32 байт
 * @return                  Зашифрованный текст или пустая std::string при ошибке
 */
std::string aes256decrypt(const std::string& input, const std::string& key);


#ifdef QT_CORE_LIB
/**
 * @brief qtEncryptAes256Cbc    Зашифровать текст с помощью AES-256
 * @param plainText             Текст для шифрования
 * @param key                   Ключ для дешифрования, 32 байт
 * @return                      Зашифрованный текст или NULL QByteArray при ошибке
 */
QByteArray qtEncryptAes256Cbc(const QByteArray& plainText, QByteArray key);

/**
 * @brief qtDecryptAes256Cbc    Дешифровать зашифрованный с помощью AES-256 текст
 * @param plainText             Текст для дешифрования
 * @param key                   Ключ для дешифрования, 32 байт
 * @return                      Дешифрованный текст или NULL QByteArray при ошибке
 */
QByteArray qtDecryptAes256Cbc(const QByteArray& cipherText, QByteArray key);
#endif // QT_CORE_LIB

}  // namespace Encryption
