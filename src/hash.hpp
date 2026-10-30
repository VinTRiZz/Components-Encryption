#pragma once

#include <string>
#include <optional>

#include "common.hpp"

namespace Encryption {

/**
 * @brief sha256    Вычислить хеш по функции SHA-256
 * @param input     Входной массив байт (или текст)
 * @return          Хеш (64 байт)
 */
std::optional<std::string> sha256(const std::string_view& input);

/**
 * @brief sha256file    Вычислить хеш данных файла
 * @param filepath
 * @return
 */
std::optional<std::string> sha256file(const std::string_view& filepath);

/**
 * @brief The SensitiveDataHash class Comparable object for sensitive data hashing
 */
struct SensitiveDataHash {
    std::string salt;
    std::string hash;

    bool isValid() const {
        return !(hash.empty() | salt.empty());
    }
};

/**
 * @brief hashSensitiveData Create hash using sensitive data, using PBKDF2-HMAC-SHA256 algorithm
 * @param sensitiveData
 * @return                  Comparable object
 */
SensitiveDataHash hashSensitiveData(std::string&& sensitiveData);

}  // namespace Encryption
