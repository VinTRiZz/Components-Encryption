#pragma once

#include <QByteArray>

#include <string>

namespace Encryption {

/**
 * @brief qtSha256  Вычислить хеш по функции SHA-256
 * @param txt       Входной массив байт (или текст)
 * @return          Хеш (64 байт)
 */
QByteArray qtSha256(QByteArray txt);

/**
 * @brief sha256    Вычислить хеш по функции SHA-256
 * @param input     Входной массив байт (или текст)
 * @return          Хеш (64 байт)
 */
std::string sha256(const std::string& input);

}  // namespace Encryption
