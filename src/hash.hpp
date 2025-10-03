#pragma once

#ifdef QT_CORE_LIB
#include <QByteArray>
#endif // QT_CORE_LIB

#include <string>

namespace Encryption {

#ifdef QT_CORE_LIB
/**
 * @brief qtSha256  Вычислить хеш по функции SHA-256
 * @param txt       Входной массив байт (или текст)
 * @return          Хеш (64 байт)
 */
QByteArray qtSha256(QByteArray txt);
#endif // QT_CORE_LIB

/**
 * @brief sha256    Вычислить хеш по функции SHA-256
 * @param input     Входной массив байт (или текст)
 * @return          Хеш (64 байт)
 */
std::string sha256(const std::string& input);

/**
 * @brief sha256file    Вычислить хеш данных файла
 * @param filepath
 * @return
 */
std::string sha256file(const std::string& filepath);

}  // namespace Encryption
