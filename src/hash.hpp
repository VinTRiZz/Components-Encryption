#pragma once

#include <QByteArray>

namespace Encryption {

/**
 * @brief sha256    Вычислить хеш по функции SHA-256
 * @param txt       Входной массив байт (или текст)
 * @return          Хеш (64 байт)
 */
QByteArray sha256(QByteArray txt);

}  // namespace Encryption
