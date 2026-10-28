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
 * @brief glueFiles     Glue files into one
 * @param fileA
 * @param fileB
 * @param resultFile    Filename for result
 * @return
 */
bool glueFiles(const std::string& fileA, const std::string& fileB, const std::string& resultFile);

/**
 * @brief splitGluedFiles   Split glued files. Will save files just as named on calling glueFiles() function
 * @param inputFile         File to split
 * @param fileA             Output file A (same as fileA in glueFiles() )
 * @param fileB             Output file B (same as fileB in glueFiles() )
 * @return
 */
bool splitGluedFiles(const std::string& inputFile, const std::string &fileA, const std::string &fileB);

}  // namespace Encryption
