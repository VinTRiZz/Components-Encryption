#include "hash.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <iomanip>
#include <fstream>
#include <memory>
#include <filesystem>

#include <Components/Filework/TemporaryFile.h>

#include "gluefilemetadata.hpp"

// OpenSSL engine implementation
#define OPENSSL_ENGINE NULL

namespace Encryption {

std::optional<std::string> sha256(const std::string_view &input)
{
    if (input.empty()) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalInvalidValue,
                           "[SHA-256] input",
                           "Empty input");
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_MD_CTX_new",
                           std::string("Failed to create context of SHA-256: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestInit_ex",
                           std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    if (EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestUpdate",
                           std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestFinal_ex",
                           std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}



std::optional<std::string> sha256file(const std::string_view &filepath)
{
    if (!std::filesystem::exists(filepath)) {
        setEncryptionError(ExtraClasses::ErrorCode::SystemFileError,
                           "[SHA-256] file",
                           std::string("SHA-256 sum failed: No such file or directory: ") + filepath.data());
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_MD_CTX_new",
                           std::string("Failed to create EVP_MD_CTX: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestInit_ex",
                           std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    std::ifstream inputFile(filepath.data());
    const auto bufsize = 1024;
    char readbuf[bufsize] {};
    auto readCnt = inputFile.readsome(readbuf, bufsize);
    while (readCnt > 0) {
        if (EVP_DigestUpdate(context.get(), readbuf, readCnt) != 1) {
            setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestUpdate",
                           std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr));
            return {};
        }
        readCnt = inputFile.readsome(readbuf, bufsize);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalHashFailed,
                           "[SHA-256] EVP_DigestFinal_ex",
                           std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr));
        return {};
    }

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// =============================================== //
// File glueing

static std::pair<GlueFileMetadata, GlueFileMetadata> readFilesMetadata(const std::string& inputFile) {
    if (!std::filesystem::exists(inputFile)) {
        setEncryptionError(ExtraClasses::SystemFileError,
                           "Glued files metadata read",
                           "Glued file not exist");
        return {};
    }

    std::ifstream ifile(inputFile, std::ios_base::in | std::ios_base::binary);
    if (!ifile.is_open()) {
        setEncryptionError(ExtraClasses::SystemFileError,
                           "Glued files metadata read",
                           "Failed to open glued file");
        return {};
    }

    char readBuffer[GLUE_METADATA_SIZE * 2];
    auto readBytes = ifile.readsome(readBuffer, GLUE_METADATA_SIZE * 2);
    if (GLUE_METADATA_SIZE * 2 != readBytes) {
        setEncryptionError(ExtraClasses::SystemFileError,
                           "Read glued files metadata",
                           "Failed to read expected amount of bytes");
        return {};
    }

    std::pair<GlueFileMetadata, GlueFileMetadata> res;
    res.first.initFromString(std::string(readBuffer, GLUE_METADATA_SIZE));
    if (!res.first.isValid()) { return {}; }

    res.second.initFromString(std::string(readBuffer + GLUE_METADATA_SIZE, GLUE_METADATA_SIZE));
    if (!res.second.isValid()) { return {}; }

    return res;
}

bool glueFiles(const std::string &fileA, const std::string &fileB, const std::string &resultFile)
{
    if (!std::filesystem::exists(fileA) || !std::filesystem::exists(fileB)) {
        setEncryptionError(ExtraClasses::SystemFileError,
                           "Glue files",
                           "Failed to open input files");
        return false;
    }

    // Get metadata of file A
    const auto metadataFileA = GlueFileMetadata::fromFile(fileA);
    if (!metadataFileA.isValid()) { return false; }
    const auto metadataFileA_serialized = metadataFileA.toString();
    if (metadataFileA_serialized.empty()) { return false; }

    // Get metadata of file B
    const auto metadataFileB = GlueFileMetadata::fromFile(fileB);
    if (!metadataFileB.isValid()) { return false; }
    const auto metadataFileB_serialized = metadataFileB.toString();
    if (metadataFileB_serialized.empty()) { return false; }

    // Save metadata
    Filework::TemporaryFile ofile(resultFile);
    ofile.write(metadataFileA_serialized.c_str(), metadataFileA_serialized.size());
    ofile.flush();
    ofile.write(metadataFileB_serialized.c_str(), metadataFileB_serialized.size());
    ofile.flush();

    // Save both files data
    auto appendFileData = [&ofile](const std::string& iFile) -> bool {
        std::ifstream ifile(iFile, std::ios_base::in | std::ios_base::binary);
        if (!ifile.is_open()) {
            setEncryptionError(ExtraClasses::SystemFileError,
                               "Read glued files",
                               "Failed to open input file A");
            return false;
        }
        const auto expectedSize = std::filesystem::file_size(iFile);
        std::size_t writtenSize {};

        const auto bufferSize = 4096;
        char readBuffer[bufferSize];
        auto readBytes = ifile.readsome(readBuffer, bufferSize);
        while (readBytes > 0) {
            ofile.write(readBuffer, readBytes);
            ofile.flush();
            writtenSize += readBytes;
            readBytes = ifile.readsome(readBuffer, bufferSize);
        }
        auto res = (expectedSize == writtenSize);
        if (ifile.bad() || !res) {
            setEncryptionError(ExtraClasses::SystemFileError,
                               "Read glued files",
                               std::string("Failed to read part of input file ") + iFile);
            return false;
        }
        return true;
    };
    auto isWritten = appendFileData(fileA);
    if (!isWritten) { return false; }

    isWritten = appendFileData(fileB);
    if (!isWritten) { return false; }

    ofile.accept();
    return true;
}

bool splitGluedFiles(const std::string &inputFile, const std::string& fileA, const std::string& fileB)
{
    if (!std::filesystem::exists(inputFile)) {
        setEncryptionError(ExtraClasses::SystemFileError,
                           "Glued file read",
                           "Glued file not exist");
        return false;
    }

    const auto filesMetadata = readFilesMetadata(inputFile);
    if (!filesMetadata.first.isValid() || !filesMetadata.second.isValid()) {
        return false;
    }

    std::ifstream gluedFile(inputFile, std::ios_base::in | std::ios_base::binary);
    if (!gluedFile.is_open()) {
        setEncryptionError(ExtraClasses::SystemFileError,
                           "Glued file read",
                           "Failed to open glued file");
        return false;
    }
    gluedFile.seekg(GLUE_METADATA_SIZE * 2, std::ios_base::beg);

    auto extractFileData = [&gluedFile](const std::string& iFile, const GlueFileMetadata& fileMetadata) -> bool {
        std::ofstream ofile(iFile, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
        if (!ofile.is_open()) {
            setEncryptionError(ExtraClasses::SystemFileError,
                               "Create glued file output",
                               std::string("Failed to glued source file ") + iFile);
            return false;
        }
        auto expectedSize = fileMetadata.fileSize;

        const uint64_t bufferSize = 4096;
        char readBuffer[bufferSize];
        auto readBytes = gluedFile.readsome(readBuffer, std::min(bufferSize, expectedSize));
        while (readBytes > 0) {
            expectedSize -= readBytes;
            ofile.write(readBuffer, readBytes);
            ofile.flush();
            readBytes = gluedFile.readsome(readBuffer, std::min(bufferSize, expectedSize));
        }
        if (expectedSize > 0) {
            setEncryptionError(ExtraClasses::SystemFileError,
                               "Create glued file output",
                               std::string("Failed to glued source file ") + iFile);
            return false;
        }
        return (fileMetadata.fileHash == sha256file(iFile));
    };
    auto isExtracted = extractFileData(fileA, filesMetadata.first);
    if (!isExtracted) { return false; }

    isExtracted = extractFileData(fileB, filesMetadata.second);
    if (!isExtracted) { return false; }

    return true;
}

}  // namespace Encryption
