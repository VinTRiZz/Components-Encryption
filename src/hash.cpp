#include "hash.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <iomanip>
#include <fstream>
#include <algorithm>
#include <memory>
#include <filesystem>
#include <array>

#include <Components/Filework/TemporaryFile.h>

// OpenSSL engine implementation
#define OPENSSL_ENGINE NULL

namespace Encryption {

std::optional<std::string> sha256(const std::string_view &input)
{
    if (input.empty()) {
        global_encryptionErrorText = "Empty input";
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        global_encryptionErrorText = std::string("Failed to create context of SHA-256") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    if (EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr);
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
        global_encryptionErrorText = std::string("SHA-256 sum failed: No such file or directory: ") + filepath.data();
        return {};
    }

    std::shared_ptr<EVP_MD_CTX> context(EVP_MD_CTX_new(), [](auto* ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    });
    if (!context) {
        global_encryptionErrorText = std::string("Failed to create EVP_MD_CTX") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum init failed: ") + ERR_error_string(ERR_get_error(), nullptr);
        return {};
    }

    std::ifstream inputFile(filepath.data());
    const auto bufsize = 1024;
    char readbuf[bufsize] {};
    auto readCnt = inputFile.readsome(readbuf, bufsize);
    while (readCnt > 0) {
        if (EVP_DigestUpdate(context.get(), readbuf, readCnt) != 1) {
            global_encryptionErrorText = std::string("SHA-256 sum data adding failed: ") + ERR_error_string(ERR_get_error(), nullptr);
            return {};
        }
        readCnt = inputFile.readsome(readbuf, bufsize);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context.get(), hash, &lengthOfHash) != 1) {
        global_encryptionErrorText = std::string("SHA-256 sum finalize failed: ") + ERR_error_string(ERR_get_error(), nullptr);
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

static std::array<uint8_t, 8> serializeValue(const uint64_t value) {
    return {
        static_cast<uint8_t>(value),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 32),
        static_cast<uint8_t>(value >> 40),
        static_cast<uint8_t>(value >> 48),
        static_cast<uint8_t>(value >> 56)
    };
}

static uint64_t deserializeValue(const std::array<uint8_t, 8>& bytes) {
    return static_cast<uint64_t>(bytes[0]) |
           (static_cast<uint64_t>(bytes[1]) << 8) |
           (static_cast<uint64_t>(bytes[2]) << 16) |
           (static_cast<uint64_t>(bytes[3]) << 24) |
           (static_cast<uint64_t>(bytes[4]) << 32) |
           (static_cast<uint64_t>(bytes[5]) << 40) |
           (static_cast<uint64_t>(bytes[6]) << 48) |
           (static_cast<uint64_t>(bytes[7]) << 56);
}


static const auto GLUE_METADATA_SIZE {136};
static std::string createFileMetadata(const std::string& inputFile) {
    if (!std::filesystem::exists(inputFile)) { return {}; }
    const auto fileSizeSerialized = serializeValue(std::filesystem::file_size(inputFile));
    const auto fileHash = sha256file(inputFile).value(); // Must NOT work without this data

    std::string metadata;
    std::copy_n(fileSizeSerialized.data(), fileSizeSerialized.size(), std::back_inserter(metadata));
    metadata += fileHash;

    const auto metadataHash = sha256(metadata).value(); // Must NOT work without this data
    metadata += metadataHash;

    if (metadata.size() != GLUE_METADATA_SIZE) {
        throw std::runtime_error("Failed to glue files: metadata size could not be calculated");
    }
    return metadata;
}

static std::size_t getFilesize(const std::string& fileMetadata) {
    auto metadata = std::string(fileMetadata.data(), GLUE_METADATA_SIZE - 64);
    auto metadataHash = std::string(fileMetadata.data() + GLUE_METADATA_SIZE - 64, 64);
    if (metadataHash != sha256(metadata)) {
        throw std::runtime_error("Failed to split files: invalid metadata");
    }
    std::array<uint8_t, 8> sizeSerialized {};
    std::copy_n(metadata.begin(), 8, sizeSerialized.begin());
    return deserializeValue(sizeSerialized);
}

static std::pair<uint64_t, uint64_t> readFilesMetadata(const std::string& inputFile) {
    if (!std::filesystem::exists(inputFile)) { return {}; }

    std::ifstream ifile(inputFile, std::ios_base::in | std::ios_base::binary);
    if (!ifile.is_open()) {
        return {};
    }

    char readBuffer[GLUE_METADATA_SIZE * 2];
    auto readBytes = ifile.readsome(readBuffer, GLUE_METADATA_SIZE * 2);
    if (GLUE_METADATA_SIZE * 2 != readBytes) {
        throw std::runtime_error("Failed to split files: no metadata found");
    }
    auto fileAsize = getFilesize(std::string(readBuffer, GLUE_METADATA_SIZE));
    auto fileBsize = getFilesize(std::string(readBuffer + GLUE_METADATA_SIZE, GLUE_METADATA_SIZE));

    return {fileAsize, fileBsize};
}

bool glueFiles(const std::string &fileA, const std::string &fileB, const std::string &resultFile)
{
    if (!std::filesystem::exists(fileA)) { return false; }
    if (!std::filesystem::exists(fileB)) { return false; }

    const auto metadataFileA = createFileMetadata(fileA);
    const auto metadataFileB = createFileMetadata(fileB);

    Filework::TemporaryFile ofile(resultFile);
    ofile.write(metadataFileA.c_str(), metadataFileA.size());
    ofile.flush();
    ofile.write(metadataFileB.c_str(), metadataFileB.size());
    ofile.flush();

    auto appendFileData = [&ofile](const std::string& iFile){
        std::ifstream ifile(iFile, std::ios_base::in | std::ios_base::binary);
        const auto bufferSize = 4096;
        char readBuffer[bufferSize];
        auto readBytes = ifile.readsome(readBuffer, bufferSize);
        while (readBytes > 0) {
            ofile.write(readBuffer, readBytes);
            ofile.flush();
            readBytes = ifile.readsome(readBuffer, bufferSize);
        }
    };
    appendFileData(fileA);
    appendFileData(fileB);

    ofile.accept();
    return true;
}

bool splitGluedFiles(const std::string &inputFile, const std::string& fileA, const std::string& fileB)
{
    if (!std::filesystem::exists(inputFile)) { return false; }

    const auto filesMetadata = readFilesMetadata(inputFile);

    std::ifstream gluedFile(inputFile, std::ios_base::in | std::ios_base::binary);
    if (!gluedFile.is_open()) { return false; }
    gluedFile.seekg(GLUE_METADATA_SIZE * 2, std::ios_base::beg);

    auto extractFileData = [&gluedFile](const std::string& iFile, uint64_t expectedSize){
        std::ofstream ofile(iFile, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
        const uint64_t bufferSize = 4096;
        char readBuffer[bufferSize];
        auto readBytes = gluedFile.readsome(readBuffer, std::min(bufferSize, expectedSize));
        while (readBytes > 0) {
            expectedSize -= readBytes;
            ofile.write(readBuffer, readBytes);
            ofile.flush();
            readBytes = gluedFile.readsome(readBuffer, std::min(bufferSize, expectedSize));
        }
    };
    extractFileData(fileA, filesMetadata.first);
    extractFileData(fileB, filesMetadata.second);

    return true;
}

}  // namespace Encryption
