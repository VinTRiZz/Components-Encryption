#include <gtest/gtest.h>

#include <Components/Encryption/Hash.h>
#include <Components/Filework/TemporaryFile.h>

#include "hash.cpp"

#include <filesystem>
#include <fstream>

namespace {

const auto TEST_TEXT_SMALL  {"lgdighnkdaWdwwwwahdkla"};
const auto TEST_SUM_SMALL   {"3c7d7591638fead5296c51d770ff986db618e3aee9efbf585950fd95785ace86"};

const auto TEST_TEXT_64     {"123aiufo3uypypqhg9q3ph97f4h3qashikufgwaiylgdighnkdaWdwwwwahdkla"};
const auto TEST_SUM_64      {"fe6a24ed24bd0eee28d17c8075049d5fe0f9f2da118033968259d55fc613d296"};

const auto TEST_TEXT_BIG    {"123aiufa;ljklajwvelkfvhawkfhbk,jergkjshlfah fukwhfkuwaehgfluawo3uypypqhg9q3ph97f4h3qashikufgwaiylgdighnkdaWdwwwwahdkla"};
const auto TEST_SUM_BIG     {"fb2157025a77ba0214be02ff7aef8d62469e7bf35ed766143f8826f1e925b0f8"};


void checkHash(const std::string& hashInput, const std::string& expectedHash) {
    auto res = Encryption::sha256(hashInput);
    ASSERT_TRUE(res.has_value()) << Encryption::getEncryptionErrorText();
    ASSERT_EQ(expectedHash, res.value());
}

void checkHashFile(const std::string& hashInput, const std::string& expectedHash) {
    decltype(Encryption::sha256file({})) res;
    Filework::TemporaryFile tmpFile;
    tmpFile << hashInput;
    tmpFile.flush();

    res = Encryption::sha256file(tmpFile.getFilename());
    ASSERT_TRUE(res.has_value()) << Encryption::getEncryptionErrorText();
    ASSERT_EQ(expectedHash, res.value());
}

}

TEST(Components_Encryption, SHA256) {
    checkHash(TEST_TEXT_SMALL,  TEST_SUM_SMALL);
    checkHash(TEST_TEXT_64,     TEST_SUM_64);
    checkHash(TEST_TEXT_BIG,    TEST_SUM_BIG);
}

TEST(Components_Encryption, SHA256_files) {
    checkHashFile(TEST_TEXT_SMALL,  TEST_SUM_SMALL);
    checkHashFile(TEST_TEXT_64,     TEST_SUM_64);
    checkHashFile(TEST_TEXT_BIG,    TEST_SUM_BIG);
}

// ===================================== //
// File glue //

struct SaveTestCase {
    uint64_t value;
    const char* description;
};
TEST(Components_Encryption, GLUE_endian) {
    const std::vector<SaveTestCase> test_cases = {
        { 0x0000000000000000ULL, "0 bits" },
        { 0xFFFFFFFFFFFFFFFFULL, "All 1" },

        { 0x00000000000000FFULL, "1st byte max" },
        { 0x0000000000000100ULL, "2nd byte max" },
        { 0x000000000000FFFFULL, "3rd byte max" },
        { 0x0000000000010000ULL, "3rd byte max +" },
        { 0x00000000FFFFFFFFULL, "4 byte max" },
        { 0x0000000100000000ULL, "5 byte min" },

        { 0x0102030405060708ULL, "Ordered bytes" },
        { 0xAA55AA55AA55AA55ULL, "Subordered bytes" },
        { 0x55AA55AA55AA55AAULL, "Inverted subordered bytes" },
        { 0xF0F0F0F0F0F0F0F0ULL, "Nibbles" },

        { 0x8000000000000000ULL, "Sign byte" },
        { 0x0000000000000001ULL, "Lowest sense byte" },
        { 0x7FFFFFFFFFFFFFFFULL, "int64_t max" }
    };

    for (const auto& [testValue, testDescription] : test_cases) {
        auto converted = Encryption::serializeValue(testValue);
        auto deconverted = Encryption::deserializeValue(converted);
        ASSERT_EQ(testValue, deconverted) << "Failed serialization case:" << testDescription;
    }
}

TEST(Components_Encryption, GLUE_metadata) {
    Filework::TemporaryFile tmpf;
    const auto byteCount = 10000;
    tmpf.write(Encryption::generateSymbols(byteCount).c_str(), byteCount);
    tmpf.flush();

    auto meta = Encryption::createFileMetadata(std::string(tmpf.getFilename()));
    auto fileSize = Encryption::getFilesize(meta);
    ASSERT_EQ(tmpf.size(), fileSize);
}

TEST(Components_Encryption, GLUE_glueFiles) {
    const std::string testDataA = "12345";
    Filework::TemporaryFile tmpA;
    tmpA << testDataA;
    tmpA.flush();

    const std::string testDataB = "67890";
    Filework::TemporaryFile tmpB;
    tmpB << testDataB;
    tmpB.flush();

    const auto testGluedData = testDataA + testDataB;
    const auto sumData = testGluedData.size() + Encryption::GLUE_METADATA_SIZE * 2;

    const std::string resultFile {"./test_glued.bin"};
    if (std::filesystem::exists(resultFile)) {
        std::filesystem::remove(resultFile);
    }
    ASSERT_TRUE(Encryption::glueFiles(std::string(tmpA.getFilename()),
                                      std::string(tmpB.getFilename()),
                                      resultFile));
    ASSERT_EQ(sumData, std::filesystem::file_size(resultFile));

    std::ifstream tmpRes(resultFile, std::ios_base::in | std::ios_base::binary);
    ASSERT_TRUE(tmpRes.is_open());

    // Check data written
    char buffer[sumData];
    auto readBytes = tmpRes.readsome(buffer, sumData);
    tmpRes.close();
    std::filesystem::remove(resultFile);
    ASSERT_EQ(sumData, readBytes);
}



// ======================================================== //
void testFile(const uint64_t fileSizeA, const uint64_t fileSizeB) {
    const std::string testDataA = Encryption::generateBytes(fileSizeA);
    const std::string testDataB = Encryption::generateBytes(fileSizeB);
    const std::string resultFile {"./test_glued.bin"};
    const std::string fileA {"./test_A.txt"};
    const std::string fileB {"./test_B.txt"};

    if (std::filesystem::exists(resultFile)) {
        std::filesystem::remove(resultFile);
    }
    if (std::filesystem::exists(fileA)) {
        std::filesystem::remove(fileA);
    }
    if (std::filesystem::exists(fileB)) {
        std::filesystem::remove(fileB);
    }

    { // COPY OF UPPER TEST
        Filework::TemporaryFile tmpA;
        tmpA.write(testDataA.c_str(), testDataA.size());
        tmpA.flush();

        Filework::TemporaryFile tmpB;
        tmpB.write(testDataB.c_str(), testDataB.size());
        tmpB.flush();

        const auto testGluedData = testDataA + testDataB;
        const auto sumData = testGluedData.size() + Encryption::GLUE_METADATA_SIZE * 2;

        ASSERT_TRUE(Encryption::glueFiles(std::string(tmpA.getFilename()),
                                          std::string(tmpB.getFilename()),
                                          resultFile));
        ASSERT_EQ(sumData, std::filesystem::file_size(resultFile));

        std::ifstream tmpRes(resultFile, std::ios_base::in | std::ios_base::binary);
        ASSERT_TRUE(tmpRes.is_open());

        // Check data written
        char buffer[sumData];
        auto readBytes = tmpRes.readsome(buffer, sumData);
        tmpRes.close();
        ASSERT_EQ(sumData, readBytes);
    }

    ASSERT_TRUE(Encryption::splitGluedFiles(resultFile, fileA, fileB));

    {
        std::ifstream tmpRes(fileA, std::ios_base::in | std::ios_base::binary);
        ASSERT_TRUE(tmpRes.is_open());

        // Check data written
        char buffer[testDataA.size()];
        auto readBytes = tmpRes.readsome(buffer, testDataA.size());
        tmpRes.close();
        ASSERT_EQ(testDataA.size(), readBytes);
        ASSERT_EQ(testDataA, std::string(buffer, testDataA.size()));
        ASSERT_EQ(testDataA.size(), std::filesystem::file_size(fileA));
    }

    {
        std::ifstream tmpRes(fileB, std::ios_base::in | std::ios_base::binary);
        ASSERT_TRUE(tmpRes.is_open());

        // Check data written
        char buffer[testDataB.size()];
        auto readBytes = tmpRes.readsome(buffer, testDataB.size());
        tmpRes.close();
        ASSERT_EQ(testDataB.size(), readBytes);
        ASSERT_EQ(testDataB, std::string(buffer, testDataB.size()));
        ASSERT_EQ(testDataB.size(), std::filesystem::file_size(fileB));
    }
}


TEST(Components_Encryption, GLUE_splitFiles) {
    testFile(0, 0);
    testFile(10, 10);
    testFile(30, 0);
    testFile(0, 30);
    testFile(500, 500);
    testFile(12345, 54321);
}

