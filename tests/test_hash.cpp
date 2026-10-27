#include <gtest/gtest.h>

#include <Components/Encryption/Hash.h>
#include <Components/Filework/TemporaryFile.h>

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
    {
        std::string testFile {"./test.txt"};
        auto deleter = [&](auto*) {
            if (std::filesystem::exists(testFile)) {
                std::filesystem::remove(testFile);
            }
        };
        std::unique_ptr<void, decltype(deleter)> {reinterpret_cast<void*>(1), deleter};

        {
            std::fstream tmpFile(testFile, std::ios_base::in | std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
            ASSERT_TRUE(tmpFile.is_open()) << "Failed to open temporary file: " << strerror(errno);
            tmpFile << hashInput;
            tmpFile.flush();
        }

        res = Encryption::sha256file(testFile);
    }
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