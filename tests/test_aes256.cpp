#include <gtest/gtest.h>

#include <Components/Encryption/AES-256.h>

// test_encryption.cpp
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <random>
#include <string>

#ifdef QT_CORE_LIB
#include <QByteArray>
#endif

namespace {

std::string randomBytes(std::size_t len) {
    static std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, 255);
    std::string s(len, '\0');
    std::generate(s.begin(), s.end(),
                  [&] { return static_cast<char>(dist(rng)); });
    return s;
}

std::string freshKey() {
    return Encryption::generateKey(32);
}

void expectRoundTrip(const std::string& input) {
    const std::string key    = freshKey();
    const std::string cipher = Encryption::aes256encrypt(input, key);
    if (!input.empty()) {
        EXPECT_FALSE(cipher.empty()) << "encrypt() returned empty for non-empty input";
    }
    EXPECT_EQ(Encryption::aes256decrypt(cipher, key), input);
}

#ifdef QT_CORE_LIB
void expectRoundTrip(const QByteArray& input) {
    const QByteArray key    = QByteArray::fromStdString(freshKey());
    const QByteArray cipher = Encryption::qtEncryptAes256Cbc(input, key);
    if (!input.isEmpty()) {
        EXPECT_FALSE(cipher.isEmpty()) << "qtEncryptAes256Cbc() returned empty";
    }
    EXPECT_EQ(Encryption::qtDecryptAes256Cbc(cipher, key), input);
}
#endif

}  // namespace

// ===========================================================================
// Round-trip: одна строка DEFINE_ENCRYPTION_ROUNDTRIP(...) -> два TEST'а.
//
// Аргументы после имени — это аргументы конструктора контейнера.
//   DEFINE_ENCRYPTION_ROUNDTRIP(Small, "hello")   -> std::string("hello")
//   DEFINE_ENCRYPTION_ROUNDTRIP(B16,   16, 'A')   -> std::string(16, 'A')
// ===========================================================================

#ifdef QT_CORE_LIB
#define DEFINE_ENCRYPTION_ROUNDTRIP(Name, ...)                                     \
TEST(Encryption, Std##Name) { expectRoundTrip(std::string(__VA_ARGS__)); }     \
    TEST(Encryption, Qt##Name)  { expectRoundTrip(QByteArray(__VA_ARGS__)); }
#else
#define DEFINE_ENCRYPTION_ROUNDTRIP(Name, ...)                                     \
TEST(Encryption, Std##Name) { expectRoundTrip(std::string(__VA_ARGS__)); }
#endif

// --- Кейсы. Добавляй новые одной строкой. ----------------------------------

DEFINE_ENCRYPTION_ROUNDTRIP(SmallString,      "hello")
DEFINE_ENCRYPTION_ROUNDTRIP(EmptyString,      "")
DEFINE_ENCRYPTION_ROUNDTRIP(SingleByte,       "x")
DEFINE_ENCRYPTION_ROUNDTRIP(NullByteOnly,     1, '\0')
DEFINE_ENCRYPTION_ROUNDTRIP(FifteenBytes,     15, 'A')      // меньше блока
DEFINE_ENCRYPTION_ROUNDTRIP(SixteenBytes,     16, 'A')      // ровно блок
DEFINE_ENCRYPTION_ROUNDTRIP(SeventeenBytes,   17, 'A')      // +1 к блоку
DEFINE_ENCRYPTION_ROUNDTRIP(ThirtyTwoBytes,   32, 'A')
DEFINE_ENCRYPTION_ROUNDTRIP(Utf8Cyrillic,     "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82")

// ===========================================================================
// Случайные бинарные данные (в т.ч. с нулями) на разных длинах.
// ===========================================================================

TEST(Encryption, StdRandomBinaryRoundTrip) {
    for (std::size_t len : {std::size_t{1}, std::size_t{7}, std::size_t{16},
                            std::size_t{32}, std::size_t{100}, std::size_t{1000},
                            std::size_t{4096}}) {
        expectRoundTrip(randomBytes(len));
    }
}

#ifdef QT_CORE_LIB
TEST(Encryption, QtRandomBinaryRoundTrip) {
    for (std::size_t len : {std::size_t{1}, std::size_t{7}, std::size_t{16},
                            std::size_t{32}, std::size_t{100}, std::size_t{1000},
                            std::size_t{4096}}) {
        const std::string s = randomBytes(len);
        expectRoundTrip(QByteArray(s.data(), static_cast<int>(s.size())));
    }
}
#endif

TEST(Encryption, StdWrongKeyDoesNotRecoverPlaintext) {
    const std::string key      = freshKey();
    const std::string otherKey = freshKey();
    const std::string plain    = "top secret payload";
    const std::string cipher   = Encryption::aes256encrypt(plain, key);
    EXPECT_NE(Encryption::aes256decrypt(cipher, otherKey), plain);
}

#ifdef QT_CORE_LIB
TEST(Encryption, QtWrongKeyDoesNotRecoverPlaintext) {
    const QByteArray key      = QByteArray::fromStdString(freshKey());
    const QByteArray otherKey = QByteArray::fromStdString(freshKey());
    const QByteArray plain    = "top secret payload";
    const QByteArray cipher   = Encryption::qtEncryptAes256Cbc(plain, key);
    EXPECT_NE(Encryption::qtDecryptAes256Cbc(cipher, otherKey), plain);
}
#endif

TEST(Encryption, GenerateKeyReturnsRequestedLength) {
    for (std::size_t len : {std::size_t{1}, std::size_t{8}, std::size_t{16},
                            std::size_t{32}, std::size_t{64}}) {
        EXPECT_EQ(Encryption::generateKey(len).size(), len);
    }
}

TEST(Encryption, GenerateKeyIsNotConstant) {
    // Крайне маловероятное совпадение; ловит "всегда возвращает одно и то же".
    EXPECT_NE(Encryption::generateKey(32), Encryption::generateKey(32));
}

TEST(Encryption, FixKeyAlwaysProduces32Bytes) {

    std::string sample = "";
    auto sampledSize = Encryption::fixKey(sample).size();
    EXPECT_EQ(sampledSize, std::size_t{32});

    sample = "str";
    sampledSize = Encryption::fixKey(sample).size();
    EXPECT_EQ(sampledSize, std::size_t{32});

    sample = randomBytes(300);
    sampledSize = Encryption::fixKey(sample).size();
    EXPECT_EQ(sampledSize, std::size_t{32});
}