#include "encoding.hpp"

#include <sstream>
#include <iconv.h>
#include <limits>

// Common OpenSSL
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace Encryption
{

namespace {

inline constexpr char kHexDigitsUpper[17] = "0123456789ABCDEF";
inline constexpr char kHexDigitsLower[17] = "0123456789abcdef";

struct HexNibbleTable {
    unsigned char v[256];

    constexpr HexNibbleTable() noexcept : v{} {
        for (auto& x : v) {
            x = 0xFFu;
        }
        for (unsigned i = 0; i < 10u; ++i) {
            v[static_cast<unsigned char>('0' + i)] = static_cast<unsigned char>(i);
        }
        for (unsigned i = 0; i < 6u; ++i) {
            v[static_cast<unsigned char>('A' + i)] = static_cast<unsigned char>(10u + i);
            v[static_cast<unsigned char>('a' + i)] = static_cast<unsigned char>(10u + i);
        }
    }
};
inline constexpr HexNibbleTable kHexNibble{};
}


std::optional<std::string> encodeBase64(const std::string &input)
{
    BIO *bio {}, *b64 {};
    BUF_MEM* bufferPtr {};

    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), static_cast<int>(input.length()));
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string output(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return output;
}

std::optional<std::string> decodeBase64(const std::string &input)
{
    BIO *bio {}, *b64 {};
    char* buffer = new char[input.size()];
    memset(buffer, 0, input.size());

    bio = BIO_new_mem_buf(input.c_str(), static_cast<int>(input.length()));
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer, static_cast<int>(input.size()));

    BIO_free_all(bio);

    std::string output(buffer, len);
    delete[] buffer;

    return output;
}

std::optional<std::string> encodeHex(const std::string& input, bool useUpperCase)
{
    if (input.size() > (std::numeric_limits<std::size_t>::max)() / 2u) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[HEX-ENC]",
                           "Result size overflow");
        return {};
    }

    const char* digits = useUpperCase ? kHexDigitsUpper : kHexDigitsLower;
    std::string out;
    out.resize(input.size() * 2u);

    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto b = static_cast<unsigned char>(input[i]);
        out[2 * i]     = digits[(b >> 4) & 0x0Fu];
        out[2 * i + 1] = digits[b & 0x0Fu];
    }
    return out;
}

std::optional<std::string> decodeHex(const std::string& input, bool useUpperCase)
{
    if (input.size() % 2u != 0u) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[HEX-DEC]",
                           "Invalid length (odd)");
        return {};
    }

    std::string out;
    out.resize(input.size() / 2u);

    const unsigned char wrongCaseLow  = useUpperCase ? 'a' : 'A';
    const unsigned char wrongCaseHigh = useUpperCase ? 'f' : 'F';

    for (std::size_t i = 0; i < out.size(); ++i) {
        const unsigned char hiChar = static_cast<unsigned char>(input[2u * i]);
        const unsigned char loChar = static_cast<unsigned char>(input[2u * i + 1u]);

        const bool wrongCase =
            (hiChar >= wrongCaseLow && hiChar <= wrongCaseHigh) ||
            (loChar >= wrongCaseLow && loChar <= wrongCaseHigh);

        const unsigned char hi = kHexNibble.v[hiChar];
        const unsigned char lo = kHexNibble.v[loChar];

        if (wrongCase || hi == 0xFFu || lo == 0xFFu) {
            setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                               "[HEX-DEC]",
                               "Invalid hex character");
            return {};
        }

        out[i] = static_cast<char>((hi << 4u) | lo);
    }
    return out;
}

std::optional<std::string> cp1251_to_utf8(const std::string_view &input)
{
    if (input.empty()) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalInvalidValue,
                           "[CP1251->UTF8] input",
                           "Empty input");
        return {};
    }

    iconv_t cd = iconv_open("UTF-8", "CP1251");
    if (cd == reinterpret_cast<iconv_t>(-1)) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[CP1251->UTF8] iconv_open",
                           std::string("Failed to open iconv descriptor: ") + std::strerror(errno));
        return {};
    }

    std::string output(input.size() * 3 + 1, '\0');
    char *inBuf = const_cast<char *>(input.data());
    size_t inBytesLeft = input.size();
    char *outBuf = output.data();
    size_t outBytesLeft = output.size();

    const size_t result = iconv(cd, &inBuf, &inBytesLeft, &outBuf, &outBytesLeft);
    struct IconvCloser {
        iconv_t descriptor;
        ~IconvCloser() {
            if (descriptor != reinterpret_cast<iconv_t>(-1)) {
                iconv_close(descriptor);
            }
        }
    } closer{cd};

    if (result == static_cast<size_t>(-1)) {
        std::stringstream ss;
        ss << "Conversion failed: " << std::strerror(errno);

        if (errno == EILSEQ) {
            ss << " (invalid CP1251 byte"
               << ", offset: " << (input.size() - inBytesLeft) << ")";
        } else if (errno == EINVAL) {
            ss << " (incomplete input sequence at end of input)";
        } else if (errno == E2BIG) {
            ss << " (output buffer too small)";
        }

        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[CP1251->UTF8] iconv",
                           ss.str());
        return {};
    }

    if (inBytesLeft != 0) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[CP1251->UTF8] iconv",
                           "Incomplete conversion: " + std::to_string(inBytesLeft) + " input byte(s) left");
        return {};
    }

    output.resize(outBuf - output.data());
    return output;
}

std::optional<std::string> utf8_to_cp1251(const std::string_view &input)
{
    if (input.empty()) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalInvalidValue,
                           "[UTF8->CP1251] input",
                           "Empty input");
        return {};
    }

    iconv_t cd = iconv_open("CP1251", "UTF-8");
    if (cd == reinterpret_cast<iconv_t>(-1)) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[UTF8->CP1251] iconv_open",
                           std::string("Failed to open iconv descriptor: ") + std::strerror(errno));
        return {};
    }

    std::string output(input.size() + 1, '\0');
    char *inBuf = const_cast<char *>(input.data());
    size_t inBytesLeft = input.size();
    char *outBuf = output.data();
    size_t outBytesLeft = output.size();

    const size_t result = iconv(cd, &inBuf, &inBytesLeft, &outBuf, &outBytesLeft);
    struct IconvCloser {
        iconv_t descriptor;
        ~IconvCloser() {
            if (descriptor != reinterpret_cast<iconv_t>(-1)) {
                iconv_close(descriptor);
            }
        }
    } closer{cd};

    if (result == static_cast<size_t>(-1)) {
        std::stringstream ss;
        ss << "Conversion failed: " << std::strerror(errno);

        if (errno == EILSEQ) {
            ss << " (invalid UTF-8 sequence or character not representable in CP1251"
               << ", offset: " << (input.size() - inBytesLeft) << ")";
        } else if (errno == EINVAL) {
            ss << " (incomplete UTF-8 sequence at end of input)";
        } else if (errno == E2BIG) {
            ss << " (output buffer too small)";
        }

        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[UTF8->CP1251] iconv",
                           ss.str());
        return {};
    }

    if (inBytesLeft != 0) {
        setEncryptionError(ExtraClasses::ErrorCode::LogicalEncodingFailed,
                           "[UTF8->CP1251] iconv",
                           "Incomplete conversion: " + std::to_string(inBytesLeft) + " input byte(s) left");
        return {};
    }

    output.resize(outBuf - output.data());
    return output;
}

}
