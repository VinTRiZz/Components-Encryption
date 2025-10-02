#include "encoding.hpp"

#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <boost/algorithm/hex.hpp>

// Common OpenSSL
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace Encryption
{

std::string encodeBase64(const std::string &input)
{
    BIO *bio, *b64;
    BUF_MEM* bufferPtr;

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

std::string decodeBase64(const std::string &input)
{
    BIO *bio, *b64;
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

std::string encodeHex(const std::string& input)
{
    std::string convertedStr;
    convertedStr.reserve(input.size());
    boost::algorithm::hex(input.begin(), input.end(), std::back_inserter(convertedStr));
    return convertedStr;
}

std::string decodeHex(const std::string& input)
{
    std::string convertedStr;
    convertedStr.reserve(input.size());
    boost::algorithm::unhex(input, std::back_inserter(convertedStr));
    return convertedStr;
}

}
