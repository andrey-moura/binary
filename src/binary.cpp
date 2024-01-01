#include <uva/binary.hpp>

#ifdef __UVA_OPENSSL_FOUND__
    #include <openssl/sha.h>
    #include <openssl/evp.h>
    #include <openssl/hmac.h>
    #include <openssl/bio.h>
    #include <openssl/pem.h>
    #include <openssl/evp.h>
    #include <openssl/applink.c>

#endif

#include <uva.hpp>

static char hexadecimal_digits[16] { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
static std::string_view hexadecimal_digits_sv = (const char*)hexadecimal_digits;

uva::binary::binary_uint256_t::binary_uint256_t(int __integer)
{
    values.integers[INTEGER_256_INTEGERS-1] = __integer;
}

uva::binary::binary_uint256_t::binary_uint256_t(std::string_view str)
{
    from_string(str);
}

uva::binary::binary_uint256_t::binary_uint256_t(const char* str)
{
    from_string(std::string_view(str));
}

void uva::binary::binary_uint256_t::from_string(std::string_view str)
{
    if(str.size() % 2 != 0) {
        throw std::runtime_error(std::format("failed to convert {} to uint256_t: invalid format.", str));
    }

    const char* data = str.data();

    size_t index = 0;
    while(*data) {
        values.bytes[index] = byte_from_hex_string(data);
        data+=2;
        index++;
    }

    (void)str;
}

std::string uva::binary::binary_uint256_t::to_s() const
{
    std::string hex = to_hex_string(values.bytes, SHA256_DIGEST_LENGTH);
    return hex;
}

uva::binary::binary_uint256_t& uva::binary::binary_uint256_t::operator=(const char* str)
{
    return (*this = std::string_view(str));
}

uva::binary::binary_uint256_t& uva::binary::binary_uint256_t::operator=(std::string_view str)
{
    from_string(str);
    return *this;
}

bool uva::binary::binary_uint256_t::operator==(const uva::binary::binary_uint256_t& other) const
{
    for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        if(values.bytes[i] != other.values.bytes[i]) return false;
    }

    return true;
}

uint8_t uva::binary::nibble_from_hex_string(const char& __nibble_str)
{
    if(__nibble_str >= '0' && __nibble_str <= '9') {
        return __nibble_str - '0';
    } else if(__nibble_str >= 'a' && __nibble_str <= 'f')
    {
        return (__nibble_str - 'a') + 0xA;
    }
    else if(__nibble_str >= 'A' && __nibble_str <= 'F')
    {
        return (__nibble_str - 'A') + 0xA;
    }

    throw std::runtime_error("invalid input");
}

uint8_t uva::binary::byte_from_hex_string(const char* __str)
{
    return nibble_from_hex_string(__str[0]) << 4 | nibble_from_hex_string(__str[1]);
}

std::string uva::binary::to_hex_string(const uint8_t* __values, size_t __count)
{
    std::string text;
    text.reserve(__count*2);

    for(size_t i = 0; i < __count; ++i)
    {
        text.push_back(hexadecimal_digits[(__values[0] & 0xF0) >> 4]);
        text.push_back(hexadecimal_digits[__values[0] & 0x0F]);

        ++__values;
    }

    return text;
}

bool uva::binary::is_hex_digit(const char &c)
{
    return hexadecimal_digits_sv.find((char)toupper(c)) != std::string::npos;
}

#ifdef __UVA_OPENSSL_FOUND__
uva::binary::binary_uint256_t uva::binary::sha256(const char* data, const size_t& len)
{
    binary_uint256_t hash;
    SHA256((unsigned char*)data, len, (unsigned char*)&hash);

    return hash;
}

uva::binary::binary_uint256_t uva::binary::hmac_sha256(const std::string &s, const std::string &key)
{
    return hmac_sha256(s.c_str(), s.size(), key);
}

uva::binary::binary_uint256_t uva::binary::hmac_sha256(const char *data, const size_t &len, const std::string& key)
{
    binary_uint256_t hash;
    unsigned int out_len = sizeof(binary_uint256_t);
    unsigned char * r = HMAC(EVP_sha256(), key.c_str(), key.size(), (const unsigned char*)data, len, (unsigned char*)&hash, &out_len);

    return hash;
}
#endif
std::string uva::binary::encode_octet_sequence(const std::string &str)
{
    std::string buffer;
    //max 3 characters per int plus one comma
    // + 2 []
    size_t reserved_size = (str.size()*(3+1))+2;
    buffer.reserve(reserved_size);

    buffer.push_back('[');

    for(const char& c : str) {
        buffer += std::to_string(c);
        buffer.push_back(',');
    }

    buffer.pop_back();
    buffer.push_back(']');

    UVA_CHECK_RESERVED_BUFFER(buffer, reserved_size);

    return buffer;
}

std::string uva::binary::decode_octet_sequence(const std::string &str)
{
    return std::string();
}

#ifdef __UVA_OPENSSL_FOUND__

std::string uva::binary::encode_base64(binary_uint256_t b, bool padding)
{
    return encode_base64((const char*)&b, sizeof(binary_uint256_t), padding);
}

std::string uva::binary::encode_base64(std::string_view sv, bool padding)
{
    return encode_base64(sv.data(), sv.size(), padding);
}

std::string uva::binary::encode_base64(const char *begin, size_t len, bool padding)
{
    size_t output_len = (4*((len+2)/3)); //+1 for the terminating null that EVP_EncodeBlock adds on;
    std::string output;
    output.resize(output_len);

    size_t actual_len = EVP_EncodeBlock((unsigned char*)output.data(), (unsigned char*)begin, len);
    if(actual_len != output_len) {
        throw std::runtime_error("failed to enconde base64: the buffer was smaller");
    }

    if(!padding) {
        while(output.ends_with('=')) {
            output.pop_back();
        }
    }

    return output;
}
#endif

uva::binary::key::key(void *__key)
    : internal_key(__key)
{
}

uva::binary::key::key(const std::string &__original_key)
{
    BIO* bio = BIO_new( BIO_s_mem() );

    if(!bio) {
        throw std::runtime_error("BIO_new failed.");
    }

    if(BIO_write( bio, original_key.c_str(), original_key.size()) != original_key.size()) {
        throw std::runtime_error("BIO_write failed.");
    }

    EVP_PKEY* pkey = 0;
    PEM_read_bio_PUBKEY( bio, &pkey, 0, 0 );

    if(!pkey) {
        throw std::runtime_error("PEM_read_bio_PUBKEY failed.");
    }

    if(!BIO_free(bio)) {
        throw std::runtime_error("BIO_free failed.");
    }

    internal_key = (void*)pkey;
}

uva::binary::key::key(key &&__key)
    : internal_key(__key.internal_key)
{
    __key.internal_key = nullptr;
}

uva::binary::key uva::binary::key::from_certificate(const std::string &__original_certificate)
{
    OpenSSL_add_all_algorithms();

  const char* cert_file = "C:\\Program Files\\OpenSSL-Win64\\bin\\cert.pem";
 FILE* cert_file_ptr = fopen(cert_file, "r");
    if (!cert_file_ptr) {
        std::cerr << "Erro ao abrir o arquivo de certificado." << std::endl;
        return 0;
    }

    EVP_PKEY* public_key = PEM_read_PUBKEY(cert_file_ptr, NULL, NULL, NULL);
    fclose(cert_file_ptr);

//    // BIO* bio = BIO_new_mem_buf((void*)original_certificate.data(), original_certificate.size());
//    BIO* bio = BIO_new(BIO_s_mem());

//     if(!bio) {
//         throw std::runtime_error("BIO_new_mem_buf failed.");
//     }

//         BIO_puts(bio, original_certificate.c_str());

//     X509* cert = PEM_read_bio_X509(bio, nullptr, 0, NULL);
    
//     if(cert == NULL) {
//         throw std::runtime_error("Erro ao carregar o certificado PEM");
//     }

//     BIO_free(bio);

//     EVP_PKEY* pkey = X509_get_pubkey(cert);

//     X509_free(cert);

//     if (!pkey) {
//         throw std::runtime_error("Erro ao extrair a chave pública do certificado");
//     }

//     uva::binary::key key((void*)pkey);
}

uva::binary::key::~key()
{
    if(internal_key) {
        EVP_PKEY_free((EVP_PKEY*)internal_key);
    }
}
