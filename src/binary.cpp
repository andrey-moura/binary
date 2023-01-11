#include <binary.hpp>

static char hexadecimal_digits[16]{ '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

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

uva::binary::binary_uint256_t uva::binary::sha256(const char* data, const size_t& len)
{
    binary_uint256_t hash;
    SHA256((unsigned char*)data, len, (unsigned char*)&hash);

    return hash;
}