#include <cstdint>
#include <stdexcept>
#include <iostream>

#include "andy/binary.hpp"

uint8_t andy::binary::nibble_from_hex_string(const char& __nibble_str)
{
    if(__nibble_str >= '0' && __nibble_str <= '9')
    {
        return __nibble_str - '0';
    }
    else if(__nibble_str >= 'A' && __nibble_str <= 'F')
    {
        return __nibble_str - 'A' + 10;
    }
    else if(__nibble_str >= 'a' && __nibble_str <= 'f')
    {
        return __nibble_str - 'a' + 10;
    }
}

uint8_t andy::binary::byte_from_hex_string(const char* __str)
{
    return (nibble_from_hex_string(__str[0]) << 4) | nibble_from_hex_string(__str[1]);
}

std::string andy::binary::to_hex_string(const uint8_t* values, size_t count)
{
    static const char* hexadecimal_digits = "0123456789ABCDEF";

    std::string text;
    text.resize(count * 2);

    char* output = text.data();

    const uint8_t* it = values + count - 1;
    while(it >= values)
    {
        uint8_t byte = *it--;
        uint8_t high_nibble = (byte >> 4);
        uint8_t low_nibble = (byte & 0x0F);
        char high_nibble_chat = hexadecimal_digits[high_nibble];
        char low_nibble_chat = hexadecimal_digits[low_nibble];
        *output++ = high_nibble_chat;
        *output++ = low_nibble_chat;
    }

    return text;
}

bool andy::binary::is_hex_digit(const char &c)
{
    throw std::runtime_error("not implemented");
}