#pragma once

#include <string>
#include <vector>

namespace andy
{
	namespace binary
	{
        /**
         *  @brief Converts a string representation of a hex 4 bits nibble to a 8 bits byte
         *  @param  __nibble_str A char in the range of '0' to 'F', case insensitive
         *  @return         The computer readable value of the hex in @a __nibble_str. The nibble is always stored in the lowest, leaving the highest as zero, ie 09.
         */
		uint8_t nibble_from_hex_string(const char& __nibble_str);

        /**
         *  @brief Converts a string representation of a hex 8 bits byte to a 8 bits byte
         *  @param  __str   A 2 byte wide memory block, each byte representing a char in the range of '0' to 'F', case insensitive
         *  @return         The computer readable value of the hex in @a __str
         */
		uint8_t byte_from_hex_string(const char* __str);

        /**
         *  @brief Converts an block of memmory to a string representation in the hexadecimal format, in little endian (the memmory block is reversed).
         *  @param  __values  A memmory block, each byte to be represented with a char in the range of '0' to 'F'
         *  @param  __count  The lenght in bytes of @a __values.
         *  @return         The human readable value of @a __values in the hexadecimal format.
         */
		std::string to_hex_string(const uint8_t* __values, size_t __count);

        /**
         *  @brief Converts an integerto a string representation in the hexadecimal format, in little endian (the memmory block is reversed).
         *  @param  __integer  A memmory block, each byte to be represented with a char in the range of '0' to 'F'
         *  @return         The human readable value of @a __integer in the hexadecimal format.
         */
        template<typename Integer>
		std::string to_hex_string(const Integer& __integer)
        {
            return to_hex_string((const uint8_t*)&__integer, sizeof(__integer));
        }

        bool is_hex_digit(const char& c);
    }
}