#pragma once

#include <string>
#include <sstream>
#include <format>

#include <openssl/sha.h>

#define INTEGER_256_BITS 256
#define INTEGER_256_BYTES INTEGER_256_BITS / 8
#define INTEGER_256_INTEGERS INTEGER_256_BYTES / sizeof(int)

namespace uva
{
	namespace binary
	{
        struct binary_uint256_t {
        private:
        union v {
            uint8_t bytes[SHA256_DIGEST_LENGTH] { 0 };
            int integers[INTEGER_256_INTEGERS];
        } values;
        public:
            binary_uint256_t() = default;
            binary_uint256_t(int __integer);
            binary_uint256_t(std::string_view str);
            binary_uint256_t(const char* str);
        public:
            binary_uint256_t& operator=(const char* str);
            binary_uint256_t& operator=(std::string_view str);
            bool operator==(const binary_uint256_t& other) const;
        public:
            void integer_assign(const void* integer, size_t integer_size);
            void from_string(std::string_view str);
            std::string to_s() const;
        };

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

        binary_uint256_t sha256(const char* data, const size_t& len);
	};
};

#ifdef USE_FMT_FORMT
    template<>
    struct std::formatter<uva::binary::binary_uint256_t>
    {
        template<typename ParseContext>
        constexpr auto parse(ParseContext& ctx);

        template<typename FormatContext>
        auto format(uva::binary::binary_uint256_t const& v, FormatContext& ctx);

    };

    template<typename ParseContext>
    constexpr auto std::formatter<uva::binary::binary_uint256_t>::parse(ParseContext& ctx)
    {
        return ctx.begin();
    }

    template<typename FormatContext>
    auto std::formatter<uva::binary::binary_uint256_t>::format(uva::binary::binary_uint256_t const& v, FormatContext& ctx)
    {
        return std::format_to(ctx.out(), "{}", v.to_s());
    }

#endif