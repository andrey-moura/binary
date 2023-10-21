#pragma once

#include <string>
#include <sstream>
#include <format.hpp>
#include <vector>

#define SHA256_DIGEST_LENGTH 32
#define INTEGER_256_BITS 256
#define INTEGER_256_BYTES INTEGER_256_BITS / 8
#define INTEGER_256_INTEGERS INTEGER_256_BYTES / sizeof(int)

namespace uva
{
	namespace binary
	{
        struct binary_uint256_t {
            public:
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
        struct key {
            public:
                key(const std::string& __original_key);
            private:
                void* internal_key;
            public:
                std::string original_key;
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

        bool is_hex_digit(const char& c);

#ifdef __UVA_OPENSSL_FOUND__
        binary_uint256_t sha256(const char* data, const size_t& len);
        binary_uint256_t hmac_sha256(const std::string& s, const std::string& key);
        binary_uint256_t hmac_sha256(const char* data, const size_t& len, const std::string& key);
#endif
        std::string encode_octet_sequence(const std::string& str);
        std::string decode_octet_sequence(const std::string& str);

        std::string encode_base64(binary_uint256_t b, bool padding = true);
        std::string encode_base64(std::string_view sv, bool padding = true);
        std::string encode_base64(const char* begin, size_t len, bool padding = true);

        //now, we done something cool. Based on https://stackoverflow.com/a/41094722, I brought the fastest encoder and the fastest decoder here

        template<typename container>
        void decode_base64(std::string_view input, container& __output, bool url)
        {
            static const int base64_indexes[256] = {
                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
                56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
                7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
                0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
            };


            static const int base64url_indexes[256] = {
                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0, 63, 52, 53, 54, 55,
                56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
                7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
                0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
            };

            const int* base_indexes = nullptr;

            if(url) {
                base_indexes = base64url_indexes;
            } else {
                base_indexes = base64_indexes;
            }

            unsigned char* p = (unsigned char*)input.data();
            size_t len = input.size();

            int pad = len > 0 && (len % 4 || p[len - 1] == '=');
            const size_t L = ((len + 3) / 4 - pad) * 4;

            __output.resize(L / 4 * 3 + pad, '\0');

            for (size_t i = 0, j = 0; i < L; i += 4)
            {
                int n = base_indexes[p[i]] << 18 | base_indexes[p[i + 1]] << 12 | base_indexes[p[i + 2]] << 6 | base_indexes[p[i + 3]];
                __output[j++] = n >> 16;
                __output[j++] = n >> 8 & 0xFF;
                __output[j++] = n & 0xFF;
            }

            if (pad)
            {
                int n = base_indexes[p[L]] << 18 | base_indexes[p[L + 1]] << 12;
                __output[__output.size() - 1] = n >> 16;

                if (len > L + 2 && p[L + 2] != '=')
                {
                    n |= base_indexes[p[L + 2]] << 6;
                    __output.push_back(n >> 8 & 0xFF);
                }
            }
        }

        template<typename container>
        container decode_base64(std::string_view input, bool url)
        {
            container c;
            decode_base64(input, c, url);

            return c;
        }
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