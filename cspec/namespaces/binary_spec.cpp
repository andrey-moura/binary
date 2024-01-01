#include <vector>

#include <faker.hpp>

#include <string.hpp>
#include <uva/binary.hpp>
#include <cspec.hpp>

using namespace uva::binary;

std::string test_string = "A small string to test sha256";
const char* test_string_sha_256_string = "572bcd8a67484dd16df224bc9147a18a7f91cc8de5c4130fc72d34ce60ddef8e";
const char* one_256_string =             "0000000000000000000000000000000000000000000000000000000000000001";
binary_uint256_t test_string_sha_256 = test_string_sha_256_string;

cspec_describe("uva::binary",

    describe("binary_uint256_t",
        describe("to_s",
            it("should convert to string correctly", [](){
                expect(uva::string::tolower(binary_uint256_t(1).to_s())).to eq(one_256_string);
            })    
        )
    )

    describe("sha256",
        it("should return correct checksum", []() {
            expect(sha256(test_string.data(), test_string.size())).to eq(test_string_sha_256);
        })
    )
);