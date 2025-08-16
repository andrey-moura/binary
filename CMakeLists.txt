#Require a minimum version
cmake_minimum_required(VERSION 3.16)

project(andy-binary)

add_library(andy-binary OBJECT
	${CMAKE_CURRENT_LIST_DIR}/src/binary.cpp
)

include_directories(${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(andy-binary Threads::Threads)

find_package(OpenSSL)

if(OPENSSL_FOUND)
	target_compile_definitions(andy-binary PRIVATE __UVA_OPENSSL_FOUND__)
	include_directories(${OPENSSL_INCLUDE_DIR})

	set(ANDY_BINARY_LIBRARIES ${OPENSSL_LIBRARIES})
endif()