#Require a minimum version
cmake_minimum_required(VERSION 3.16)

project(uva-binary)

add_library(uva-binary OBJECT
	${CMAKE_CURRENT_LIST_DIR}/src/binary.cpp
)

include_directories(${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(uva-binary Threads::Threads)

find_package(OpenSSL)

if(OPENSSL_FOUND)
	target_compile_definitions(uva-binary PRIVATE __UVA_OPENSSL_FOUND__)
	include_directories(${OPENSSL_INCLUDE_DIR})

	set(ANDY_BINARY_LIBRARIES ${OPENSSL_LIBRARIES})
endif()