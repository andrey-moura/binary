#Require a minimum version
cmake_minimum_required(VERSION 3.20)

project(uva-binary)

add_library(uva-binary
	${CMAKE_CURRENT_LIST_DIR}/src/binary.cpp
)

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(uva-binary Threads::Threads ${OPENSSL_LIBRARIES})

#Tests

#Create tests for parent project
cspec_configure("uva-binary" ${CMAKE_CURRENT_LIST_DIR} "uva-binary;uva-string")
