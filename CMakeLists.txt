#Require a minimum version
cmake_minimum_required(VERSION 3.16)

project(uva-binary)

add_library(uva-binary
	${CMAKE_CURRENT_LIST_DIR}/src/binary.cpp
)

include_directories(${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(uva-binary Threads::Threads)

if(DEFINED OPENSSL_INCLUDE_DIR)
	target_compile_definitions(uva-binary PRIVATE __UVA_OPENSSL_FOUND__)
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(uva-binary ${OPENSSL_LIBRARIES})
endif()

#Tests

#Create tests for parent project
cspec_configure("uva-binary" ${CMAKE_CURRENT_LIST_DIR} "uva-binary;uva-string")
