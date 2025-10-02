cmake_minimum_required(VERSION 3.10)
project(wmbus_decrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(wmbus_decrypt main.cpp)
target_link_libraries(wmbus_decrypt PRIVATE OpenSSL::Crypto)
