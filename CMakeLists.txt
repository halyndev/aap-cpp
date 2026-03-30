cmake_minimum_required(VERSION 3.15)
project(aap-protocol VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# Header-only library target
add_library(aap INTERFACE)
target_include_directories(aap INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(aap INTERFACE OpenSSL::SSL OpenSSL::Crypto)

# Examples
add_executable(quickstart examples/quickstart.cpp)
target_link_libraries(quickstart PRIVATE aap)

# Tests
enable_testing()
add_executable(test_aap tests/test_aap.cpp)
target_link_libraries(test_aap PRIVATE aap)
add_test(NAME aap_tests COMMAND test_aap)
