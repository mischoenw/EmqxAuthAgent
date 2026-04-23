cmake_minimum_required(VERSION 3.20)
project(EmqxAuthAgent CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -march=x86-64-v2 -mtune=generic)
endif()

# OpenSSL must be found before libwebsockets: libwebsockets' cmake config
# references the openssl::openssl target in its INTERFACE_LINK_LIBRARIES.
# Conan's openssl recipe sets cmake_file_name="OpenSSL" (capital O), so
# CMakeDeps generates OpenSSL-config.cmake — find_package must match that.
find_package(OpenSSL REQUIRED)
find_package(libwebsockets REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(emqx-auth-agent
    src/main.cpp
    src/http_handler.cpp
    src/cert_parser.cpp
    src/topic_matcher.cpp
    src/rules_engine.cpp
)

target_include_directories(emqx-auth-agent PRIVATE src)
target_link_libraries(emqx-auth-agent PRIVATE
    websockets
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
)

enable_testing()
add_subdirectory(tests)
