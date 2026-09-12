cmake_minimum_required(VERSION 3.16)
project(cloak-c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

enable_testing()

add_subdirectory(third_party/cjson)
add_subdirectory(libcloak-common)
add_subdirectory(libcloak-mux)
add_subdirectory(libcloak-server)
