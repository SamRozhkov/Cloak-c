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
add_subdirectory(third_party/sqlite)
add_subdirectory(libcloak-common)
add_subdirectory(libcloak-mux)
add_subdirectory(libcloak-server)
add_subdirectory(libcloak-client)

# The binaries. Appended rather than folded into the list above so this
# file's existing content stays byte-identical; the libraries must be
# declared first either way, since an executable links them.
add_subdirectory(cmd/ck-server)

# ck-client comes after ck-server because its test drives BOTH binaries
# and names ck-server as a target dependency.
add_subdirectory(cmd/ck-client)
