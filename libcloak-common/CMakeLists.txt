find_package(OpenSSL REQUIRED)

add_library(cloak-common STATIC
    src/version.c
    src/random.c
    src/base64.c
    src/aead.c
    src/salsa20.c
    src/x25519.c
    src/reactor.c
    src/clienthello.c
)

target_include_directories(cloak-common PUBLIC include)
target_link_libraries(cloak-common PUBLIC OpenSSL::Crypto)

add_subdirectory(tests)
