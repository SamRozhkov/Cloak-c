add_library(cloak-client STATIC
    src/client_auth.c
)

target_include_directories(cloak-client PUBLIC include)
target_link_libraries(cloak-client PUBLIC cloak-common)

add_subdirectory(tests)
