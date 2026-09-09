add_library(cloak-server STATIC
    src/clienthello_parse.c
)

target_include_directories(cloak-server PUBLIC include)

add_subdirectory(tests)
