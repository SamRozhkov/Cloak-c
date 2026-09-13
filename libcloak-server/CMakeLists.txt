add_library(cloak-server STATIC
    src/clienthello_parse.c
    src/server_auth.c
    src/replay_cache.c
    src/firstpacket.c
    src/server.c
    src/registry.c
)

target_include_directories(cloak-server PUBLIC include)
target_link_libraries(cloak-server PUBLIC cloak-common cloak-mux)

add_subdirectory(tests)
