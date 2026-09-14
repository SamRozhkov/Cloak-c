add_library(cloak-server STATIC
    src/clienthello_parse.c
    src/server_auth.c
    src/replay_cache.c
    src/firstpacket.c
    src/server.c
    src/registry.c
    src/dispatcher.c
    src/proxy.c
    src/usermanager.c
    src/userpanel.c
)

target_include_directories(cloak-server PUBLIC include)
target_link_libraries(cloak-server PUBLIC cloak-common cloak-mux)

# PRIVATE: cloak/usermanager.h deliberately keeps cloak_usermanager_t
# opaque and never includes sqlite3.h, so no consumer of this library
# needs SQLite on its include path -- only usermanager.c does. The archive
# still carries the link dependency through to final executables.
target_link_libraries(cloak-server PRIVATE sqlite3)

add_subdirectory(tests)
