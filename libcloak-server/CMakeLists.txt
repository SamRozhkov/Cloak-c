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

# The admin API's HTTP/1.1 request parser. Appended rather than folded
# into the add_library list above so this file's existing content stays
# byte-identical; CMake resolves the path against this directory and
# applies it to the already-declared target either way.
target_sources(cloak-server PRIVATE src/http.c)

# The admin API's JSON codec for one user record. Appended for the same
# reason src/http.c is -- this file's existing content stays
# byte-identical -- and it needs the vendored cJSON, which cloak-common
# links PRIVATE and therefore does not propagate. PRIVATE again here: no
# consumer of cloak/user_json.h ever sees cJSON.h, exactly as no consumer
# of cloak/usermanager.h sees sqlite3.h.
target_sources(cloak-server PRIVATE src/user_json.c)
target_link_libraries(cloak-server PRIVATE cjson)
