add_library(cloak-client STATIC
    src/client_auth.c
    src/client_transport.c
)

target_include_directories(cloak-client PUBLIC include)
target_link_libraries(cloak-client PUBLIC cloak-common)

add_subdirectory(tests)

# cloak_client_connector_t builds a client-side cloak_session_t out of the
# connections it brings up, so the client library now depends on
# libcloak-mux as well. Appended rather than folded into the line above so
# the original dependency statement stays where a reader first looks for
# it. Still nothing from libcloak-server, ever: that would be circular.
target_sources(cloak-client PRIVATE src/client_connector.c)
target_link_libraries(cloak-client PUBLIC cloak-mux)
