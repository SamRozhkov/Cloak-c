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

# cloak_client_piper_t: the local listener. It splices with
# cloak_stream_relay_t (libcloak-mux), which the connector's dependency
# above already supplies -- so this adds a source and no new link.
# Appended rather than folded in above for the same reason the connector
# was: the original dependency statement stays where a reader looks for it.
target_sources(cloak-client PRIVATE src/client_piper.c)
