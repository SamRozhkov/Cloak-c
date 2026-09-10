add_library(cloak-mux STATIC
    src/frame.c
    src/bytequeue.c
    src/stream.c
    src/strmtab.c
    src/conn.c
    src/switchboard.c
)

target_include_directories(cloak-mux PUBLIC include)
target_link_libraries(cloak-mux PUBLIC cloak-common)

add_subdirectory(tests)
