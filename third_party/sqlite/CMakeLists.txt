# Vendored SQLite 3.50.4 (amalgamation) -- see VENDORING.md. Built with
# warnings suppressed so the upstream source can stay byte-identical to the
# release while project code keeps -Wall -Wextra.
add_library(sqlite3 STATIC sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(sqlite3 PRIVATE -w)

target_compile_definitions(sqlite3 PRIVATE
    # This project is a single-threaded epoll reactor: there is never more
    # than one thread touching a connection. SQLite's internal mutexes are
    # pure overhead here, not a safety net -- do NOT "fix" this to 1 or
    # FULLMUTEX; doing so would silently reintroduce lock overhead on every
    # call for no correctness benefit. The one place this is verified is
    # test_sqlite_link.c's sqlite3_threadsafe() == 0 assertion.
    SQLITE_THREADSAFE=0
    # Nothing in this project loads a shared-object extension; omitting the
    # feature removes a filesystem-driven attack surface entirely.
    SQLITE_OMIT_LOAD_EXTENSION
    # Deprecated interfaces are dead weight this project never calls.
    SQLITE_OMIT_DEPRECATED
    # Shared-cache mode is a multi-connection feature this single-threaded,
    # single-connection-at-a-time reactor never uses.
    SQLITE_OMIT_SHARED_CACHE
    # Reject double-quoted string literals: SQLite's historical leniency
    # here silently turns a typo'd identifier into a string literal instead
    # of a compile error.
    SQLITE_DQS=0
    # Disable the memory-usage tracking subsystem; nothing in this project
    # queries it, and it costs bookkeeping on every allocation.
    SQLITE_DEFAULT_MEMSTATUS=0
    # Enforce FOREIGN KEY constraints by default rather than requiring every
    # connection to opt in with a PRAGMA.
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    # LIKE/GLOB never match BLOB values; make that explicit instead of
    # relying on SQLite's default text-affinity coercion.
    SQLITE_LIKE_DOESNT_MATCH_BLOBS
    # No fixed expression-tree depth limit; this project's queries are
    # generated internally, not built from untrusted, deeply nested input.
    SQLITE_MAX_EXPR_DEPTH=0
)
