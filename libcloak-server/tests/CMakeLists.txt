add_executable(test_clienthello_parse test_clienthello_parse.c)
target_include_directories(test_clienthello_parse PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_clienthello_parse PRIVATE cloak-server)
add_test(NAME test_clienthello_parse COMMAND test_clienthello_parse)

add_executable(test_server_auth test_server_auth.c)
target_include_directories(test_server_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_auth PRIVATE cloak-server)
add_test(NAME test_server_auth COMMAND test_server_auth)

add_executable(test_replay_cache test_replay_cache.c)
target_include_directories(test_replay_cache PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_replay_cache PRIVATE cloak-server)
add_test(NAME test_replay_cache COMMAND test_replay_cache)

add_executable(test_firstpacket test_firstpacket.c)
target_include_directories(test_firstpacket PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_firstpacket PRIVATE cloak-server)
add_test(NAME test_firstpacket COMMAND test_firstpacket)
set_tests_properties(test_firstpacket PROPERTIES TIMEOUT 60)

add_executable(test_server_state test_server_state.c)
target_include_directories(test_server_state PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_state PRIVATE cloak-server)
add_test(NAME test_server_state COMMAND test_server_state)
set_tests_properties(test_server_state PROPERTIES TIMEOUT 60)

add_executable(test_registry test_registry.c)
target_include_directories(test_registry PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_registry PRIVATE cloak-server)
add_test(NAME test_registry COMMAND test_registry)
set_tests_properties(test_registry PROPERTIES TIMEOUT 60)

add_executable(test_dispatcher_redirect test_dispatcher_redirect.c)
target_include_directories(test_dispatcher_redirect PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_redirect PRIVATE cloak-server)
add_test(NAME test_dispatcher_redirect COMMAND test_dispatcher_redirect)
set_tests_properties(test_dispatcher_redirect PROPERTIES TIMEOUT 60)

add_executable(test_dispatcher_auth test_dispatcher_auth.c)
target_include_directories(test_dispatcher_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_auth PRIVATE cloak-server)
add_test(NAME test_dispatcher_auth COMMAND test_dispatcher_auth)
set_tests_properties(test_dispatcher_auth PROPERTIES TIMEOUT 60)

# Test-only LD_PRELOAD shim (see test_write_shim.c's own top-of-file
# comment) that lets test_dispatcher_auth deterministically force the
# dispatcher's step-10 reply write to see EAGAIN or a real error, which
# genuine socket-buffer backpressure cannot do for a reply this small.
add_library(cloak_test_write_shim SHARED test_write_shim.c)
target_link_libraries(cloak_test_write_shim PRIVATE ${CMAKE_DL_LIBS})

# Under an ASan-instrumented build (CMAKE_C_FLAGS carries -fsanitize=address
# out of band -- this project has no CMake-level ASan option of its own),
# ASan requires its own runtime to be the FIRST thing LD_PRELOAD loads, or
# it aborts at startup ("ASan runtime does not come first in initial
# library list"): our shim is built and ASan-instrumented too (see its
# target_link_libraries above / CMAKE_SHARED_LINKER_FLAGS), but merely
# preloading it is not enough on its own. Detect that case and preload
# libasan.so first, ahead of our own shim, in LD_PRELOAD's search order
# (space-separated, per LD_PRELOAD's own documented syntax).
set(_cloak_ld_preload "$<TARGET_FILE:cloak_test_write_shim>")
if(CMAKE_C_FLAGS MATCHES "-fsanitize=[^ ]*address")
    # ASSUMPTION: -print-file-name=libasan.so is a GCC-runtime-naming
    # query and only means anything to a GCC ${CMAKE_C_COMPILER}. Under a
    # Clang/compiler-rt toolchain this resolves to the literal string
    # "libasan.so" (compiler-rt's own runtime has a different name and
    # location entirely), the EXISTS check below fails, and this whole
    # block silently no-ops -- LD_PRELOAD then carries only our shim, ASan
    # aborts at startup ("ASan runtime does not come first in initial
    # library list"), and this coverage (the whole of test_dispatcher_auth
    # and test_dispatcher_limits under the sanitizer suite) is lost
    # without any build failure to flag it. This project's own build is
    # GCC-only today, so that gap is not live, but a future Clang CI leg
    # would hit it silently; fixing that is out of scope here (no attempt
    # is made to restructure this build for Clang) -- this comment exists
    # so the assumption is visible instead of implicit.
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -print-file-name=libasan.so
        OUTPUT_VARIABLE _cloak_asan_rt
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_cloak_asan_rt AND EXISTS "${_cloak_asan_rt}")
        set(_cloak_ld_preload "${_cloak_asan_rt} ${_cloak_ld_preload}")
    endif()
endif()
set_tests_properties(test_dispatcher_auth PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

add_executable(test_dispatcher_limits test_dispatcher_limits.c)
target_include_directories(test_dispatcher_limits PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_limits PRIVATE cloak-server)
add_test(NAME test_dispatcher_limits COMMAND test_dispatcher_limits)
set_tests_properties(test_dispatcher_limits PROPERTIES TIMEOUT 60)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth): test_dispatcher_limits' mid-reply-write and
# reply-write-deadline cases need the exact same LD_PRELOAD interposition,
# for the exact same reason -- see test_write_shim.c's own top-of-file
# comment.
set_tests_properties(test_dispatcher_limits PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")
