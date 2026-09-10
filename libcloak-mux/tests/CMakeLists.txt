add_executable(test_frame test_frame.c)
target_include_directories(test_frame PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_frame PRIVATE cloak-mux)
add_test(NAME test_frame COMMAND test_frame)

add_executable(test_bytequeue test_bytequeue.c)
target_include_directories(test_bytequeue PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_bytequeue PRIVATE cloak-mux)
add_test(NAME test_bytequeue COMMAND test_bytequeue)

add_executable(test_stream test_stream.c)
target_include_directories(test_stream PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_stream PRIVATE cloak-mux)
add_test(NAME test_stream COMMAND test_stream)

add_executable(test_strmtab test_strmtab.c)
target_include_directories(test_strmtab PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_strmtab PRIVATE cloak-mux)
add_test(NAME test_strmtab COMMAND test_strmtab)

add_executable(test_conn test_conn.c)
target_include_directories(test_conn PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_conn PRIVATE cloak-mux)
add_test(NAME test_conn COMMAND test_conn)

add_executable(test_switchboard test_switchboard.c)
target_include_directories(test_switchboard PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_switchboard PRIVATE cloak-mux)
add_test(NAME test_switchboard COMMAND test_switchboard)
