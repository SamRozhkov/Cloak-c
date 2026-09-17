add_executable(test_frame test_frame.c)
target_include_directories(test_frame PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_frame PRIVATE cloak-mux)
add_test(NAME test_frame COMMAND test_frame)

add_executable(test_stream test_stream.c)
target_include_directories(test_stream PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_stream PRIVATE cloak-mux)
add_test(NAME test_stream COMMAND test_stream)

add_executable(test_stream_unordered test_stream_unordered.c)
target_include_directories(test_stream_unordered PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_stream_unordered PRIVATE cloak-mux)
add_test(NAME test_stream_unordered COMMAND test_stream_unordered)
set_tests_properties(test_stream_unordered PROPERTIES TIMEOUT 120)

add_executable(test_msgqueue_property test_msgqueue_property.c)
target_include_directories(test_msgqueue_property PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_msgqueue_property PRIVATE cloak-mux)
add_test(NAME test_msgqueue_property COMMAND test_msgqueue_property)
set_tests_properties(test_msgqueue_property PROPERTIES TIMEOUT 120)

add_executable(test_strmtab test_strmtab.c)
target_include_directories(test_strmtab PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_strmtab PRIVATE cloak-mux)
add_test(NAME test_strmtab COMMAND test_strmtab)

add_executable(test_conn test_conn.c)
target_include_directories(test_conn PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_conn PRIVATE cloak-mux)
add_test(NAME test_conn COMMAND test_conn)
set_tests_properties(test_conn PROPERTIES TIMEOUT 60)

add_executable(test_switchboard test_switchboard.c)
target_include_directories(test_switchboard PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_switchboard PRIVATE cloak-mux)
add_test(NAME test_switchboard COMMAND test_switchboard)
set_tests_properties(test_switchboard PROPERTIES TIMEOUT 60)

add_executable(test_session test_session.c)
target_include_directories(test_session PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_session PRIVATE cloak-mux)
add_test(NAME test_session COMMAND test_session)
set_tests_properties(test_session PROPERTIES TIMEOUT 60)

add_executable(test_backpressure test_backpressure.c)
target_include_directories(test_backpressure PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_backpressure PRIVATE cloak-mux)
add_test(NAME test_backpressure COMMAND test_backpressure)
set_tests_properties(test_backpressure PROPERTIES TIMEOUT 60)

add_executable(test_stream_data_cb test_stream_data_cb.c)
target_include_directories(test_stream_data_cb PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_stream_data_cb PRIVATE cloak-mux)
add_test(NAME test_stream_data_cb COMMAND test_stream_data_cb)
set_tests_properties(test_stream_data_cb PROPERTIES TIMEOUT 60)

add_executable(test_stream_relay test_stream_relay.c)
target_include_directories(test_stream_relay PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_stream_relay PRIVATE cloak-mux)
add_test(NAME test_stream_relay COMMAND test_stream_relay)
set_tests_properties(test_stream_relay PROPERTIES TIMEOUT 60)

add_executable(test_valve test_valve.c)
target_include_directories(test_valve PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_valve PRIVATE cloak-mux)
add_test(NAME test_valve COMMAND test_valve)
set_tests_properties(test_valve PROPERTIES TIMEOUT 60)

add_executable(test_valve_rate test_valve_rate.c)
target_include_directories(test_valve_rate PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_valve_rate PRIVATE cloak-mux)
add_test(NAME test_valve_rate COMMAND test_valve_rate)
set_tests_properties(test_valve_rate PROPERTIES TIMEOUT 60)

add_executable(test_conn_record test_conn_record.c)
target_include_directories(test_conn_record PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_conn_record PRIVATE cloak-mux)
add_test(NAME test_conn_record COMMAND test_conn_record)
set_tests_properties(test_conn_record PROPERTIES TIMEOUT 60)

add_executable(test_ws_frame test_ws_frame.c)
target_include_directories(test_ws_frame PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_ws_frame PRIVATE cloak-mux)
add_test(NAME test_ws_frame COMMAND test_ws_frame)
set_tests_properties(test_ws_frame PROPERTIES TIMEOUT 120)

add_executable(test_conn_ws_framing test_conn_ws_framing.c)
target_include_directories(test_conn_ws_framing PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_conn_ws_framing PRIVATE cloak-mux)
add_test(NAME test_conn_ws_framing COMMAND test_conn_ws_framing)
set_tests_properties(test_conn_ws_framing PROPERTIES TIMEOUT 120)

# None of this directory's tests fork a process (module 9 task 0's
# fast/slow split; see the top-level CMakeLists.txt's own comment on
# cloak_label_fast_tests() for what this call does and why it has to be
# made from here rather than from that file). Every test above ends up
# labelled "fast".
cloak_label_fast_tests()
