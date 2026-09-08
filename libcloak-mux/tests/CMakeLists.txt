add_executable(test_frame test_frame.c)
target_include_directories(test_frame PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_frame PRIVATE cloak-mux)
add_test(NAME test_frame COMMAND test_frame)
