add_executable(test_version test_version.c)
target_include_directories(test_version PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_version PRIVATE cloak-common)
add_test(NAME test_version COMMAND test_version)
