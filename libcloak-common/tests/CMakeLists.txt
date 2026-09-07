add_executable(test_version test_version.c)
target_include_directories(test_version PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_version PRIVATE cloak-common)
add_test(NAME test_version COMMAND test_version)

add_executable(test_random test_random.c)
target_link_libraries(test_random PRIVATE cloak-common)
add_test(NAME test_random COMMAND test_random)

add_executable(test_aead test_aead.c)
target_link_libraries(test_aead PRIVATE cloak-common)
add_test(NAME test_aead COMMAND test_aead)

add_executable(test_salsa20 test_salsa20.c)
target_link_libraries(test_salsa20 PRIVATE cloak-common)
add_test(NAME test_salsa20 COMMAND test_salsa20)

add_executable(test_x25519 test_x25519.c)
target_link_libraries(test_x25519 PRIVATE cloak-common)
add_test(NAME test_x25519 COMMAND test_x25519)
