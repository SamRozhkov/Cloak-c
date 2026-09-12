# Vendored cJSON v1.7.19 -- see VENDORING.md. Built with warnings
# suppressed so the upstream sources can stay byte-identical to the
# release while project code keeps -Wall -Wextra.
add_library(cjson STATIC cJSON.c)
target_include_directories(cjson PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(cjson PRIVATE -w)
