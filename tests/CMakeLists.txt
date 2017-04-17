project(snip_test)

add_subdirectory(lib/gtest-1.8.0)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

add_executable(runConfigTest test-config.cpp)

target_compile_definitions(runConfigTest
        PUBLIC SNIP_TEST_DIR="${CMAKE_CURRENT_SOURCE_DIR}/"
        PUBLIC SNIP_TEST_CONFIGS="${CMAKE_CURRENT_SOURCE_DIR}/configs"
        PUBLIC SNIP_TEST_CAPTURES="${CMAKE_CURRENT_SOURCE_DIR}/captures"
        )

target_link_libraries(runConfigTest gtest gtest_main)
target_link_libraries(runConfigTest snip_lib)

add_executable(runTLSTest test-tls.cpp)

target_compile_definitions(runTLSTest
        PUBLIC SNIP_TEST_DIR="${CMAKE_CURRENT_SOURCE_DIR}/"
        PUBLIC SNIP_TEST_CONFIGS="${CMAKE_CURRENT_SOURCE_DIR}/configs"
        PUBLIC SNIP_TEST_CAPTURES="${CMAKE_CURRENT_SOURCE_DIR}/captures"
        )

target_link_libraries(runTLSTest gtest gtest_main)
target_link_libraries(runTLSTest snip_lib)