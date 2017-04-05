project(sniproxy_test)

add_subdirectory(lib/gtest-1.8.0)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

add_executable(runConfigTest test-config.cpp)

target_link_libraries(runConfigTest gtest gtest_main)
target_link_libraries(runConfigTest sniproxy_lib)