cmake_minimum_required(VERSION 3.6)
project(sniproxy)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "/usr/lib/" "/usr/local/lib/")

set(CMAKE_C_STANDARD 99)

find_package(Libevent 2.1 REQUIRED libevent)
include_directories(${LIBEVENT_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBEVENT_LIBRARIES})


find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

set(SOURCE_FILES main.c sniproxy.c sniproxy.h)
add_executable(sniproxy ${SOURCE_FILES})

target_link_libraries(sniproxy ${LIBS})