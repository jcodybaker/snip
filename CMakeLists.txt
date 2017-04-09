cmake_minimum_required(VERSION 3.6)
project(snip)

set(SNIP_VERSION 0.1)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "/usr/lib/" "/usr/local/lib/")
set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "/usr/include/" "/usr/local/include/")

set(CMAKE_C_STANDARD 99)

find_package(Libevent 2.1 REQUIRED libevent pthreads)
include_directories(${LIBEVENT_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBEVENT_LIBRARIES})

find_package(LibYAML)
include_directories(${LibYAML_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LibYAML_LIBRARIES})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

set(SOURCE_FILES snip.c snip.h tls.h compat.h config.c config.h log.c log.h)
add_executable(snip main.c ${SOURCE_FILES})

target_compile_definitions(snip
        PUBLIC SNIP_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        PUBLIC SNIP_INSTALL_CONF_DIR="${CMAKE_INSTALL_PREFIX}etc/"
        PUBLIC SNIP_INSTALL_CONF_PATH="${CMAKE_INSTALL_CONF_DIR}snip.yml"
        PUBLIC SNIP_VERSION="${SNIP_VERSION}"
        )

add_subdirectory(tests)

target_link_libraries(snip ${LIBS})

# We build this as a library so we can test with it.  May eventually make it available this way also though.
add_library(snip_lib ${SOURCE_FILES})
target_compile_definitions(snip_lib
        PUBLIC SNIP_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        PUBLIC SNIP_INSTALL_CONF_DIR="${CMAKE_INSTALL_PREFIX}etc/"
        PUBLIC SNIP_INSTALL_CONF_PATH="${CMAKE_INSTALL_CONF_DIR}snip.yml"
        PUBLIC SNIP_VERSION="${SNIP_VERSION}"
        )
target_link_libraries(snip_lib ${LIBS})