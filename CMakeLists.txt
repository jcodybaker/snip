cmake_minimum_required(VERSION 3.5)
project(snip)

set(SNIP_VERSION 0.1)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "/usr/lib/" "/usr/local/lib/" )

set(CMAKE_C_STANDARD 99)

find_package( Threads )

option(SNIP__DOWNLOAD_AND_BUILD_DEPENDENCIES
    "Download and build dependencies files." OFF)

if(SNIP__DOWNLOAD_AND_BUILD_DEPENDENCIES)
	set(CMAKE_INCLUDE_PATH  "/usr/include/" "/usr/local/include/" ${CMAKE_INCLUDE_PATH})
	if(NOT EXISTS "${CMAKE_SOURCE_DIR}/third_party/libevent/include/event2/event.h")
		execute_process(COMMAND "git" "clone" "-b" "patches-2.1" "https://github.com/libevent/libevent.git" "${CMAKE_SOURCE_DIR}/third_party/libevent")
	endif()
	set(EVENT__DISABLE_OPENSSL ON)
	set(EVENT__DISABLE_TESTS ON)
	add_subdirectory("third_party/libevent")
	# set(LIBEVENT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/third_party/libevent/include")

	if(NOT EXISTS "${CMAKE_SOURCE_DIR}/third_party/libyaml/include/yaml.h")
		execute_process(COMMAND "git" "clone" "https://github.com/yaml/libyaml.git" "${CMAKE_SOURCE_DIR}/third_party/libyaml")
	endif()
	add_subdirectory("third_party/libyaml")
	set(LibYAML_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/third_party/libyaml/include")
	set(LIBS ${LIBS} event yaml)
else ()
	find_package(LibYAML)
	include_directories(${LibYAML_INCLUDE_DIRS})
	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		find_package(Libevent 2.1 REQUIRED libevent windows)
	else()
		find_package(Libevent 2.1 REQUIRED libevent pthreads)
	endif()
	set(LIBS ${LIBS} ${LIBEVENT_LIBRARIES} ${LibYAML_LIBRARIES})
endif()




include_directories(${LIBEVENT_INCLUDE_DIRS})
include_directories(${LibYAML_INCLUDE_DIRS})



#find_package(OpenSSL REQUIRED)
#include_directories(${OPENSSL_INCLUDE_DIR})
#set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

set(SOURCE_FILES snip.c snip.h tls.h compat.h config.c config.h log.c log.h net_util.c net_util.h sys_util.c sys_util.h tls.c)
add_executable(snip main.c ${SOURCE_FILES})


target_link_libraries(snip ${CMAKE_THREAD_LIBS_INIT} )

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
target_link_libraries(snip_lib ${CMAKE_THREAD_LIBS_INIT} )

if(SNIP__DOWNLOAD_AND_BUILD_DEPENDENCIES) 
# If we downloaded dependencies, we should build, require, and use them.
add_dependencies(snip event)
add_dependencies(snip_lib event)
add_dependencies(snip yaml)
add_dependencies(snip_lib yaml)
endif()
