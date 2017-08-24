project (ndhs)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu99 -fno-strict-overflow -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wpointer-arith -Wno-unused-parameter -DNDHS_BUILD")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=gnu++1z -fno-strict-overflow -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat-security -Wpointer-arith -Wno-unused-parameter -DNDHS_BUILD")

if (WIN32)
  set(OSNAME "Win32")
else()
execute_process(
  COMMAND uname
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE OSNAME
  )
endif()
#message("OSNAME: '${OSNAME}'")

if (${OSNAME} STREQUAL "Linux")
  message("Detected that the current host is a Linux system.")
  execute_process(
    COMMAND uname -r
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE LINUX_VERSION
    )
else()
  message("ndhs requires a Linux host system.")
  return()
endif()

include_directories("${PROJECT_SOURCE_DIR}"
                    "${PROJECT_SOURCE_DIR}/ncmlib"
                    "${PROJECT_SOURCE_DIR}/asio"
                    "${PROJECT_SOURCE_DIR}/fmt")
add_subdirectory(ncmlib)
add_subdirectory(fmt)

find_package(Threads)

set(RAGEL_CFG ${CMAKE_CURRENT_BINARY_DIR}/cfg.cpp)
set(RAGEL_DYNLEASE ${CMAKE_CURRENT_BINARY_DIR}/dynlease.cpp)

find_program(RAGEL ragel)
add_custom_command(
  OUTPUT ${RAGEL_CFG}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_CFG} cfg.rl
  DEPENDS cfg.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: cfg.rl"
  VERBATIM
  )
add_custom_command(
  OUTPUT ${RAGEL_DYNLEASE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_DYNLEASE} dynlease.rl
  DEPENDS dynlease.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: dynlease.rl"
  VERBATIM
  )

file(GLOB NDHS_SRCS_C "*.c")
file(GLOB NDHS_SRCS_CPP "*.cpp")
list(APPEND NDHS_SRCS ${NDHS_SRCS_C} ${NDHS_SRCS_CPP})

add_executable(ndhs ${RAGEL_CFG} ${RAGEL_DYNLEASE} ${NDHS_SRCS})
target_link_libraries(ndhs ${CMAKE_THREAD_LIBS_INIT} ncmlib fmt)

