cmake_minimum_required(VERSION 3.3)
if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
else()
  cmake_policy(VERSION 3.12)
endif()

project (ndhs DESCRIPTION "dhcp[46] and ipv6 router advertisement server" LANGUAGES CXX C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -fno-strict-overflow -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -DNDHS_BUILD -DASIO_STANDALONE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -fno-strict-overflow -fno-rtti -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat-security -Wpointer-arith -DNDHS_BUILD -DASIO_STANDALONE -DASIO_NO_TYPEID")

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

add_subdirectory(ncmlib)

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
set_property(SOURCE ${RAGEL_CFG} APPEND PROPERTY GENERATED TRUE)
if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set_property(SOURCE ${RAGEL_CFG} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-unused-const-variable")
endif()
add_custom_command(
  OUTPUT ${RAGEL_DYNLEASE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_DYNLEASE} dynlease.rl
  DEPENDS dynlease.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: dynlease.rl"
  VERBATIM
  )
set_property(SOURCE ${RAGEL_DYNLEASE} APPEND PROPERTY GENERATED TRUE)
if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set_property(SOURCE ${RAGEL_DYNLEASE} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-unused-const-variable")
endif()

add_executable(ndhs ${RAGEL_CFG} ${RAGEL_DYNLEASE})
target_sources(ndhs PRIVATE
  "rng.cpp"
  "attach_bpf.c"
  "ip_address.cpp"
  "dhcp6.cpp"
  "duid.cpp"
  "nl.c"
  "options.c"
  "dhcp4.cpp"
  "dhcp_state.cpp"
  "ndhs.cpp"
  "nlsocket.cpp"
  "radv6.cpp"
)
target_include_directories(ndhs PRIVATE
  "${PROJECT_SOURCE_DIR}"
  "${PROJECT_SOURCE_DIR}/ncmlib"
  "${PROJECT_SOURCE_DIR}/asio"
)
target_link_libraries(ndhs PUBLIC ${CMAKE_THREAD_LIBS_INIT} ncmlib)

