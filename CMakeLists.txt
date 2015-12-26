project (ndhs)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -ldl -pedantic -Wall -Wextra -Wformat=2 -Wformat-security -Wpointer-arith -Wno-unused-parameter -DNDHS_BUILD")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -std=gnu++14 -ldl -pedantic -Wall -Wextra -Wformat=2 -Wformat-security -Wpointer-arith -Wno-unused-parameter -DNDHS_BUILD")

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

if (${OSNAME} STREQUAL "Linux")
  message("Detected that the current host is a Linux system.")
endif()

include_directories("${PROJECT_SOURCE_DIR}"
                    "${PROJECT_SOURCE_DIR}/ncmlib"
                    "${PROJECT_SOURCE_DIR}/cppformat")
add_subdirectory(ncmlib)
add_subdirectory(cppformat)

find_package( Boost COMPONENTS system program_options )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )
find_package(Threads)

file(GLOB LUA_SRCS "lua/*.c")
add_library(lua ${LUA_SRCS})

subdirs(sqlite)

file(GLOB NDHS_SRCS_C "*.c")
file(GLOB NDHS_SRCS_CPP "*.cpp")
list(APPEND NDHS_SRCS ${NDHS_SRCS_C} ${NDHS_SRCS_CPP})

add_executable(ndhs ${NDHS_SRCS})
target_link_libraries(ndhs ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES}
                           ncmlib cppformat lua sqlite)
