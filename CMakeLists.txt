project (ndhs)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -ldl -Wall -DHAVE_CLEARENV -DLINUX -DNDHS_BUILD")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -std=gnu++0x -ldl -Wall -DHAVE_CLEARENV -DLINUX -DNDHS_BUILD")

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

find_package( Boost COMPONENTS system program_options )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )

file(GLOB LUA_SRCS "lua/*.c")
add_library(lua ${LUA_SRCS})

subdirs(sqlite)

file(GLOB NDHS_SRCS_C "*.c")
file(GLOB NDHS_SRCS_CPP "*.cpp")
list(APPEND NDHS_SRCS ${NDHS_SRCS_C} ${NDHS_SRCS_CPP})

add_executable(ndhs ${NDHS_SRCS})
target_link_libraries(ndhs ${Boost_LIBRARIES} ncmlib lua sqlite)
