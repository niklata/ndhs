project(SQLITE)
include_directories(${CMAKE_SOURCE_DIR})
set(SQLITE_SRCS sqlite3.c)
add_library(sqlite ${SQLITE_SRCS})
