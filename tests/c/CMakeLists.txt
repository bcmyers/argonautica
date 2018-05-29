cmake_minimum_required (VERSION 2.6)
project (a2)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -L/usr/local/lib")

include_directories("/usr/local/include")

add_executable(tests tests.c)
target_link_libraries (tests argon2)
