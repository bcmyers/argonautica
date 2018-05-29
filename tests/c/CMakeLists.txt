cmake_minimum_required (VERSION 2.6)
project (a2)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L/usr/local/lib")

include_directories("/usr/local/include")

add_executable(tests tests.c)
target_link_libraries (tests argon2)
