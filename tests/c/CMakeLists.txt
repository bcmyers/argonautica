cmake_minimum_required (VERSION 2.8)
project (tests)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-std=c89 -pthread -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

include_directories("src")
include_directories("src/blake2")

find_package (Threads)

add_library(argon2 STATIC
    src/argon2.c
    src/blake2/blake2b.c
    src/core.c
    src/encoding.c
    src/ref.c
    src/thread.c
)
target_link_libraries (argon2 ${CMAKE_THREAD_LIBS_INIT})

add_library(argon2simd STATIC
    src/argon2.c
    src/blake2/blake2b.c
    src/core.c
    src/encoding.c
    src/opt.c
    src/thread.c
)
target_link_libraries (argon2simd ${CMAKE_THREAD_LIBS_INIT})

add_executable(test src/test.c)
target_link_libraries (test argon2)

add_executable(test_simd src/test.c)
target_link_libraries (test_simd argon2simd)
