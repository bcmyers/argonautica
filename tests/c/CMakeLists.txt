cmake_minimum_required (VERSION 2.8)
project (tests)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-std=c11 -pthread -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

include_directories("src")
include_directories("src/argon2")
include_directories("src/argon2/blake2")

find_package (Threads)

add_library(argon2 STATIC
    src/argon2/argon2.c
    src/argon2/blake2/blake2b.c
    src/argon2/core.c
    src/argon2/encoding.c
    src/argon2/ref.c
    src/argon2/thread.c
)
target_link_libraries (argon2 ${CMAKE_THREAD_LIBS_INIT})

add_library(argon2simd STATIC
    src/argon2/argon2.c
    src/argon2/blake2/blake2b.c
    src/argon2/core.c
    src/argon2/encoding.c
    src/argon2/opt.c
    src/argon2/thread.c
)
target_link_libraries (argon2simd ${CMAKE_THREAD_LIBS_INIT})

set(CODE_TEST_HASH_C src/test_hash_c.c src/hash.c src/utils.c src/verify.c)

add_executable(test_hash_c ${CODE_TEST_HASH_C})
target_link_libraries (test_hash_c argon2)

add_executable(test_hash_c_simd ${CODE_TEST_HASH_C})
target_link_libraries (test_hash_c_simd argon2simd)
