cmake_minimum_required(VERSION 3.22)

project(OpenSSH-bcrypt_pbkdf-benchmark
   LANGUAGES C CXX
   VERSION 0.1.0
   DESCRIPTION "Benchmark different round numbers of bcrypt_pbkdf used by OpenSSH"
   HOMEPAGE_URL "OpenSSH-bcrypt_pbkdf-benchmark"
)

# homebrew llvm toolchain hack
set(CMAKE_XCODE_ATTRIBUTE_COMPILER_INDEX_STORE_ENABLE NO)

option(FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." ON)

if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options(-fdiagnostics-color=always)
    elseif ("${FORCE_COLORED_OUTPUT}" STREQUAL "Clang" OR "${FORCE_COLORED_OUTPUT}" STREQUAL "AppleClang")
       add_compile_options(-fcolor-diagnostics)
    endif ()
endif ()

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_C_FLAGS "-Ofast -fvisibility=hidden -flto")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

# add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
# add_link_options(-fsanitize=address)

add_subdirectory(3rdparty)
add_subdirectory(tools)
