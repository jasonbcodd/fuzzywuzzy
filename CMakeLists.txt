cmake_minimum_required(VERSION 3.30)
project(fuzzywuzzy)

include(ExternalProject)

set(CMAKE_C_STANDARD 23)

add_executable(segv tests/binaries/segv/segv.c)
target_compile_options(segv PRIVATE -z,execstack -fno-pie -fno-stack-protector -z,norelro)


add_executable(safe tests/binaries/safe/safe.c)
target_compile_options(safe PRIVATE -z,execstack -fno-pie -fno-stack-protector -z,norelro)


add_executable(hang tests/binaries/hang/hang.c)
target_compile_options(hang PRIVATE -z,execstack -fno-pie -fno-stack-protector -z,norelro)

add_subdirectory(external/boost.throw_exception)
add_subdirectory(external/boost.core)
add_subdirectory(external/boost.config)
add_subdirectory(external/boost.assert)
add_subdirectory(external/boost.static_assert)
add_subdirectory(external/boost.mp11)
add_subdirectory(external/boost.type_traits)
add_subdirectory(external/boost.integer)
add_subdirectory(external/boost.winapi)
add_subdirectory(external/boost.pool)
add_subdirectory(external/boost.predef)
add_subdirectory(external/boost.smart_ptr)
add_subdirectory(external/boost.context)


add_library(harness SHARED src/fuzzer/harness/harness.c src/fuzzer/harness/harness.h src/fuzzer/harness/hooks.c src/fuzzer/harness/hooks.h src/fuzzer/harness/socket.c src/fuzzer/harness/socket.h src/fuzzer/harness/hooks.def.h)# src/fuzzer/harness/fcontext.h)
target_compile_options(harness PRIVATE -Wl,--no-undefined -rdynamic -ldl)
target_link_libraries(harness PRIVATE Boost::context)
