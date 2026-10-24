cmake_minimum_required(VERSION 3.25)

project(native-injection-fixtures LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "Native injection fixtures can only be built on Windows.")
endif()

configure_file(src/injector-fixture.def.in "${CMAKE_CURRENT_BINARY_DIR}/injector-fixture.def" @ONLY)

set(FIXTURE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${FIXTURE_OUTPUT_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${FIXTURE_OUTPUT_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${FIXTURE_OUTPUT_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${FIXTURE_OUTPUT_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${FIXTURE_OUTPUT_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${FIXTURE_OUTPUT_DIR}")

add_executable(injection-target src/injection-target.c)
add_library(injector-fixture SHARED src/injector-fixture.c "${CMAKE_CURRENT_BINARY_DIR}/injector-fixture.def")

if(MSVC)
    target_compile_options(injection-target PRIVATE /W4 /WX)
    target_compile_options(injector-fixture PRIVATE /W4 /WX)
endif()
