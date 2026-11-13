cmake_minimum_required(VERSION 3.16)

project(assignment LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(ASSIGNMENT_SOURCES
    src/main.cpp
    src/server.cpp
    src/qrgen.cpp
    src/data2qrlib.cpp
)

add_executable(assignment ${ASSIGNMENT_SOURCES})
target_include_directories(assignment PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/header)

target_compile_options(assignment PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-pedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

set(SODIUM_DISABLE_TESTS ON CACHE BOOL "Disable libsodium-cmake tests")
FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG cfebfd3da486d5a86c644c8b47067e5411c7599c
)
FetchContent_MakeAvailable(Sodium)

target_link_libraries(assignment PRIVATE sodium)

if(WIN32)
    set_target_properties(assignment PROPERTIES OUTPUT_NAME "assignment")
endif()
