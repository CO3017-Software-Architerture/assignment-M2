cmake_minimum_required(VERSION 3.16)

project(assignment LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(ASSIGNMENT_CORE_SOURCES
    src/client.cpp
    src/server.cpp
    src/Verifier.cpp
    src/nonce.cpp
    src/NonceCache.cpp
    src/PassbackCache.cpp
    src/qrcodegen.cpp
    src/qrgen.cpp
)

add_library(assignment_core STATIC ${ASSIGNMENT_CORE_SOURCES})
target_include_directories(assignment_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/header)

target_compile_options(assignment_core PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-pedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

set(SODIUM_DISABLE_TESTS ON CACHE BOOL "Disable libsodium-cmake tests")
FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG cfebfd3da486d5a86c644c8b47067e5411c7599c
)
FetchContent_MakeAvailable(Sodium)

target_link_libraries(assignment_core PUBLIC sodium)

add_executable(client src/client_main.cpp)
add_executable(server src/server_main.cpp)
add_executable(assignment src/main.cpp)
add_executable(seedgen src/seedgen.cpp)

target_link_libraries(client PRIVATE assignment_core)
target_link_libraries(server PRIVATE assignment_core)
target_link_libraries(assignment PRIVATE assignment_core)
target_link_libraries(seedgen PRIVATE assignment_core)
target_sources(client PRIVATE src/client_entry.cpp)
target_sources(assignment PRIVATE src/client_entry.cpp)
# target_sources(seedgen PRIVATE src/seedgen.cpp)

foreach(target client server assignment seedgen)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-pedantic>
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
    )
endforeach()
