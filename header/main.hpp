#ifndef MAIN_H
#define MAIN_H
#define SODIUM_STATIC
// #define CLIENT_NO_MAIN

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <sodium.h>
#include <array>

using key_id_t = std::uint64_t;


enum class Direction
{
    IN,
    OUT
};

enum class Decision
{
    ALLOW,
    BAD_SIGNATURE,
    EXPIRED,
    FUTURE,
    REPLAY,
    UNKNOWN_KEY,
    PASSBACK,
    MALFORMED,
    INTERNAL_ERROR
};

int run();

#endif
