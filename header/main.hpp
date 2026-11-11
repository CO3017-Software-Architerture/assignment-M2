#ifndef MAIN_H
#define MAIN_H
#define SODIUM_STATIC

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <sodium.h>

using key_id_t = uint64_t;


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
    MALFORMED
};

int run();

#endif