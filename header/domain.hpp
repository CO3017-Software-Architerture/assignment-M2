#pragma once

#include <cstdint>

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
