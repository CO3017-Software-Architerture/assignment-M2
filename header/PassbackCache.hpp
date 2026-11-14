#pragma once

#include "main.hpp"
#include <map>

enum class Location
{
    IN,
    OUT
};

class PassbackCache
{
public:
    using passback_map_t = std::map<key_id_t, Location>;
private:
    passback_map_t m_passbackMap;


public:
    PassbackCache() = default;
    ~PassbackCache() = default;

    bool check_anti_passback(key_id_t key_id, Direction direction) const;

    bool commit_passback(key_id_t key_id, Direction direction);

    bool reset_passback(key_id_t key_id);
};
