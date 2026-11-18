#pragma once

#include "domain.hpp"

class IPassbackStore
{
public:
    virtual ~IPassbackStore() = default;

    virtual bool check_anti_passback(key_id_t key_id, Direction direction) const = 0;
    virtual bool commit_passback(key_id_t key_id, Direction direction) = 0;
    virtual bool reset_passback(key_id_t key_id) = 0;
};
