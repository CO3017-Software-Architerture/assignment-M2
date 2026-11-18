#pragma once

#include "domain.hpp"
#include "nonce.hpp"

#include <chrono>

class INonceStore
{
public:
    using Clock = std::chrono::steady_clock;
    virtual ~INonceStore() = default;

    virtual void purge_expired(Clock::time_point current_time = Clock::now()) = 0;
    virtual bool seen_or_insert(key_id_t key_id, nonce_t nonce,
                                Clock::time_point current_time = Clock::now()) = 0;
};

class IPassbackStore
{
public:
    virtual ~IPassbackStore() = default;

    virtual bool check_anti_passback(key_id_t key_id, Direction direction) const = 0;
    virtual bool commit_passback(key_id_t key_id, Direction direction) = 0;
    virtual bool reset_passback(key_id_t key_id) = 0;
};
