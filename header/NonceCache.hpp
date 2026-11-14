#pragma once

#include "nonce.hpp"
#include "main.hpp"
#include <map>
#include <utility>

class NonceCache
{
public:
    using Clock = std::chrono::steady_clock;

    struct nonce_key_pair
    {
        key_id_t key_id;
        nonce_t nonce;
    };

private:
    static constexpr std::chrono::seconds NONCE_EXPIRATION_TIME{60};
    std::map<std::pair<key_id_t, nonce_t>, Clock::time_point> used_nonces;

public:

    NonceCache() = default;
    ~NonceCache() = default;

    void purge_expired(Clock::time_point current_time = Clock::now());

    bool contains(nonce_key_pair kp) const;

    bool add(nonce_key_pair kp, Clock::time_point current_time = Clock::now());

    bool seen_or_insert(nonce_key_pair kp, Clock::time_point current_time = Clock::now());
    
};
