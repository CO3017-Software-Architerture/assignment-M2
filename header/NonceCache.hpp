#pragma once

#include "NonceStore.hpp"
#include "nonce.hpp"
#include "domain.hpp"
#include <array>
#include <cstdint>
#include <chrono>
#include <map>
#include <utility>

class NonceCache : public INonceStore
{
public:
    using Clock = INonceStore::Clock;

    struct nonce_key_pair
    {
        key_id_t key_id;
        nonce_t nonce;
    };

private:
    std::chrono::seconds m_expirationTime{60};
    std::map<std::pair<key_id_t, nonce_t>, Clock::time_point> used_nonces;

public:
    explicit NonceCache(std::chrono::seconds expirationTime = std::chrono::seconds{60})
        : m_expirationTime(expirationTime)
    {
        if (m_expirationTime.count() < 0)
        {
            m_expirationTime = std::chrono::seconds::zero();
        }
    }
    ~NonceCache() override = default;

    void purge_expired(Clock::time_point current_time = Clock::now()) override;

    // Returns true when the nonce is currently present in the cache.
    bool contains(nonce_key_pair kp) const;

    // Returns true when the nonce is newly inserted; false when already present.
    bool add(nonce_key_pair kp, Clock::time_point current_time = Clock::now());

    // Returns true when the nonce was already seen; false when newly inserted.
    bool seen_or_insert(nonce_key_pair kp, Clock::time_point current_time = Clock::now());

    // Returns true when the nonce was already seen; false when newly inserted.
    bool seen_or_insert(key_id_t key_id, nonce_t nonce,
                        Clock::time_point current_time = Clock::now()) override;
};