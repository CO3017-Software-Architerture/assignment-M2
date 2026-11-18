#include "NonceCache.hpp"

void NonceCache::purge_expired(Clock::time_point current_time)
{
    for (auto entry = used_nonces.begin(); entry != used_nonces.end();)
    {
        if (current_time - entry->second >= NONCE_EXPIRATION_TIME)
            entry = used_nonces.erase(entry);
        else
            ++entry;
    }
}

bool NonceCache::contains(nonce_key_pair kp) const
{
    return used_nonces.find({kp.key_id, kp.nonce}) != used_nonces.end();
}

bool NonceCache::add(nonce_key_pair kp, Clock::time_point current_time)
{
    return used_nonces.emplace(std::make_pair(kp.key_id, kp.nonce), current_time).second;
}

bool NonceCache::seen_or_insert(nonce_key_pair kp, Clock::time_point current_time)
{
    return !add(kp, current_time);
}
