#include "NonceCache.hpp"

void NonceCache::purge_expired(clock::time_point current_time = clock::now())
{
    // TODO: iterate and remove expired nonces from the used_nonces set
}

bool NonceCache::contains(nonce_key_pair kp) const
{
    // TODO: check if the nonce_key_pair exists in the used_nonces set
    return false;
}

bool NonceCache::add(nonce_key_pair kp, clock::time_point current_time = clock::now())
{
    // TODO: add the nonce_key_pair to the used_nonces set with the current timestamp
    return false;
}

bool NonceCache::seen_or_insert(nonce_key_pair kp)
{
    // TODO: return true if the key pair has been seen, otherwise insert and return false

    return false;
}
