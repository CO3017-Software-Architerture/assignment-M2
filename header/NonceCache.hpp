#include "Nonce.hpp"
#include "main.hpp"
#include <set>

using clock = std::chrono::steady_clock;


static constexpr std::chrono::seconds NONCE_EXPIRATION_TIME{60};

class NonceCache
{
public:

    struct nonce_key_pair
    {
        key_id_t key_id;
        nonce_t nonce;
    };

    struct nonce_cache_entry
    {
        nonce_key_pair key_pair;
        clock::time_point timestamp;
    };

    using nonce_set_t = std::set<nonce_cache_entry>;
private:
    nonce_set_t used_nonces;

public:

    NonceCache() = default;
    ~NonceCache() = default;

    void purge_expired(clock::time_point current_time = clock::now())
    {
        // TODO: iterate and remove expired nonces from the used_nonces set
    }

    bool contains(nonce_key_pair kp) const
    {
        // TODO: check if the nonce_key_pair exists in the used_nonces set
    }

    bool add(nonce_key_pair kp, clock::time_point current_time = clock::now())
    {
        // TODO: add the nonce_key_pair to the used_nonces set with the current timestamp
    }

    bool seen_or_insert(nonce_key_pair kp)
    {
        // TODO: return true if the key pair has been seen, otherwise insert and return false
    }
    
};