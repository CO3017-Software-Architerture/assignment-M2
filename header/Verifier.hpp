#pragma once

#include "NonceCache.hpp"
#include "PassbackCache.hpp"
#include "barrier.hpp"
#include "qrgen.hpp"

class Verifier
{
public:
    using Clock = std::chrono::system_clock;
    using KeyCache = std::map<key_id_t, qrgen::PublicKey>;

    Verifier(NonceCache& nonceCache, PassbackCache& passbackCache, Barrier& barrier,
             const KeyCache& keys)
        : m_nonceCache(nonceCache), m_passbackCache(passbackCache), m_barrier(barrier), m_keys(keys) {}

    // Both readers of an area use the same verifier from a serial scan loop.
    Decision handle_scan(std::string_view text, Direction direction, Clock::time_point now,
                         NonceCache::Clock::time_point replay_now = NonceCache::Clock::now());

private:
    NonceCache& m_nonceCache;
    PassbackCache& m_passbackCache;
    Barrier& m_barrier;
    const KeyCache& m_keys;
    Decision verify_scan(const qrgen::QRContent& qr, Direction direction, Clock::time_point now,
                         NonceCache::Clock::time_point replay_now);
    bool log_event(Decision decision, std::optional<key_id_t> key_id, Direction direction,
                   Clock::time_point timestamp) const;
    void open_gate();
};

std::string_view decision_name(Decision decision);
