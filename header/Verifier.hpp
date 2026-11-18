#pragma once

#include "NonceCache.hpp"
#include "PassbackCache.hpp"
#include "barrier.hpp"
#include "qrgen.hpp"
#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <string_view>
#include <vector>

enum class AntiPassbackMode
{
    HARD,
    SOFT,
    Hard = HARD,
    Soft = SOFT
};

struct VerifierConfig
{
    std::chrono::seconds max_age{30};
    std::chrono::seconds max_clock_skew{5};
    AntiPassbackMode anti_passback_mode{AntiPassbackMode::HARD};
    AntiPassbackMode passback_mode{AntiPassbackMode::HARD};
};

class Verifier
{
public:
    using Clock = std::chrono::system_clock;
    using KeyCache = std::map<key_id_t, qrgen::PublicKey>;
    using VerificationRule = std::function<std::optional<Decision>(
        const qrgen::QRContent&, Direction, Clock::time_point,
        NonceCache::Clock::time_point)>;

    Verifier(NonceCache& nonceCache, PassbackCache& passbackCache, Barrier& barrier,
             const KeyCache& keys, VerifierConfig config = {})
        : m_nonceCache(nonceCache), m_passbackCache(passbackCache), m_barrier(barrier),
          m_keys(keys), m_config(config) {}

    static Decision check_timestamp(std::uint32_t ts, Clock::time_point now);
    static Decision check_timestamp(std::uint32_t ts, Clock::time_point now,
                                    std::chrono::seconds max_age,
                                    std::chrono::seconds max_clock_skew);

    void add_verification_rule(VerificationRule rule);
    void add_rule(VerificationRule rule);
    const VerifierConfig& config() const noexcept { return m_config; }

    // Both readers of an area use the same verifier from a serial scan loop.
    Decision handle_scan(std::string_view text, Direction direction, Clock::time_point now,
                         NonceCache::Clock::time_point replay_now = NonceCache::Clock::now());

private:
    NonceCache& m_nonceCache;
    PassbackCache& m_passbackCache;
    Barrier& m_barrier;
    const KeyCache& m_keys;
    VerifierConfig m_config;
    std::vector<VerificationRule> m_verificationRules;
    Decision verify_scan(const qrgen::QRContent& qr, Direction direction, Clock::time_point now,
                         NonceCache::Clock::time_point replay_now);
    bool log_event(Decision decision, std::optional<key_id_t> key_id, Direction direction,
                   Clock::time_point timestamp) const;
    void open_gate();
};

std::string_view decision_name(Decision decision);