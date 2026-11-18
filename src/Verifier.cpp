#include "Verifier.hpp"

#include <exception>
#include <iostream>

namespace
{
    constexpr std::int64_t MAX_AGE_SECONDS = 30;
    constexpr std::int64_t MAX_CLOCK_SKEW_SECONDS = 5;

    auto unix_seconds(Verifier::Clock::time_point time)
    {
        return std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
    }

    std::int64_t timestamp_delta(Verifier::Clock::time_point now, std::uint32_t timestamp)
    {
        // Interpret the modular difference as signed without a narrowing conversion.
        const std::uint32_t delta = static_cast<std::uint32_t>(unix_seconds(now)) - timestamp;
        constexpr std::int64_t range = std::int64_t{1} << 32;
        return delta < range / 2 ? delta : delta - range;
    }
}

std::string_view decision_name(Decision decision)
{
    switch (decision)
    {
        case Decision::ALLOW: return "ALLOW";
        case Decision::BAD_SIGNATURE: return "BAD_SIGNATURE";
        case Decision::EXPIRED: return "EXPIRED";
        case Decision::FUTURE: return "FUTURE";
        case Decision::REPLAY: return "REPLAY";
        case Decision::UNKNOWN_KEY: return "UNKNOWN_KEY";
        case Decision::PASSBACK: return "PASSBACK";
        case Decision::MALFORMED: return "MALFORMED";
        case Decision::INTERNAL_ERROR: return "INTERNAL_ERROR";
    }
    return "INTERNAL_ERROR";
}

Decision Verifier::verify_scan(const qrgen::QRContent& qr, Direction direction, Clock::time_point now,
                               NonceCache::Clock::time_point replay_now)
{
    // The QR identifies a key from the locally provisioned allowlist.
    const auto key = m_keys.find(qr.key_ID);
    if (key == m_keys.end())
        return Decision::UNKNOWN_KEY;

    const auto message = qrgen::build_signed_message(qr.receivedPayload);
    if (crypto_sign_verify_detached(qr.signature.data(), message.data(), message.size(),
                                    key->second.data()) != 0)
        return Decision::BAD_SIGNATURE;

    const auto delta = timestamp_delta(now, qr.timestamp);
    if (delta > MAX_AGE_SECONDS)
        return Decision::EXPIRED;
    if (delta < -MAX_CLOCK_SKEW_SECONDS)
        return Decision::FUTURE;
    if (m_nonceCache.seen_or_insert({qr.key_ID, qr.nonce}, replay_now))
        return Decision::REPLAY;
    if (!m_passbackCache.check_anti_passback(qr.key_ID, direction))
        return Decision::PASSBACK;
    return Decision::ALLOW;
}

Decision Verifier::handle_scan(std::string_view text, Direction direction, Clock::time_point now,
                               NonceCache::Clock::time_point replay_now)
{
    m_barrier.CloseGate();
    std::optional<key_id_t> key_id;
    try
    {
        m_nonceCache.purge_expired(replay_now);
        const auto qr = qrgen::parse_qr(text);
        auto decision = Decision::MALFORMED;
        if (qr && (direction == Direction::IN || direction == Direction::OUT))
        {
            key_id = qr->key_ID;
            decision = verify_scan(*qr, direction, now, replay_now);
        }
        if (!log_event(decision, key_id, direction, now))
            return Decision::INTERNAL_ERROR;

        if (decision == Decision::ALLOW)
        {
            if (!m_passbackCache.commit_passback(*key_id, direction))
            {
                log_event(Decision::INTERNAL_ERROR, key_id, direction, now);
                return Decision::INTERNAL_ERROR;
            }
            open_gate();
        }
        return decision;
    }
    catch (const std::exception&)
    {
        log_event(Decision::INTERNAL_ERROR, key_id, direction, now);
        return Decision::INTERNAL_ERROR;
    }
}

bool Verifier::log_event(Decision decision, std::optional<key_id_t> key_id, Direction direction,
                         Clock::time_point timestamp) const
{
    const char* reader = "UNKNOWN";
    if (direction == Direction::IN)
        reader = "IN";
    else if (direction == Direction::OUT)
        reader = "OUT";

    std::clog << "scan time=" << unix_seconds(timestamp) << " direction=" << reader
              << " decision=" << decision_name(decision) << " key_id=";
    if (key_id)
        std::clog << *key_id;
    else
        std::clog << '-';
    std::clog << '\n' << std::flush;
    return static_cast<bool>(std::clog);
}

void Verifier::open_gate()
{
    m_barrier.OpenGate();
}
