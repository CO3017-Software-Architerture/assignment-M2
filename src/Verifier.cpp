#include "Verifier.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>

// decision_name is defined in header/IFacade.hpp

Decision Verifier::check_timestamp(std::uint32_t ts, Clock::time_point now)
{
    return check_timestamp(ts, now, std::chrono::seconds{30}, std::chrono::seconds{5});
}

Decision Verifier::check_timestamp(std::uint32_t ts, Clock::time_point now,
                                   std::chrono::seconds max_age,
                                   std::chrono::seconds max_clock_skew)
{
    const auto now_secs =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    const auto now_u32 = static_cast<std::uint32_t>(static_cast<std::uint64_t>(now_secs));
    const auto delta = static_cast<std::int32_t>(now_u32 - ts);

    if (delta > max_age.count())
    {
        return Decision::EXPIRED;
    }
    if (delta < -max_clock_skew.count())
    {
        return Decision::FUTURE;
    }
    return Decision::ALLOW;
}

void Verifier::add_verification_rule(VerificationRule rule)
{
    if (rule)
    {
        m_verificationRules.push_back(std::move(rule));
    }
}

void Verifier::add_rule(VerificationRule rule)
{
    add_verification_rule(std::move(rule));
}

Decision Verifier::handle_scan(
    std::string_view text,
    Direction direction,
    Clock::time_point now,
    NonceCache::Clock::time_point replay_now)
{
    m_barrier.CloseGate();
    m_nonceCache.purge_expired(replay_now);

    try
    {
        const auto parsed = qrgen::decode_and_parse_qr(text);
        if (!parsed.has_value())
        {
            log_event(Decision::MALFORMED, std::nullopt, direction, now);
            return Decision::MALFORMED;
        }

        const Decision decision = verify_scan(*parsed, direction, now, replay_now);
        log_event(decision, parsed->key_id, direction, now);
        if (decision == Decision::ALLOW)
        {
            open_gate();
        }
        return decision;
    }
    catch (...)
    {
        log_event(Decision::INTERNAL_ERROR, std::nullopt, direction, now);
        return Decision::INTERNAL_ERROR;
    }
}

Decision Verifier::verify_scan(
    const qrgen::QRContent& qr,
    Direction direction,
    Clock::time_point now,
    NonceCache::Clock::time_point replay_now)
{
    const auto key_it = m_keys.find(qr.key_id);
    if (key_it == m_keys.end())
    {
        return Decision::UNKNOWN_KEY;
    }

    const auto signed_message = qrgen::build_signed_message(qr.raw_payload);
    if (!qrgen::verify(key_it->second, qr.signature, signed_message))
    {
        return Decision::BAD_SIGNATURE;
    }

    const Decision ts_decision = check_timestamp(
        qr.timestamp, now, m_config.max_age, m_config.max_clock_skew);
    if (ts_decision != Decision::ALLOW)
    {
        return ts_decision;
    }

    if (m_nonceCache.seen_or_insert({qr.key_id, qr.nonce}, replay_now))
    {
        return Decision::REPLAY;
    }

    for (const auto& rule : m_verificationRules)
    {
        const auto rule_decision =
            rule(qr, direction, now, replay_now);
        if (rule_decision.has_value())
        {
            return *rule_decision;
        }
    }

    if (!m_passbackCache.check_anti_passback(qr.key_id, direction))
    {
        const bool soft_mode =
            m_config.anti_passback_mode == AntiPassbackMode::SOFT ||
            m_config.passback_mode == AntiPassbackMode::SOFT;
        if (!soft_mode)
        {
            return Decision::PASSBACK;
        }

        std::cerr << "[AUDIT] soft anti-passback warning"
                  << " key_id=" << qr.key_id
                  << " dir=" << ((direction == Direction::IN) ? "IN" : "OUT") << '\n';
    }

    m_passbackCache.commit_passback(qr.key_id, direction);
    return Decision::ALLOW;
}

bool Verifier::log_event(
    Decision decision,
    std::optional<key_id_t> key_id,
    Direction direction,
    Clock::time_point timestamp) const
{
    const auto secs =
        std::chrono::duration_cast<std::chrono::seconds>(timestamp.time_since_epoch()).count();
    const char* dir_str = (direction == Direction::IN) ? "IN" : "OUT";

    std::cout << "[AUDIT] ts=" << secs
              << " dir=" << dir_str
              << " key_id=";
    if (key_id.has_value())
    {
        std::ios_base::fmtflags flags(std::cout.flags());
        std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << *key_id;
        std::cout.flags(flags);
    }
    else
    {
        std::cout << "none";
    }
    std::cout << " decision=" << decision_name(decision) << '\n';
    return true;
}

void Verifier::open_gate()
{
    m_barrier.OpenGate();
}