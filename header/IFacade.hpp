#pragma once

#include "NonceStore.hpp"
#include "PassbackStore.hpp"
#include "domain.hpp"
#include "nonce.hpp"
#include "qrgen.hpp"

#include <chrono>
#include <iostream>
#include <map>
#include <optional>
#include <ostream>
#include <string_view>

inline std::string_view decision_name(Decision decision)
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

class IBarrier
{
public:
    virtual ~IBarrier() = default;

    virtual void OpenGate() = 0;
    virtual void CloseGate() = 0;
    virtual bool isOpen() const = 0;
};

class IKeyStore
{
public:
    virtual ~IKeyStore() = default;

    virtual std::optional<qrgen::PublicKey> find_public_key(key_id_t key_id) const = 0;
};

class MapKeyStore final : public IKeyStore
{
public:
    using KeyMap = std::map<key_id_t, qrgen::PublicKey>;

    explicit MapKeyStore(const KeyMap& keys) : m_keys(keys) {}

    std::optional<qrgen::PublicKey> find_public_key(key_id_t key_id) const override
    {
        const auto it = m_keys.find(key_id);
        if (it == m_keys.end())
            return std::nullopt;
        return it->second;
    }

private:
    const KeyMap& m_keys;
};

class IAuditLogger
{
public:
    using Clock = std::chrono::system_clock;
    virtual ~IAuditLogger() = default;

    virtual bool log_event(Decision decision, std::optional<key_id_t> key_id,
                           Direction direction, Clock::time_point timestamp) = 0;
};

class StreamAuditLogger final : public IAuditLogger
{
public:
    explicit StreamAuditLogger(std::ostream& stream = std::clog) : m_stream(stream) {}

    bool log_event(Decision decision, std::optional<key_id_t> key_id,
                   Direction direction, Clock::time_point timestamp) override
    {
        const char* reader = "UNKNOWN";
        if (direction == Direction::IN)
            reader = "IN";
        else if (direction == Direction::OUT)
            reader = "OUT";

        const auto unix_sec =
            std::chrono::duration_cast<std::chrono::seconds>(timestamp.time_since_epoch()).count();

        m_stream << "scan time=" << unix_sec << " direction=" << reader
                 << " decision=" << decision_name(decision) << " key_id=";
        if (key_id)
            m_stream << *key_id;
        else
            m_stream << '-';
        m_stream << '\n' << std::flush;
        return static_cast<bool>(m_stream);
    }

private:
    std::ostream& m_stream;
};

class NullAuditLogger final : public IAuditLogger
{
public:
    bool log_event(Decision, std::optional<key_id_t>, Direction, Clock::time_point) override
    {
        return true;
    }
};