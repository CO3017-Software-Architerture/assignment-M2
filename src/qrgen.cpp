#include "qrgen.hpp"

#include <algorithm>
#include <stdexcept>

namespace
{
    template <typename UInt>
    UInt read_big_endian(const std::uint8_t* bytes)
    {
        UInt value = 0;
        for (std::size_t i = 0; i < sizeof(UInt); ++i)
            value = (value << 8) | bytes[i];
        return value;
    }
}

namespace qrgen
{
    key_id_t derive_key_id(const PublicKey& key)
    {
        std::array<std::uint8_t, crypto_hash_sha256_BYTES> digest{};
        if (crypto_hash_sha256(digest.data(), key.data(), key.size()) != 0)
            throw std::runtime_error("Cannot derive public key ID");

        return read_big_endian<key_id_t>(digest.data());
    }

    SignedMessage build_signed_message(const Payload& payload)
    {
        SignedMessage message{};
        const auto start = std::copy(DOMAIN_PREFIX.begin(), DOMAIN_PREFIX.end(), message.begin());
        std::copy(payload.begin(), payload.end(), start);
        return message;
    }

    std::optional<QRContent> parse_qr(std::string_view text)
    {
        if (text.size() != TEXT_SIZE)
            return std::nullopt;

        std::array<std::uint8_t, TOKEN_SIZE> bytes{};
        std::size_t size = 0;
        const char* end = nullptr;
        if (sodium_base642bin(bytes.data(), bytes.size(), text.data(), text.size(),
                             nullptr, &size, &end, BASE64_VARIANT) != 0 ||
            size != bytes.size() || end != text.data() + text.size() || bytes[0] != VERSION)
            return std::nullopt;

        QRContent qr{};
        constexpr std::size_t key_offset = 1;
        constexpr std::size_t timestamp_offset = key_offset + sizeof(key_id_t);
        constexpr std::size_t nonce_offset = timestamp_offset + sizeof(std::uint32_t);
        qr.version = bytes[0];
        qr.key_ID = read_big_endian<key_id_t>(bytes.data() + key_offset);
        qr.timestamp = read_big_endian<std::uint32_t>(bytes.data() + timestamp_offset);
        std::copy_n(bytes.begin() + nonce_offset, qr.nonce.size(), qr.nonce.begin());
        std::copy_n(bytes.begin(), qr.receivedPayload.size(), qr.receivedPayload.begin());
        std::copy_n(bytes.begin() + PAYLOAD_SIZE, qr.signature.size(), qr.signature.begin());
        return qr;
    }

    std::string generateCode()
    {
        return std::string();
    }
}
