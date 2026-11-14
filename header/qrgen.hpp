#ifndef MYLIB_H
#define MYLIB_H

#include "main.hpp"
#include "nonce.hpp"

#include <optional>
#include <string_view>

namespace qrgen
{
    inline constexpr std::uint8_t VERSION = 1;
    inline constexpr std::size_t PAYLOAD_SIZE = 1 + 8 + 4 + NONCE_SIZE;
    inline constexpr std::size_t TOKEN_SIZE = PAYLOAD_SIZE + crypto_sign_BYTES;
    inline constexpr int BASE64_VARIANT = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
    inline constexpr std::size_t TEXT_SIZE =
        sodium_base64_ENCODED_LEN(TOKEN_SIZE, BASE64_VARIANT) - 1;
    inline constexpr std::string_view DOMAIN_PREFIX = "corp-qr-access-v1";

    using PublicKey = std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>;
    using Payload = std::array<std::uint8_t, PAYLOAD_SIZE>;
    using SignedMessage = std::array<std::uint8_t, DOMAIN_PREFIX.size() + PAYLOAD_SIZE>;

    struct QRContent
    {
        std::uint8_t version{};
        std::uint32_t timestamp{};
        nonce_t nonce{};
        key_id_t key_ID{};
        std::array<std::uint8_t, crypto_sign_BYTES> signature{};
        Payload receivedPayload{};
    };

    key_id_t derive_key_id(const PublicKey& key);
    SignedMessage build_signed_message(const Payload& payload);
    std::optional<QRContent> parse_qr(std::string_view text);
    std::string generateCode(/*args*/);
}

#endif
