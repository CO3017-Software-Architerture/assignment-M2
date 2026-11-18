#ifndef QRGEN_HPP
#define QRGEN_HPP

#include "main.hpp"
#include "nonce.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sodium.h>
#include <string>
#include <string_view>
#include <vector>

namespace qrgen
{
    inline constexpr std::uint8_t PROTOCOL_VERSION = 0x01;
    inline constexpr std::size_t VERSION_OFFSET = 0;
    inline constexpr std::size_t KEY_ID_OFFSET = 1;
    inline constexpr std::size_t TIMESTAMP_OFFSET = 9;
    inline constexpr std::size_t NONCE_OFFSET = 13;
    inline constexpr std::size_t PAYLOAD_SIZE = 21;
    inline constexpr std::size_t SIGNATURE_SIZE = crypto_sign_BYTES;
    inline constexpr std::size_t QR_RAW_SIZE = PAYLOAD_SIZE + SIGNATURE_SIZE;
    inline constexpr std::string_view DOMAIN_PREFIX = "ACCESS-QR-v1";

    using PublicKey = std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>;
    using SecretKey = std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES>;
    using Seed = std::array<std::uint8_t, crypto_sign_SEEDBYTES>;
    using Signature = std::array<std::uint8_t, crypto_sign_BYTES>;
    using Payload = std::array<std::uint8_t, PAYLOAD_SIZE>;

    template <typename Buffer>
    struct SecretBufferWiper
    {
        Buffer& buffer;
        explicit SecretBufferWiper(Buffer& buf) noexcept : buffer(buf) {}
        ~SecretBufferWiper() noexcept
        {
            sodium_memzero(buffer.data(), buffer.size());
        }
        SecretBufferWiper(const SecretBufferWiper&) = delete;
        SecretBufferWiper& operator=(const SecretBufferWiper&) = delete;
    };

    struct QRContent
    {
        std::uint8_t version{};
        key_id_t key_id{};
        std::uint32_t timestamp{};
        nonce_t nonce{};
        Payload raw_payload{};
        Signature signature{};
    };

    // Shared crypto operations
    bool crypto_init();
    Signature sign(const SecretKey& secret_key, const std::vector<std::uint8_t>& message);
    bool verify(const PublicKey& public_key, const Signature& signature, const std::vector<std::uint8_t>& message);
    key_id_t derive_key_id(const PublicKey& public_key);
    nonce_t random_nonce();

    // Big-endian serialization helpers
    void write_be64(std::uint8_t* dst, std::uint64_t value);
    void write_be32(std::uint8_t* dst, std::uint32_t value);
    std::uint64_t read_be64(const std::uint8_t* src);
    std::uint32_t read_be32(const std::uint8_t* src);

    // Shared QR payload serialization & parsing
    Payload build_payload(key_id_t key_id, std::uint32_t timestamp, const nonce_t& nonce);
    std::vector<std::uint8_t> build_signed_message(const Payload& payload);
    std::string encode_qr_text(const std::vector<std::uint8_t>& bytes);
    std::optional<std::vector<std::uint8_t>> decode_qr_text(std::string_view qr_text);
    std::optional<QRContent> parse_qr(const std::vector<std::uint8_t>& bytes);
    std::optional<QRContent> decode_and_parse_qr(std::string_view qr_text);
} // namespace qrgen

#endif // QRGEN_HPP