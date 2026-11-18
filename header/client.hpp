#ifndef CLIENT_HPP
#define CLIENT_HPP

#include "domain.hpp"
#include "nonce.hpp"
#include "qrgen.hpp"
#include <array>
#include <chrono>
#include <sodium.h>
#include <string>
#include <vector>

namespace client
{
    struct RefreshConfig
    {
        std::chrono::seconds qr_refresh_interval{20};
    };

    using ClientConfig = RefreshConfig;

    inline constexpr std::size_t PAYLOAD_SIZE = qrgen::PAYLOAD_SIZE;

    using public_key_t = qrgen::PublicKey;
    using secret_key_t = qrgen::SecretKey;
    using signature_t = qrgen::Signature;
    using payload_t = qrgen::Payload;

    struct LoadedSecretKey
    {
        secret_key_t secret_key;
        public_key_t public_key;
        key_id_t key_id;
    };

    LoadedSecretKey load_secret_key(const std::string& path);

    std::uint32_t unix_time();
    nonce_t random_nonce();

    payload_t build_payload(
        key_id_t key_id,
        std::uint32_t timestamp,
        const nonce_t& nonce);

    std::vector<std::uint8_t> build_signed_message(
        const payload_t& payload);

    signature_t sign(
        const secret_key_t& secret_key,
        const std::vector<std::uint8_t>& message);

    std::string encode_qr_text(
        const std::vector<std::uint8_t>& bytes);

    std::string generate_qr_at(
        const secret_key_t& secret_key,
        key_id_t key_id,
        std::uint32_t timestamp,
        const nonce_t& nonce);

    std::string generate_qr(
        const secret_key_t& secret_key,
        key_id_t key_id);

    std::string render_qr_terminal(const std::string& qr_text);

    void qr_refresh_loop(
        const secret_key_t& secret_key,
        key_id_t key_id,
        RefreshConfig config = {});
} // namespace client

#endif // CLIENT_HPP