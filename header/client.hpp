#ifndef CLIENT_HPP
#define CLIENT_HPP


#include <sodium.h>
#include <array>
#include <main.hpp>
#include "nonce.hpp"

namespace client
{
    inline constexpr std::size_t PAYLOAD_SIZE = 21;

    using public_key_t = std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>;
    using secret_key_t = std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES>;
    using signature_t = std::array<std::uint8_t, crypto_sign_BYTES>;
    using payload_t = std::array<std::uint8_t, PAYLOAD_SIZE>;

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

    std::string generate_qr(
        const secret_key_t& secret_key,
        key_id_t key_id);

    void qr_refresh_loop(
        const secret_key_t& secret_key,
        key_id_t key_id);
}

#endif // CLIENT_HPP
