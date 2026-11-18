#include "client.hpp"
#include "nonce.hpp"
#include "qrcodegen.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace client
{
    LoadedSecretKey load_secret_key(const std::string& path)
    {
        if (!qrgen::crypto_init())
        {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            throw std::runtime_error("Unable to open seed file: " + path);
        }

        qrgen::Seed seed{};
        qrgen::SecretBufferWiper<qrgen::Seed> seed_wiper(seed);

        file.read(reinterpret_cast<char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (file.gcount() != static_cast<std::streamsize>(seed.size()) || file.peek() != std::ifstream::traits_type::eof())
        {
            throw std::runtime_error("Seed file must contain exactly 32 bytes: " + path);
        }

        LoadedSecretKey loaded{};
        if (crypto_sign_seed_keypair(loaded.public_key.data(), loaded.secret_key.data(), seed.data()) != 0)
        {
            sodium_memzero(loaded.secret_key.data(), loaded.secret_key.size());
            throw std::runtime_error("Failed to derive Ed25519 keypair from seed");
        }

        loaded.key_id = qrgen::derive_key_id(loaded.public_key);
        return loaded;
    }

    std::uint32_t unix_time()
    {
        const auto now = std::chrono::system_clock::now();
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return static_cast<std::uint32_t>(static_cast<std::uint64_t>(secs));
    }

    nonce_t random_nonce()
    {
        return generate_nonce();
    }

    payload_t build_payload(key_id_t key_id, std::uint32_t timestamp, const nonce_t& nonce)
    {
        return qrgen::build_payload(key_id, timestamp, nonce);
    }

    std::vector<std::uint8_t> build_signed_message(const payload_t& payload)
    {
        return qrgen::build_signed_message(payload);
    }

    signature_t sign(const secret_key_t& secret_key, const std::vector<std::uint8_t>& message)
    {
        return qrgen::sign(secret_key, message);
    }

    std::string encode_qr_text(const std::vector<std::uint8_t>& bytes)
    {
        return qrgen::encode_qr_text(bytes);
    }

    std::string generate_qr_at(
        const secret_key_t& secret_key,
        key_id_t key_id,
        std::uint32_t timestamp,
        const nonce_t& nonce)
    {
        const payload_t payload = build_payload(key_id, timestamp, nonce);
        const std::vector<std::uint8_t> signed_msg = build_signed_message(payload);
        const signature_t sig = sign(secret_key, signed_msg);

        std::vector<std::uint8_t> raw_qr;
        raw_qr.reserve(payload.size() + sig.size());
        raw_qr.insert(raw_qr.end(), payload.begin(), payload.end());
        raw_qr.insert(raw_qr.end(), sig.begin(), sig.end());

        return encode_qr_text(raw_qr);
    }

    std::string generate_qr(const secret_key_t& secret_key, key_id_t key_id)
    {
        return generate_qr_at(secret_key, key_id, unix_time(), random_nonce());
    }

    std::string render_qr_terminal(const std::string& qr_text)
    {
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
            qr_text.c_str(), qrcodegen::QrCode::Ecc::LOW);

        std::ostringstream out;
        constexpr int border = 2;
        for (int y = -border; y < qr.getSize() + border; ++y)
        {
            for (int x = -border; x < qr.getSize() + border; ++x)
            {
                out << (qr.getModule(x, y) ? "\033[40m  \033[0m" : "\033[47m  \033[0m");
            }
            out << '\n';
        }
        return out.str();
    }

    void qr_refresh_loop(const secret_key_t& secret_key, key_id_t key_id,
                         RefreshConfig config)
    {
        while (true)
        {
            const std::string qr_text = generate_qr(secret_key, key_id);
            std::cout << render_qr_terminal(qr_text)
                      << "\nQR Text: " << qr_text << std::endl;
            std::this_thread::sleep_for(config.qr_refresh_interval);
        }
    }
} // namespace client