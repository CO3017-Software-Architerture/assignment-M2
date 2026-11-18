#include "client.hpp"

#include "qrcodegen.hpp"
#include "qrgen.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace
{
    constexpr std::size_t KEY_ID_OFFSET = 1;
    constexpr std::size_t TIMESTAMP_OFFSET = KEY_ID_OFFSET + sizeof(key_id_t);
    constexpr std::size_t NONCE_OFFSET = TIMESTAMP_OFFSET + sizeof(std::uint32_t);

    void initialize_sodium()
    {
        if (sodium_init() < 0)
            throw std::runtime_error("Failed to initialize libsodium");
    }

    struct SeedWiper
    {
        std::array<std::uint8_t, crypto_sign_SEEDBYTES> &seed;

        ~SeedWiper()
        {
            sodium_memzero(seed.data(), seed.size());
        }
    };

    struct SecretKeyWiper
    {
        client::secret_key_t &secret_key;

        ~SecretKeyWiper()
        {
            sodium_memzero(secret_key.data(), secret_key.size());
        }
    };
}

client::LoadedSecretKey client::load_secret_key(const std::string &path)
{
    initialize_sodium();

    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("Cannot open secret seed file: " + path);

    std::array<std::uint8_t, crypto_sign_SEEDBYTES> seed{};
    SeedWiper wipe_seed{seed};
    input.read(reinterpret_cast<char *>(seed.data()),
               static_cast<std::streamsize>(seed.size()));
    if (input.gcount() != static_cast<std::streamsize>(seed.size()) ||
        input.peek() != std::char_traits<char>::eof())
        throw std::runtime_error("Secret seed file must contain exactly 32 bytes");
    if (input.bad())
        throw std::runtime_error("Failed to read secret seed file: " + path);

    LoadedSecretKey loaded{};
    if (crypto_sign_seed_keypair(loaded.public_key.data(), loaded.secret_key.data(),
                                 seed.data()) != 0)
        throw std::runtime_error("Cannot derive Ed25519 key pair from secret seed");

    loaded.key_id = qrgen::derive_key_id(loaded.public_key);
    return loaded;
}

std::uint32_t client::unix_time()
{
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    if (seconds < 0)
        throw std::runtime_error("System clock is before the Unix epoch");

    return static_cast<std::uint32_t>(seconds);
}

nonce_t client::random_nonce()
{
    initialize_sodium();

    nonce_t nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

client::payload_t client::build_payload(key_id_t key_id, std::uint32_t timestamp,
                                        const nonce_t &nonce)
{
    payload_t payload{};
    payload[0] = qrgen::VERSION;

    // Store multi-byte numbers in big-endian order for the verifier.
    for (std::size_t i = 0; i < sizeof(key_id); ++i)
        payload[KEY_ID_OFFSET + i] =
            static_cast<std::uint8_t>(key_id >> (8 * (sizeof(key_id) - 1 - i)));

    for (std::size_t i = 0; i < sizeof(timestamp); ++i)
        payload[TIMESTAMP_OFFSET + i] =
            static_cast<std::uint8_t>(timestamp >> (8 * (sizeof(timestamp) - 1 - i)));

    std::copy(nonce.begin(), nonce.end(), payload.begin() + NONCE_OFFSET);
    return payload;
}

std::vector<std::uint8_t> client::build_signed_message(const payload_t &payload)
{
    const auto message = qrgen::build_signed_message(payload);
    return {message.begin(), message.end()};
}

client::signature_t client::sign(const secret_key_t &secret_key,
                                 const std::vector<std::uint8_t> &message)
{
    initialize_sodium();

    signature_t signature{};
    if (crypto_sign_detached(signature.data(), nullptr, message.data(), message.size(),
                             secret_key.data()) != 0)
        throw std::runtime_error("Failed to sign QR payload");
    return signature;
}

std::string client::encode_qr_text(const std::vector<std::uint8_t> &bytes)
{
    initialize_sodium();

    std::vector<char> encoded(
        sodium_base64_ENCODED_LEN(bytes.size(), qrgen::BASE64_VARIANT));
    if (sodium_bin2base64(encoded.data(), encoded.size(), bytes.data(), bytes.size(),
                          qrgen::BASE64_VARIANT) == nullptr)
        throw std::runtime_error("Failed to encode QR payload");
    return std::string(encoded.data());
}

std::string client::generate_qr(const secret_key_t &secret_key, key_id_t key_id)
{
    const auto payload = build_payload(key_id, unix_time(), random_nonce());
    const auto message = build_signed_message(payload);
    const auto signature = sign(secret_key, message);

    std::vector<std::uint8_t> token;
    token.reserve(payload.size() + signature.size());
    token.insert(token.end(), payload.begin(), payload.end());
    token.insert(token.end(), signature.begin(), signature.end());
    return encode_qr_text(token);
}

std::string client::render_qr_terminal(const std::string &qr_text)
{
    const auto qr = qrcodegen::QrCode::encodeText(
        qr_text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    constexpr int QUIET_ZONE = 4;
    const auto size = qr.getSize();
    const auto width = static_cast<std::size_t>(size + 2 * QUIET_ZONE);

    std::string output;
    output.reserve(width * (2 * width + 1));
    for (int y = -QUIET_ZONE; y < size + QUIET_ZONE; ++y)
    {
        bool have_background = false;
        bool previous_dark = false;
        for (int x = -QUIET_ZONE; x < size + QUIET_ZONE; ++x)
        {
            const bool dark = qr.getModule(x, y);
            if (!have_background || dark != previous_dark)
            {
                output += dark ? "\x1b[40m" : "\x1b[47m";
                previous_dark = dark;
                have_background = true;
            }
            output += "  ";
        }
        output += "\x1b[0m";
        output.push_back('\n');
    }
    return output;
}

void client::qr_refresh_loop(const secret_key_t &secret_key, key_id_t key_id)
{
    while (true)
    {
        const auto qr_text = generate_qr(secret_key, key_id);
        std::cout << "Scan QR:\n"
                  << render_qr_terminal(qr_text)
                  << "\nQR text: " << qr_text << '\n'
                  << std::flush;
        if (!std::cout)
            throw std::runtime_error("Failed to write QR code to terminal");
        std::this_thread::sleep_for(std::chrono::seconds{20});
    }
}
