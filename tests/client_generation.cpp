#include "client.hpp"
#include "qrgen.hpp"

#include <cassert>
#include <iostream>

int main()
{
    if (sodium_init() < 0)
        return 1;

    constexpr key_id_t test_key_id = 0x0102030405060708ULL;
    constexpr std::uint32_t test_timestamp = 0x11223344;
    const nonce_t test_nonce{0, 1, 2, 3, 4, 5, 6, 7};
    const auto payload = client::build_payload(test_key_id, test_timestamp, test_nonce);

    // Check the payload fields and their big-endian byte order.
    assert(payload[0] == qrgen::VERSION);
    for (std::size_t i = 0; i < 8; ++i)
        assert(payload[1 + i] == static_cast<std::uint8_t>(i + 1));
    assert(payload[9] == static_cast<std::uint8_t>(0x11));
    assert(payload[10] == static_cast<std::uint8_t>(0x22));
    assert(payload[11] == static_cast<std::uint8_t>(0x33));
    assert(payload[12] == static_cast<std::uint8_t>(0x44));
    for (std::size_t i = 0; i < test_nonce.size(); ++i)
        assert(payload[13 + i] == test_nonce[i]);

    // Create a temporary key pair for the QR-generation test.
    std::array<std::uint8_t, crypto_sign_SEEDBYTES> seed{};
    client::LoadedSecretKey key_pair{};
    randombytes_buf(seed.data(), seed.size());
    assert(crypto_sign_seed_keypair(key_pair.public_key.data(), key_pair.secret_key.data(),
                                    seed.data()) == 0);
    key_pair.key_id = qrgen::derive_key_id(key_pair.public_key);

    const auto qr_text = client::generate_qr(key_pair.secret_key, key_pair.key_id);
    assert(qr_text.size() == qrgen::TEXT_SIZE);

    const auto qr = qrgen::parse_qr(qr_text);
    assert(qr);
    assert(qr->version == qrgen::VERSION);
    assert(qr->key_ID == key_pair.key_id);

    // Verify that the server-side public key accepts the generated signature.
    const auto message = qrgen::build_signed_message(qr->receivedPayload);
    assert(crypto_sign_verify_detached(qr->signature.data(), message.data(),
                                       message.size(), key_pair.public_key.data()) == 0);

    sodium_memzero(seed.data(), seed.size());
    sodium_memzero(key_pair.secret_key.data(), key_pair.secret_key.size());
    std::cout << "Client generation tests passed\n";
}
