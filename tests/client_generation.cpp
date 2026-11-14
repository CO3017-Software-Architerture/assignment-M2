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

    assert(payload[0] == qrgen::VERSION);
    for (std::size_t i = 0; i < 8; ++i)
        assert(payload[1 + i] == i + 1);
    assert(payload[9] == 0x11);
    assert(payload[10] == 0x22);
    assert(payload[11] == 0x33);
    assert(payload[12] == 0x44);
    for (std::size_t i = 0; i < test_nonce.size(); ++i)
        assert(payload[13 + i] == test_nonce[i]);

    std::array<std::uint8_t, crypto_sign_SEEDBYTES> seed{};
    client::LoadedSecretKey keys{};
    randombytes_buf(seed.data(), seed.size());
    assert(crypto_sign_seed_keypair(keys.public_key.data(), keys.secret_key.data(),
                                    seed.data()) == 0);
    keys.key_id = qrgen::derive_key_id(keys.public_key);

    const auto text = client::generate_qr(keys.secret_key, keys.key_id);
    assert(text.size() == qrgen::TEXT_SIZE);

    const auto parsed = qrgen::parse_qr(text);
    assert(parsed);
    assert(parsed->version == qrgen::VERSION);
    assert(parsed->key_ID == keys.key_id);

    const auto message = qrgen::build_signed_message(parsed->receivedPayload);
    assert(crypto_sign_verify_detached(parsed->signature.data(), message.data(),
                                       message.size(), keys.public_key.data()) == 0);

    sodium_memzero(seed.data(), seed.size());
    sodium_memzero(keys.secret_key.data(), keys.secret_key.size());
    std::cout << "Client generation tests passed\n";
}
