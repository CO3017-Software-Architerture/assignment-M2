#include "qrgen.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <string>

int main(int argc, char const* argv[])
{
    if (!qrgen::crypto_init())
    {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    const std::filesystem::path seed_path =
        (argc > 1) ? std::filesystem::path(argv[1]) : std::filesystem::path("private_seed/client.seed");

    if (seed_path.has_parent_path())
    {
        std::filesystem::create_directories(seed_path.parent_path());
    }

    qrgen::Seed seed{};
    qrgen::SecretBufferWiper<qrgen::Seed> seed_wiper(seed);
    randombytes_buf(seed.data(), seed.size());

    std::ofstream out(seed_path, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "Failed to open output seed file: " << seed_path.string() << '\n';
        return 1;
    }
    out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
    out.close();

    qrgen::PublicKey pk{};
    qrgen::SecretKey sk{};
    qrgen::SecretBufferWiper<qrgen::SecretKey> sk_wiper(sk);

    if (crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data()) != 0)
    {
        std::cerr << "Failed to derive keypair\n";
        return 1;
    }

    const key_id_t key_id = qrgen::derive_key_id(pk);
    char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1]{};
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk.data(), pk.size());

    std::cout << "Seed written to: " << seed_path.string() << '\n'
              << "key_id: 0x" << std::hex << std::setw(16) << std::setfill('0') << key_id << std::dec << '\n'
              << "public_key_hex: " << pk_hex << '\n';
    return 0;
}