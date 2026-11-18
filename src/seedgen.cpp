#include <sodium.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace
{
    using Seed = std::array<unsigned char, crypto_sign_SEEDBYTES>;
    using PublicKey = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>;
    using SecretKey = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>;

    const std::filesystem::path seed_path{"private_seed/client.seed"};

    struct SecretWiper
    {
        Seed& seed;
        SecretKey& secret_key;

        ~SecretWiper()
        {
            sodium_memzero(seed.data(), seed.size());
            sodium_memzero(secret_key.data(), secret_key.size());
        }
    };

    bool load_or_create_seed(Seed& seed)
    {
        if (std::filesystem::exists(seed_path))
        {
            std::ifstream file(seed_path, std::ios::binary);
            if (!file)
                throw std::runtime_error("Cannot open private_seed/client.seed");

            file.read(reinterpret_cast<char*>(seed.data()), seed.size());
            if (file.gcount() != static_cast<std::streamsize>(seed.size()) ||
                file.peek() != std::char_traits<char>::eof())
                throw std::runtime_error("Seed file must contain exactly 32 bytes");
            if (file.bad())
                throw std::runtime_error("Failed to read seed file");

            return true;
        }

        std::filesystem::create_directories(seed_path.parent_path());
        randombytes_buf(seed.data(), seed.size());

        std::ofstream file(seed_path, std::ios::binary);
        if (!file)
            throw std::runtime_error("Cannot create private_seed/client.seed");

        file.write(reinterpret_cast<const char*>(seed.data()), seed.size());
        file.close();
        if (!file)
        {
            std::filesystem::remove(seed_path);
            throw std::runtime_error("Failed to write seed file");
        }

        return false;
    }
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    Seed seed{};
    PublicKey public_key{};
    SecretKey secret_key{};
    SecretWiper wipe_secrets{seed, secret_key};

    try
    {
        const bool seed_was_loaded = load_or_create_seed(seed);
        if (crypto_sign_seed_keypair(public_key.data(), secret_key.data(),
                                     seed.data()) != 0)
            throw std::runtime_error("Failed to create Ed25519 key pair");

        std::array<char, crypto_sign_PUBLICKEYBYTES * 2 + 1> public_key_hex{};
        if (sodium_bin2hex(public_key_hex.data(), public_key_hex.size(),
                           public_key.data(), public_key.size()) == nullptr)
            throw std::runtime_error("Failed to format public key");

        std::cout << public_key_hex.data() << '\n';
        std::cerr << (seed_was_loaded ? "Loaded" : "Created")
                  << " seed at " << seed_path.string() << '\n';
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }

    return 0;
}
