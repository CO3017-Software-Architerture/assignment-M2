#include <sodium.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <system_error>

namespace
{
    struct SensitiveDataWiper
    {
        std::array<unsigned char, crypto_sign_SEEDBYTES>& seed;
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secret_key;

        ~SensitiveDataWiper()
        {
            sodium_memzero(seed.data(), seed.size());
            sodium_memzero(secret_key.data(), secret_key.size());
        }
    };
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    std::array<unsigned char, crypto_sign_SEEDBYTES> seed{};
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> public_key{};
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key{};
    SensitiveDataWiper wipe_sensitive_data{seed, secret_key};

    randombytes_buf(seed.data(), seed.size());

    if (crypto_sign_seed_keypair(
            public_key.data(), secret_key.data(), seed.data()) != 0)
    {
        std::cerr << "Failed to derive Ed25519 key pair\n";
        return 1;
    }

    const std::filesystem::path seed_path{"private_seed/client.seed"};
    std::error_code error;
    std::filesystem::create_directories(seed_path.parent_path(), error);
    if (error)
    {
        std::cerr << "Cannot create seed directory: " << error.message() << '\n';
        return 1;
    }

    if (std::filesystem::exists(seed_path, error))
    {
        std::cerr << "Seed file already exists; refusing to overwrite "
                  << seed_path.string() << '\n';
        return 1;
    }
    if (error)
    {
        std::cerr << "Cannot check seed file: " << error.message() << '\n';
        return 1;
    }

    std::ofstream file(seed_path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Cannot create seed file: " << seed_path.string() << '\n';
        return 1;
    }
    file.write(reinterpret_cast<const char *>(seed.data()),
               static_cast<std::streamsize>(seed.size()));
    file.close();
    if (!file)
    {
        std::error_code cleanup_error;
        std::filesystem::remove(seed_path, cleanup_error);
        std::cerr << "Cannot write seed file: " << seed_path.string() << '\n';
        return 1;
    }

    std::array<char, crypto_sign_PUBLICKEYBYTES * 2 + 1> hex{};
    if (sodium_bin2hex(hex.data(), hex.size(),
                       public_key.data(), public_key.size()) == nullptr)
    {
        std::cerr << "Cannot encode public key\n";
        return 1;
    }

    std::cout << hex.data() << '\n';
    std::cerr << "Saved 32-byte seed to " << seed_path.string() << '\n';
    std::cerr << "Keep the seed private and do not commit it.\n";

    return 0;
}