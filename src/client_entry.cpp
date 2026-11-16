#include "client.hpp"

#include <iostream>

namespace
{
    struct SecretKeyWiper
    {
        client::secret_key_t& secret_key;

        ~SecretKeyWiper()
        {
            sodium_memzero(secret_key.data(), secret_key.size());
        }
    };
}

namespace Client
{
    int main(int argc, char const* argv[])
    {
        if (argc != 2)
        {
            std::cerr << "Usage: " << argv[0] << " SECRET_SEED_FILE\n";
            return 1;
        }

        try
        {
            auto loaded = client::load_secret_key(argv[1]);
            SecretKeyWiper wipe_secret_key{loaded.secret_key};
            client::qr_refresh_loop(loaded.secret_key, loaded.key_id);
        }
        catch (const std::exception& error)
        {
            std::cerr << error.what() << '\n';
            return 1;
        }

        return 0;
    }
}
