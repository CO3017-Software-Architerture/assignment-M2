#include "client_entry.hpp"
#include "client.hpp"
#include "qrgen.hpp"
#include <iostream>
#include <string>

namespace client
{
    int main(int argc, char const* argv[])
    {
        const std::string seed_path = (argc > 1) ? argv[1] : "private_seed/client.seed";
        try
        {
            if (!qrgen::crypto_init())
            {
                std::cerr << "Error: Failed to initialize libsodium\n";
                return 1;
            }

            auto loaded = client::load_secret_key(seed_path);
            qrgen::SecretBufferWiper<client::secret_key_t> secret_wiper(loaded.secret_key);

            if (argc > 2 && std::string_view(argv[2]) == "--once")
            {
                std::cout << client::generate_qr(loaded.secret_key, loaded.key_id) << '\n';
                return 0;
            }

            client::qr_refresh_loop(loaded.secret_key, loaded.key_id);
            return 0;
        }
        catch (const std::exception& ex)
        {
            std::cerr << "Error: " << ex.what() << '\n';
            return 1;
        }
    }
} // namespace client

namespace Client
{
    int main(int argc, char const* argv[])
    {
        return client::main(argc, argv);
    }
}
