#include "server.hpp"
#include "Verifier.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace
{
    Verifier::KeyCache load_keys(int argc, char const* argv[])
    {
        Verifier::KeyCache keys;
        for (int i = 1; i < argc; ++i)
        {
            const std::string_view hex{argv[i]};
            qrgen::PublicKey key{};
            std::size_t size = 0;
            if (hex.size() != key.size() * 2 ||
                sodium_hex2bin(key.data(), key.size(), hex.data(), hex.size(),
                               nullptr, &size, nullptr) != 0 || size != key.size())
                throw std::invalid_argument("Expected each public key as 64 hex characters");

            const auto key_id = qrgen::derive_key_id(key);
            if (!keys.emplace(key_id, key).second)
                throw std::invalid_argument("Duplicate public key ID");
        }
        return keys;
    }

    // Retain one byte past the maximum so oversized lines are always rejected.
    std::optional<std::string> read_scan()
    {
        constexpr auto max_line_size = qrgen::TEXT_SIZE + sizeof("OUT ");
        std::string line;
        for (char ch; std::cin.get(ch);)
        {
            if (ch == '\n')
                return line;
            if (line.size() <= max_line_size)
                line.push_back(ch);
        }
        if (!line.empty() && std::cin.eof() && !std::cin.bad())
            return line;
        return std::nullopt;
    }
}

int server::main(int argc, char const* argv[])
{
    // TODO remove the PUBLIC KEY HEX argument take in
    // load dictionary from a file of any type you want that contain [(employees key_id from qr->key_id ref: docs/Security Flow.md:44; header/qrgen.hpp:29);(employee public hex key id generated from ref:src/seedgen.cpp)]
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " PUBLIC_KEY_HEX [PUBLIC_KEY_HEX ...]\n"
                  << "Enter IN <qr_text> or OUT <qr_text> on stdin.\n";
        return EXIT_FAILURE;
    }
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium\n";
        return EXIT_FAILURE;
    }

    try
    {
        const auto keys = load_keys(argc, argv);
        NonceCache nonceCache;
        PassbackCache passbackCache;
        Barrier barrier;
        Verifier verifier(nonceCache, passbackCache, barrier, keys);
        while (const auto line = read_scan())
        {
            std::string_view record{*line};
            if (!record.empty() && record.back() == '\r')
                record.remove_suffix(1);

            auto direction = static_cast<Direction>(-1);
            std::string_view qr_text;
            if (record.substr(0, 3) == "IN ")
            {
                direction = Direction::IN;
                qr_text = record.substr(3);
            }
            else if (record.substr(0, 4) == "OUT ")
            {
                direction = Direction::OUT;
                qr_text = record.substr(4);
            }
            const auto decision = verifier.handle_scan(qr_text, direction, Verifier::Clock::now());
            std::cout << decision_name(decision) << std::endl;
        }
        if (std::cin.bad() || !std::cin.eof())
        {
            std::cerr << "Failed to read scanner input\n";
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
