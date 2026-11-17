#include "server.hpp"
#include "Verifier.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace
{
    constexpr auto DEFAULT_KEYS_FILE = "employee_public_keys.txt";

    Verifier::KeyCache load_key_file(const std::string& path)
    {
        std::ifstream file(path);
        if (!file)
            throw std::runtime_error("Cannot open employee public key file: " + path);

        Verifier::KeyCache keys;
        std::string line;
        std::size_t line_number = 0;
        while (std::getline(file, line))
        {
            ++line_number;
            const auto start = line.find_first_not_of(" \t\r");
            if (start == std::string::npos)
                continue;
            const auto end = line.find_last_not_of(" \t\r");
            const auto hex = std::string_view(line).substr(start, end - start + 1);
            qrgen::PublicKey key{};
            std::size_t size = 0;
            if (hex.size() != key.size() * 2 ||
                sodium_hex2bin(key.data(), key.size(), hex.data(), hex.size(),
                               nullptr, &size, nullptr) != 0 || size != key.size())
                throw std::runtime_error(path + ":" + std::to_string(line_number) +
                                         ": expected an Ed25519 public key as 64 hex characters");

            const auto key_id = qrgen::derive_key_id(key);
            if (!keys.emplace(key_id, key).second)
                throw std::runtime_error(path + ":" + std::to_string(line_number) +
                                         ": duplicate public key or key ID");
        }
        if (file.bad() || !file.eof())
            throw std::runtime_error("Cannot read employee public key file: " + path);
        if (keys.empty())
            throw std::runtime_error("Employee public key file is empty: " + path);
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
    if (argc > 2)
    {
        std::cerr << "Usage: " << argv[0] << " [EMPLOYEE_PUBLIC_KEYS_FILE]\n"
                  << "Default: " << DEFAULT_KEYS_FILE << '\n'
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
        const auto keys = load_key_file(argc == 2 ? argv[1] : DEFAULT_KEYS_FILE);
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
