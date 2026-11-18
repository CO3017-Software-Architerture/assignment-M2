#include "server.hpp"
#include "qrgen.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace server
{
    namespace
    {
        std::optional<qrgen::PublicKey> decode_public_key_token(std::string_view token)
        {
            if (token.empty() || !qrgen::crypto_init())
            {
                return std::nullopt;
            }

            qrgen::PublicKey pk{};
            std::size_t bin_len = 0;

            if (token.size() == crypto_sign_PUBLICKEYBYTES * 2 &&
                sodium_hex2bin(
                    pk.data(),
                    pk.size(),
                    token.data(),
                    token.size(),
                    nullptr,
                    &bin_len,
                    nullptr) == 0 &&
                bin_len == pk.size())
            {
                return pk;
            }

            for (int variant : {
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING,
                     sodium_base64_VARIANT_URLSAFE,
                     sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
                     sodium_base64_VARIANT_ORIGINAL})
            {
                if (sodium_base642bin(
                        pk.data(),
                        pk.size(),
                        token.data(),
                        token.size(),
                        nullptr,
                        &bin_len,
                        nullptr,
                        variant) == 0 &&
                    bin_len == pk.size())
                {
                    return pk;
                }
            }

            return std::nullopt;
        }
    } // namespace

    Verifier::KeyCache load_key_file(const std::string& path)
    {
        if (!qrgen::crypto_init())
        {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        std::ifstream file(path);
        if (!file)
        {
            throw std::runtime_error("Unable to open key file: " + path);
        }

        Verifier::KeyCache keys;
        std::string line;
        while (std::getline(file, line))
        {
            const auto comment_pos = line.find('#');
            if (comment_pos != std::string::npos)
            {
                line.erase(comment_pos);
            }

            std::istringstream iss(line);
            std::vector<std::string> tokens;
            std::string tok;
            while (iss >> tok)
            {
                tokens.push_back(tok);
            }
            if (tokens.empty())
            {
                continue;
            }

            for (const auto& candidate : tokens)
            {
                const auto pk = decode_public_key_token(candidate);
                if (pk.has_value())
                {
                    keys[qrgen::derive_key_id(*pk)] = *pk;
                    break;
                }
            }
        }
        return keys;
    }

    std::optional<Direction> parse_direction(std::string_view token)
    {
        if (token == "IN" || token == "ENTRY")
        {
            return Direction::IN;
        }
        if (token == "OUT" || token == "EXIT")
        {
            return Direction::OUT;
        }
        return std::nullopt;
    }

    std::optional<ScanRequest> parse_scan_line(std::string_view line)
    {
        std::string text(line);
        std::istringstream iss(text);
        std::string first;
        std::string second;
        std::string extra;

        if (!(iss >> first))
        {
            return std::nullopt;
        }

        if (!(iss >> second))
        {
            return ScanRequest{Direction::IN, first};
        }

        if (iss >> extra)
        {
            return std::nullopt;
        }

        const auto direction = parse_direction(first);
        if (!direction.has_value())
        {
            return std::nullopt;
        }
        return ScanRequest{*direction, second};
    }
} // namespace server

namespace Server
{
    int main(int argc, char const* argv[])
    {
        if (!qrgen::crypto_init())
        {
            std::cerr << "Error: Failed to initialize libsodium\n";
            return 1;
        }

        NonceCache nonceCache;
        PassbackCache passbackCache;
        Barrier barrier;
        Verifier::KeyCache keys;

        if (argc > 1)
        {
            try
            {
                keys = server::load_key_file(argv[1]);
            }
            catch (const std::exception& ex)
            {
                std::cerr << "Error: " << ex.what() << '\n';
                return 1;
            }
        }

        Verifier verifier(nonceCache, passbackCache, barrier, keys);

        std::string line;
        while (std::getline(std::cin, line))
        {
            if (line.empty())
            {
                continue;
            }

            const auto req = server::parse_scan_line(line);
            const auto now = Verifier::Clock::now();
            if (!req.has_value())
            {
                const Decision decision = verifier.handle_scan("", Direction::IN, now);
                std::cout << decision_name(decision) << '\n';
                continue;
            }

            const Decision decision = verifier.handle_scan(req->qr_text, req->direction, now);
            std::cout << decision_name(decision) << '\n';
        }
        return 0;
    }
} // namespace Server

namespace server
{
    int main(int argc, char const* argv[])
    {
        return Server::main(argc, argv);
    }
}
