#include "Verifier.hpp"
#include "server.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>

namespace
{
    using Bytes = std::array<std::uint8_t, 85>;
    using SecretKey = std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES>;

    Bytes make_token(const qrgen::PublicKey& public_key, const SecretKey& secret_key,
                     std::uint32_t timestamp, std::uint8_t nonce,
                     std::uint8_t version = 1)
    {
        Bytes token{};
        std::array<std::uint8_t, crypto_hash_sha256_BYTES> digest{};
        assert(crypto_hash_sha256(digest.data(), public_key.data(), public_key.size()) == 0);
        token[0] = version;
        std::copy_n(digest.begin(), 8, token.begin() + 1);
        for (std::size_t i = 0; i < 4; ++i)
            token[9 + i] = static_cast<std::uint8_t>(timestamp >> (8 * (3 - i)));
        token[13] = nonce;

        const std::string prefix = "corp-qr-access-v1";
        std::vector<std::uint8_t> message(prefix.begin(), prefix.end());
        message.insert(message.end(), token.begin(), token.begin() + 21);
        assert(crypto_sign_detached(token.data() + 21, nullptr, message.data(),
                                    message.size(), secret_key.data()) == 0);
        return token;
    }

    std::string encode(const Bytes& token)
    {
        std::array<char, 115> text{};
        sodium_bin2base64(text.data(), text.size(), token.data(), token.size(),
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        return text.data();
    }

    std::string public_key_hex(const qrgen::PublicKey& key)
    {
        std::array<char, crypto_sign_PUBLICKEYBYTES * 2 + 1> hex{};
        return sodium_bin2hex(hex.data(), hex.size(), key.data(), key.size());
    }

    // Restore the console after exercising the same entry point as the executable.
    std::pair<int, std::string> run_server(const std::filesystem::path& keys, const std::string& scans)
    {
        const auto path = keys.string();
        const char* args[] = {"server", path.c_str()};
        std::istringstream input(scans);
        std::ostringstream output;
        auto* stdin_buffer = std::cin.rdbuf(input.rdbuf());
        auto* stdout_buffer = std::cout.rdbuf(output.rdbuf());
        const auto exit_code = server::main(2, args);
        std::cin.rdbuf(stdin_buffer);
        std::cout.rdbuf(stdout_buffer);
        return {exit_code, output.str()};
    }

    void write_key_file(const std::filesystem::path& path, const std::string& content)
    {
        std::ofstream file(path, std::ios::binary);
        file << content;
        file.close();
        assert(file);
    }
}

int main()
{
    if (sodium_init() < 0)
        return 1;

    qrgen::PublicKey public_key{}, other_key{};
    SecretKey secret_key{}, other_secret{};
    assert(crypto_sign_keypair(public_key.data(), secret_key.data()) == 0);
    assert(crypto_sign_keypair(other_key.data(), other_secret.data()) == 0);

    const auto key_id = qrgen::derive_key_id(public_key);
    const Verifier::KeyCache keys{{key_id, public_key}};
    constexpr std::uint32_t now_seconds = 1700000000;
    const Verifier::Clock::time_point now{std::chrono::seconds{now_seconds}};
    const NonceCache::Clock::time_point monotonic_now{};
    NonceCache nonces;
    PassbackCache passback;
    Barrier barrier;
    Verifier verifier(nonces, passback, barrier, keys);

    const auto scan = [&](std::string_view text, Direction direction, Decision expected)
    {
        const auto actual = verifier.handle_scan(text, direction, now, monotonic_now);
        assert(actual == expected);
        assert(barrier.isOpen() == (expected == Decision::ALLOW));
    };
    const auto token = [&](std::uint32_t timestamp, std::uint8_t nonce)
    {
        return encode(make_token(public_key, secret_key, timestamp, nonce));
    };

    const auto first = token(now_seconds, 1);
    auto bad_signature = make_token(public_key, secret_key, now_seconds, 1);
    bad_signature.back() ^= 1;
    scan(encode(bad_signature), Direction::IN, Decision::BAD_SIGNATURE);
    scan(first, Direction::IN, Decision::ALLOW);
    scan(first, Direction::OUT, Decision::REPLAY);
    const auto second_entry = token(now_seconds, 2);
    scan(second_entry, Direction::IN, Decision::PASSBACK);
    scan(second_entry, Direction::OUT, Decision::REPLAY);
    scan(token(now_seconds - 30, 3), Direction::OUT, Decision::ALLOW);
    scan(token(now_seconds, 4), Direction::OUT, Decision::PASSBACK);
    scan(token(now_seconds + 5, 5), Direction::IN, Decision::ALLOW);
    scan(token(now_seconds - 31, 6), Direction::OUT, Decision::EXPIRED);
    scan(token(now_seconds + 6, 6), Direction::OUT, Decision::FUTURE);
    scan(token(now_seconds, 6), Direction::OUT, Decision::ALLOW);
    scan(encode(make_token(other_key, other_secret, now_seconds, 7)),
         Direction::IN, Decision::UNKNOWN_KEY);
    scan(encode(make_token(public_key, secret_key, now_seconds, 7, 2)),
         Direction::IN, Decision::MALFORMED);
    scan(first.substr(1), Direction::IN, Decision::MALFORMED);
    auto bad_alphabet = first;
    bad_alphabet[1] = '+';
    scan(bad_alphabet, Direction::IN, Decision::MALFORMED);

    const Verifier::Clock::time_point rollover{std::chrono::seconds{std::int64_t{1} << 32}};
    const auto before_rollover = token(std::numeric_limits<std::uint32_t>::max(), 8);
    assert(verifier.handle_scan(before_rollover, Direction::IN, rollover, monotonic_now) ==
           Decision::ALLOW);

    const NonceCache::nonce_key_pair cache_entry{key_id, nonce_t{1}};
    nonces.purge_expired(monotonic_now + std::chrono::seconds{59});
    assert(nonces.contains(cache_entry));
    nonces.purge_expired(monotonic_now + std::chrono::seconds{60});
    assert(!nonces.contains(cache_entry));
    assert(passback.reset_passback(key_id));
    assert(passback.check_anti_passback(key_id, Direction::IN));

    // Verify both employees from one key file and reject a third, unlisted key.
    const auto current_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        Verifier::Clock::now().time_since_epoch()).count();
    const auto current_timestamp = static_cast<std::uint32_t>(current_seconds);
    const auto cli_token = token(current_timestamp, 9);
    const auto other_token = encode(make_token(other_key, other_secret, current_timestamp, 9));
    qrgen::PublicKey unknown_key{};
    SecretKey unknown_secret{};
    assert(crypto_sign_keypair(unknown_key.data(), unknown_secret.data()) == 0);
    const auto unknown_token = encode(make_token(unknown_key, unknown_secret, current_timestamp, 9));
    sodium_memzero(unknown_secret.data(), unknown_secret.size());

    const auto temp_dir = std::filesystem::temp_directory_path() /
                          ("m2-verifier-" + std::to_string(randombytes_random()));
    const auto created = std::filesystem::create_directory(temp_dir);
    assert(created);
    const auto key_file = temp_dir / "employee_public_keys.txt";
    const auto key_hex = public_key_hex(public_key);
    assert(run_server(key_file, "").first == EXIT_FAILURE);

    write_key_file(key_file, key_hex + "\r\n\r\n" + public_key_hex(other_key));
    const auto result = run_server(key_file, "IN " + cli_token + std::string(200, 'A') +
                                            "\nIN " + cli_token + "\r\nIN " + other_token +
                                            "\nOUT " + cli_token + "\nIN " + unknown_token);
    assert(result.first == EXIT_SUCCESS);
    assert(result.second == "MALFORMED\nALLOW\nALLOW\nREPLAY\nUNKNOWN_KEY\n");

    for (const auto& invalid : {std::string{" \r\n\t\n"}, key_hex + "\nbad\n",
                                key_hex + '\n' + std::string(64, 'z') + '\n',
                                key_hex + '\n' + key_hex + '\n'})
    {
        write_key_file(key_file, invalid);
        const auto invalid_result = run_server(key_file, "IN " + cli_token);
        assert(invalid_result.first == EXIT_FAILURE && invalid_result.second.empty());
    }
    std::filesystem::remove(key_file);
    std::filesystem::remove(temp_dir);

    sodium_memzero(secret_key.data(), secret_key.size());
    sodium_memzero(other_secret.data(), other_secret.size());
    std::cout << "Verifier tests passed\n";
}
