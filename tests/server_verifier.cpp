#include "Verifier.hpp"
#include "server.hpp"

#include <algorithm>
#include <cassert>
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

    // Exercise the CLI with its actual public-key argument and scanner input.
    const auto current_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        Verifier::Clock::now().time_since_epoch()).count();
    const auto cli_token = token(static_cast<std::uint32_t>(current_seconds), 9);
    std::array<char, 65> key_hex{};
    sodium_bin2hex(key_hex.data(), key_hex.size(), public_key.data(), public_key.size());
    const char* args[] = {"server", key_hex.data()};
    std::istringstream input("IN " + cli_token + std::string(200, 'A') +
                             "\nIN " + cli_token + "\r\nOUT " + cli_token);
    std::ostringstream output;
    auto* stdin_buffer = std::cin.rdbuf(input.rdbuf());
    auto* stdout_buffer = std::cout.rdbuf(output.rdbuf());
    const auto exit_code = server::main(2, args);
    std::cin.rdbuf(stdin_buffer);
    std::cout.rdbuf(stdout_buffer);
    assert(exit_code == 0);
    assert(output.str() == "MALFORMED\nALLOW\nREPLAY\n");

    sodium_memzero(secret_key.data(), secret_key.size());
    sodium_memzero(other_secret.data(), other_secret.size());
    std::cout << "Verifier tests passed\n";
}
