#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

#include "chacha20.hpp"

namespace crypto {

/// Fixed-size cryptographic containers
using Key        = std::array<std::uint8_t, 32>;
using Nonce      = std::array<std::uint8_t, 12>;
using ByteVector = std::vector<std::uint8_t>;

/**
 * High-level cryptographic cipher service wrapping ChaCha20Engine.
 * Provides clean interfaces for standard containers (std::string, std::vector, std::array)
 * without requiring low-level pointer arithmetic or manual buffer management.
 */
class ChaCha20Cipher {
public:
    // ========================================================================
    // String Interface (Ideal for text payloads, QR data, tokens)
    // ========================================================================

    /// Encrypt plaintext string into ciphertext string
    static std::string encrypt(
        const std::string& plaintext,
        const Key& key,
        const Nonce& nonce,
        std::uint32_t counter = 1)
    {
        if (plaintext.empty()) {
            return "";
        }
        std::string ciphertext(plaintext.size(), '\0');
        ChaCha20Engine engine;
        engine.init(key, nonce, counter);
        engine.crypt(
            reinterpret_cast<const std::uint8_t*>(plaintext.data()),
            reinterpret_cast<std::uint8_t*>(&ciphertext[0]),
            plaintext.size()
        );
        return ciphertext;
    }

    /// Decrypt ciphertext string into plaintext string (symmetric cipher)
    static std::string decrypt(
        const std::string& ciphertext,
        const Key& key,
        const Nonce& nonce,
        std::uint32_t counter = 1)
    {
        return encrypt(ciphertext, key, nonce, counter);
    }

    /// String encryption helper with raw C-array / pointer keys
    static std::string encrypt(
        const std::string& plaintext,
        const std::uint8_t key[32],
        const std::uint8_t nonce[12],
        std::uint32_t counter = 1)
    {
        Key k{};
        Nonce n{};
        std::copy(key, key + 32, k.begin());
        std::copy(nonce, nonce + 12, n.begin());
        return encrypt(plaintext, k, n, counter);
    }

    /// String decryption helper with raw C-array / pointer keys
    static std::string decrypt(
        const std::string& ciphertext,
        const std::uint8_t key[32],
        const std::uint8_t nonce[12],
        std::uint32_t counter = 1)
    {
        return encrypt(ciphertext, key, nonce, counter);
    }

    // ========================================================================
    // Byte Vector Interface (Ideal for binary blobs, images, packets)
    // ========================================================================

    /// Encrypt binary byte vector into ciphertext byte vector
    static ByteVector encrypt(
        const ByteVector& plaintext,
        const Key& key,
        const Nonce& nonce,
        std::uint32_t counter = 1)
    {
        if (plaintext.empty()) {
            return {};
        }
        ByteVector ciphertext(plaintext.size());
        ChaCha20Engine engine;
        engine.init(key, nonce, counter);
        engine.crypt(plaintext.data(), ciphertext.data(), plaintext.size());
        return ciphertext;
    }

    /// Decrypt binary byte vector into plaintext byte vector (symmetric cipher)
    static ByteVector decrypt(
        const ByteVector& ciphertext,
        const Key& key,
        const Nonce& nonce,
        std::uint32_t counter = 1)
    {
        return encrypt(ciphertext, key, nonce, counter);
    }

    /// ByteVector encryption helper with raw C-array / pointer keys
    static ByteVector encrypt(
        const ByteVector& plaintext,
        const std::uint8_t key[32],
        const std::uint8_t nonce[12],
        std::uint32_t counter = 1)
    {
        Key k{};
        Nonce n{};
        std::copy(key, key + 32, k.begin());
        std::copy(nonce, nonce + 12, n.begin());
        return encrypt(plaintext, k, n, counter);
    }

    /// ByteVector decryption helper with raw C-array / pointer keys
    static ByteVector decrypt(
        const ByteVector& ciphertext,
        const std::uint8_t key[32],
        const std::uint8_t nonce[12],
        std::uint32_t counter = 1)
    {
        return encrypt(ciphertext, key, nonce, counter);
    }
};

} // namespace crypto

#endif // CRYPTO_HPP
