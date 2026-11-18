#include "qrgen.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace qrgen
{
    bool crypto_init()
    {
        return sodium_init() >= 0;
    }

    Signature sign(const SecretKey& secret_key, const std::vector<std::uint8_t>& message)
    {
        if (!crypto_init())
        {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        Signature signature{};
        if (crypto_sign_detached(
                signature.data(),
                nullptr,
                message.data(),
                message.size(),
                secret_key.data()) != 0)
        {
            throw std::runtime_error("Failed to sign QR payload");
        }
        return signature;
    }

    bool verify(const PublicKey& public_key, const Signature& signature, const std::vector<std::uint8_t>& message)
    {
        if (!crypto_init())
        {
            return false;
        }

        return crypto_sign_verify_detached(
                   signature.data(),
                   message.data(),
                   message.size(),
                   public_key.data()) == 0;
    }

    key_id_t derive_key_id(const PublicKey& public_key)
    {
        if (!crypto_init())
        {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        std::array<std::uint8_t, crypto_hash_sha256_BYTES> hash{};
        crypto_hash_sha256(hash.data(), public_key.data(), public_key.size());
        return read_be64(hash.data());
    }

    nonce_t random_nonce()
    {
        return generate_nonce();
    }

    void write_be64(std::uint8_t* dst, std::uint64_t value)
    {
        for (std::size_t i = 0; i < 8; ++i)
        {
            dst[i] = static_cast<std::uint8_t>((value >> ((7 - i) * 8)) & 0xFFu);
        }
    }

    void write_be32(std::uint8_t* dst, std::uint32_t value)
    {
        for (std::size_t i = 0; i < 4; ++i)
        {
            dst[i] = static_cast<std::uint8_t>((value >> ((3 - i) * 8)) & 0xFFu);
        }
    }

    std::uint64_t read_be64(const std::uint8_t* src)
    {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i)
        {
            value = (value << 8) | static_cast<std::uint64_t>(src[i]);
        }
        return value;
    }

    std::uint32_t read_be32(const std::uint8_t* src)
    {
        std::uint32_t value = 0;
        for (std::size_t i = 0; i < 4; ++i)
        {
            value = (value << 8) | static_cast<std::uint32_t>(src[i]);
        }
        return value;
    }

    Payload build_payload(key_id_t key_id, std::uint32_t timestamp, const nonce_t& nonce)
    {
        Payload payload{};
        payload[VERSION_OFFSET] = PROTOCOL_VERSION;
        write_be64(&payload[KEY_ID_OFFSET], key_id);
        write_be32(&payload[TIMESTAMP_OFFSET], timestamp);
        std::copy(nonce.begin(), nonce.end(), payload.begin() + NONCE_OFFSET);
        return payload;
    }

    std::vector<std::uint8_t> build_signed_message(const Payload& payload)
    {
        std::vector<std::uint8_t> message;
        message.reserve(DOMAIN_PREFIX.size() + payload.size());
        message.insert(message.end(), DOMAIN_PREFIX.begin(), DOMAIN_PREFIX.end());
        message.insert(message.end(), payload.begin(), payload.end());
        return message;
    }

    std::string encode_qr_text(const std::vector<std::uint8_t>& bytes)
    {
        if (!crypto_init())
        {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        const std::size_t encoded_len =
            sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        std::string encoded(encoded_len, '\0');

        sodium_bin2base64(
            encoded.data(),
            encoded.size(),
            bytes.data(),
            bytes.size(),
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);

        if (!encoded.empty() && encoded.back() == '\0')
        {
            encoded.pop_back();
        }
        return encoded;
    }

    namespace
    {
        bool is_strict_base64url_char(char c)
        {
            return (c >= 'A' && c <= 'Z') ||
                   (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') ||
                   c == '-' || c == '_';
        }
    } // namespace

    std::optional<std::vector<std::uint8_t>> decode_qr_text(std::string_view qr_text)
    {
        if (qr_text.empty() || !crypto_init())
        {
            return std::nullopt;
        }

        for (char c : qr_text)
        {
            if (!is_strict_base64url_char(c))
            {
                return std::nullopt;
            }
        }

        std::vector<std::uint8_t> decoded(qr_text.size());
        std::size_t bin_len = 0;
        const char* b64_end = nullptr;

        if (sodium_base642bin(
                decoded.data(),
                decoded.size(),
                qr_text.data(),
                qr_text.size(),
                nullptr,
                &bin_len,
                &b64_end,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            return std::nullopt;
        }

        if (b64_end != qr_text.data() + qr_text.size())
        {
            return std::nullopt;
        }

        decoded.resize(bin_len);
        return decoded;
    }

    std::optional<QRContent> parse_qr(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.size() != QR_RAW_SIZE)
        {
            return std::nullopt;
        }

        if (bytes[VERSION_OFFSET] != PROTOCOL_VERSION)
        {
            return std::nullopt;
        }

        QRContent content{};
        content.version = bytes[VERSION_OFFSET];
        content.key_id = read_be64(&bytes[KEY_ID_OFFSET]);
        content.timestamp = read_be32(&bytes[TIMESTAMP_OFFSET]);
        std::copy_n(&bytes[NONCE_OFFSET], NONCE_SIZE, content.nonce.begin());
        std::copy_n(bytes.data(), PAYLOAD_SIZE, content.raw_payload.begin());
        std::copy_n(bytes.data() + PAYLOAD_SIZE, SIGNATURE_SIZE, content.signature.begin());
        return content;
    }

    std::optional<QRContent> decode_and_parse_qr(std::string_view qr_text)
    {
        const auto decoded = decode_qr_text(qr_text);
        if (!decoded.has_value())
        {
            return std::nullopt;
        }
        return parse_qr(*decoded);
    }
} // namespace qrgen