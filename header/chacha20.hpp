#ifndef CHACHA20_HPP
#define CHACHA20_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <algorithm>

/**
 * Low-level ChaCha20 stream cipher engine.
 * Operates directly on standard fixed-width types (std::uint32_t, std::uint8_t, std::size_t).
 * Designed for maximum performance and barebone / embedded hardware compatibility.
 */
class ChaCha20Engine {
private:
    std::array<std::uint32_t, 16> state{};

    static inline std::uint32_t rotl32(std::uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline void quarterRound(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    void chachaBlock(std::array<std::uint32_t, 16>& output, const std::array<std::uint32_t, 16>& input_state) {
        output = input_state;
        for (int i = 0; i < 10; ++i) { // 20 rounds (10 iterations of 2 rounds each)
            // (Column Rounds)
            quarterRound(output[0], output[4], output[8],  output[12]);
            quarterRound(output[1], output[5], output[9],  output[13]);
            quarterRound(output[2], output[6], output[10], output[14]);
            quarterRound(output[3], output[7], output[11], output[15]);
            // (Diagonal Rounds)
            quarterRound(output[0], output[5], output[10], output[15]);
            quarterRound(output[1], output[6], output[11], output[12]);
            quarterRound(output[2], output[7], output[8],  output[13]);
            quarterRound(output[3], output[4], output[9],  output[14]);
        }
        for (std::size_t i = 0; i < 16; ++i) {
            output[i] += input_state[i];
        }
    }

public:
    // Key: 32 bytes (256-bit), Nonce: 12 bytes (96-bit), Counter: số khởi đầu (thường là 0 hoặc 1)
    void init(const std::uint8_t key[32], const std::uint8_t nonce[12], std::uint32_t counter = 1) {
        // constant ("expand 32-byte k")
        state[0] = 0x61787065;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Điền Key (8 từ)
        for (std::size_t i = 0; i < 8; ++i) {
            state[4 + i] = static_cast<std::uint32_t>(key[i * 4]) |
                          (static_cast<std::uint32_t>(key[i * 4 + 1]) << 8) |
                          (static_cast<std::uint32_t>(key[i * 4 + 2]) << 16) |
                          (static_cast<std::uint32_t>(key[i * 4 + 3]) << 24);
        }

        // Điền Block Counter (1 từ)
        state[12] = counter;

        // Điền Nonce (3 từ)
        for (std::size_t i = 0; i < 3; ++i) {
            state[13 + i] = static_cast<std::uint32_t>(nonce[i * 4]) |
                           (static_cast<std::uint32_t>(nonce[i * 4 + 1]) << 8) |
                           (static_cast<std::uint32_t>(nonce[i * 4 + 2]) << 16) |
                           (static_cast<std::uint32_t>(nonce[i * 4 + 3]) << 24);
        }
    }

    // Modern std::array overload
    void init(const std::array<std::uint8_t, 32>& key, const std::array<std::uint8_t, 12>& nonce, std::uint32_t counter = 1) {
        init(key.data(), nonce.data(), counter);
    }

    // Hàm mã hóa/giải mã (vì đối xứng XOR nên dùng chung một hàm)
    /*  input là pointer trỏ tới vùng data
        output là pointer trỏ tới vùng đã allocate rỗng
        length là độ dài của input        
    */
    void crypt(const std::uint8_t* input, std::uint8_t* output, std::size_t length) {
        std::array<std::uint32_t, 16> block_output;
        std::array<std::uint8_t, 64> keystream;
        std::size_t i = 0;

        while (length > 0) {
            // tạo ma trận key stream
            chachaBlock(block_output, state);
            
            // Chuyển ma trận 16 từ 32-bit thành mảng 64 byte keystream (Little-endian)
            for (std::size_t j = 0; j < 16; ++j) {
                keystream[j * 4]     = static_cast<std::uint8_t>((block_output[j] >> 0)  & 0xFF);
                keystream[j * 4 + 1] = static_cast<std::uint8_t>((block_output[j] >> 8)  & 0xFF);
                keystream[j * 4 + 2] = static_cast<std::uint8_t>((block_output[j] >> 16) & 0xFF);
                keystream[j * 4 + 3] = static_cast<std::uint8_t>((block_output[j] >> 24) & 0xFF);
            }
            // đã flat xong key stream
            std::size_t take = std::min(length, static_cast<std::size_t>(64));
            for (std::size_t j = 0; j < take; ++j) {
                output[i] = input[i] ^ keystream[j];
                i++;
            }

            length -= take;
            state[12]++; // Tăng bộ đếm khối lên 1 cho khối tiếp theo
        }
    }
};

// Backward compatibility alias
#endif // CHACHA20_HPP
