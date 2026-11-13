#include <array>
#include <cstdint>
//#include <openssl/rand.h> 

// Editors' note: no class required

inline constexpr std::size_t NONCE_SIZE = 8;

using nonce_t = std::array<std::uint8_t, NONCE_SIZE>;

nonce_t generate_nonce();