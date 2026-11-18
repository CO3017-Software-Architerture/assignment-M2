#include "../header/nonce.hpp"
#include <sodium.h>
#include <stdexcept>

nonce_t generate_nonce()
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    nonce_t nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}
