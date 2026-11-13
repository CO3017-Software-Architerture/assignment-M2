#ifndef MYLIB_H
#define MYLIB_H

#include "main.hpp"
#include "nonce.hpp"

namespace qrgen
{
    struct QRContent 
    {
        std::uint8_t version;
        std::uint32_t timestamp;
        nonce_t nonce;
        key_id_t key_ID;
        std::array<std::uint8_t,crypto_core_ed25519_HASHBYTES> signature;
    };
    std::string generateCode(/*args*/);
}

#endif