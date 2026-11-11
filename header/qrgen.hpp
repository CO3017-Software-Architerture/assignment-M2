#ifndef MYLIB_H
#define MYLIB_H

#include "main.hpp"

namespace qrgen
{
    struct QRContent 
    {
        std::uint8_t version;
        key_id_t key_ID;
        std::uint32_t timestamp;
        nonce_t nonce;
        
    };
    std::string generateCode(/*args*/);
}

#endif