#include "../header/nonce.hpp"
#include "../header/crypto.hpp"


crypto::Nonce crypto::generateNonce()
{
    return Nonce{0x00,0x01,0x02};
}