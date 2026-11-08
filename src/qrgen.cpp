#include "..\header\qrgen.hpp"
#include "..\header\nonce.hpp"


const crypto::Key KEY = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

namespace qrgen
{
    std::string generateCode(Employee employee)
    {
        std::string res;
        res += std::to_string(employee.getID()) + '/';
        res += employee.getName() + '/';
        res += employee.getRole() + '/';
        res += std::to_string(int(employee.getAccesslevel())) + '/';
        res += std::to_string(std::time(nullptr)) + '/';

        const crypto::Nonce nonce = crypto::generateNonce();
        const std::string ciphertext =
            crypto::ChaCha20Cipher::encrypt(res, KEY, nonce);
        return std::string(
            reinterpret_cast<const char*>(nonce.data()), nonce.size()) + '|' + ciphertext;
    }
}