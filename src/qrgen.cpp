#include "..\header\qrgen.hpp"


const uint8_t KEY[32] = {
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
        res += std::to_string(employee.getID());
        res += employee.getName();
        res += employee.getRole();
        res += std::to_string(int(employee.getAccesslevel()));
        res += std::to_string(std::time(nullptr));

        size_t  length = res.size();
        std::vector<uint8_t> ciphertext(length);
        ChaCha20 encrypt;
        uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        };
        encrypt.init(KEY, nonce, 1);
        encrypt.crypt(reinterpret_cast<const uint8_t*>(res.data()), ciphertext.data(),length);
        return std::string(ciphertext.begin(), ciphertext.end());
    }
}