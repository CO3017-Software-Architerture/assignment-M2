#include <iostream>

#include "main.hpp"

const uint8_t KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

int tc_01()
{
    std::cout<<"---TEST CASE 01----\n";
    Employee staf01(0,"mjnk","Admin",AccessLevel::Administrator);
    std::string cipher = qrgen::generateCode(staf01);
    std::cout<<qrgen::generateCode(staf01)<<'\n';



    std::cout<<"decrypt part"<<'\n';
    std::vector<uint8_t> decryptext(cipher.size());

    ChaCha20 encrypt;
    uint8_t nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
    encrypt.init(KEY, nonce, 1);
    encrypt.crypt(reinterpret_cast<const uint8_t*>(cipher.data()),decryptext.data(),cipher.size());
    std::cout<<std::string(decryptext.begin(),decryptext.end())<<'\n';
    std::cout<<"\n--------------------\n";
    //exit(EXIT_SUCCESS);
    return 0;
}


int main()
{
    return tc_01();
}