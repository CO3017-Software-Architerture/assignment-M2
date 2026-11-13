#include <iostream>
#include <cassert>

#include "..\header\main.hpp"
#include "..\header\qrgen.hpp"
#include "..\header\server.hpp"


void setupSodium()
{
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium!" << std::endl;
        std::exit(EXIT_FAILURE);
    }
}


int main()
{
    setupSodium();
    return 0;
}
