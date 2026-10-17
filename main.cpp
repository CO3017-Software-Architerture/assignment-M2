#include <iostream>

#include "main.h"


int run()
{
    std::cout << qrgen::generateCode() << '\n';
    return 0;
}

int main()
{
    return run();
}