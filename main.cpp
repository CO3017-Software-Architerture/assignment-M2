#include <iostream>

#include "main.h"
#include "mylib.h"

int run()
{
    std::cout << mylib::message() << '\n';
    return 0;
}

int main()
{
    return run();
}