#include <iostream>

#include "main.hpp"

int tc_01()
{
    std::cout<<"---TEST CASE 01----\n";
    Employee staf01(0,"mjnk","Admin",AccessLevel::Administrator);
    std::cout<<qrgen::generateCode(staf01)<<'\n';
    std::cout<<"\n--------------------\n";
    //exit(EXIT_SUCCESS);
    return 0;
}


int main()
{
    return tc_01();
}