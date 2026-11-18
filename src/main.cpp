#include "server.hpp"
#include "client.hpp"

#include <iostream>
#include <string>

int main(int argc, char const* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " client|server [arguments...]\n";
        return 1;
    }

    if (std::string{argv[1]} == "server")
        return server::main(argc - 1, argv + 1);
    if (std::string{argv[1]} == "client")
        return Client::main(argc - 1, argv + 1);

    std::cerr << "Unknown command. Use client or server.\n";
    return 1;
}
