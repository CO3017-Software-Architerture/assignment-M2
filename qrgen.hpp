#ifndef MYLIB_H
#define MYLIB_H

#include <string>
#include "employees.hpp"
#include <chrono>
#include "chacha20.hpp"

namespace qrgen
{
    std::string generateCode(Employee);
}

#endif