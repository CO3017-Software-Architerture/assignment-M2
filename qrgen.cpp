#include "qrgen.hpp"


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
        return res;
    }
}