#include "employees.hpp"

Employee::Employee(int id, std::string name, std::string role, AccessLevel accessLevel)
{
    this->id = id;
    this->name = name;
    this->role = role;
    this->accessLevel = accessLevel;
}

Employee::~Employee()
{
    // delete?
}

std::string Employee::getName()
{
    return this->name;
}

int Employee::getID()
{
    return this->id;
}

std::string Employee::getRole()
{
    return this->role;
}

AccessLevel Employee::getAccesslevel()
{
    return this->accessLevel;
}
