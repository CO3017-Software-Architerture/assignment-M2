#include <sstream>
#include <stdexcept>
#include "..\header\employees.hpp"

Employee::Employee(int id, std::string name, std::string role, AccessLevel accessLevel, char branch)
    : id(id), name(std::move(name)), role(std::move(role)), accessLevel(accessLevel), branch(branch)
{
}

Employee::~Employee()
{
}

std::string Employee::getName() const
{
    return this->name;
}

int Employee::getID() const
{
    return this->id;
}

std::string Employee::getRole() const
{
    return this->role;
}

AccessLevel Employee::getAccesslevel() const
{
    return this->accessLevel;
}

char Employee::getBranch() const
{
    return this->branch;
}

void Employee::setID(int newId)
{
    this->id = newId;
}

void Employee::setName(const std::string& newName)
{
    this->name = newName;
}

void Employee::setRole(const std::string& newRole)
{
    this->role = newRole;
}

void Employee::setAccessLevel(AccessLevel newLevel)
{
    this->accessLevel = newLevel;
}

void Employee::setBranch(char newBranch)
{
    this->branch = newBranch;
}

bool Employee::operator==(const Employee& other) const
{
    return this->id == other.id &&
           this->name == other.name &&
           this->role == other.role &&
           this->accessLevel == other.accessLevel &&
           this->branch == other.branch;
}

bool Employee::operator!=(const Employee& other) const
{
    return !(*this == other);
}

std::string Employee::toPayloadString() const
{
    std::string s;
    s += std::to_string(this->id);
    s += "|";
    s += this->name;
    s += "|";
    s += this->role;
    s += "|";
    s += std::to_string(static_cast<int>(this->accessLevel));
    s += "|";
    s += this->branch;
    return s;
}

Employee Employee::fromPayloadString(const std::string& payload)
{
    if (payload.empty())
    {
        throw std::invalid_argument("Cannot parse empty payload");
    }

    std::vector<std::string> tokens;
    std::stringstream ss(payload);
    std::string item;
    while (std::getline(ss, item, '|'))
    {
        tokens.push_back(item);
    }

    if (tokens.size() < 4)
    {
        throw std::invalid_argument("Malformed employee payload: expected at least 4 fields, got " + std::to_string(tokens.size()));
    }

    int parsedId = 0;
    try
    {
        parsedId = std::stoi(tokens[0]);
    }
    catch (const std::exception&)
    {
        throw std::invalid_argument("Invalid employee ID: " + tokens[0]);
    }

    std::string parsedName = tokens[1];
    std::string parsedRole = tokens[2];
    AccessLevel parsedLevel = accessLevelFromString(tokens[3]);
    char parsedBranch = 'B';
    if (tokens.size() >= 5 && !tokens[4].empty())
    {
        parsedBranch = tokens[4][0];
    }

    return Employee(parsedId, parsedName, parsedRole, parsedLevel, parsedBranch);
}

std::string Employee::accessLevelToString(AccessLevel level)
{
    switch (level)
    {
        case AccessLevel::Guest: return "Guest";
        case AccessLevel::Employee: return "Employee";
        case AccessLevel::Manager: return "Manager";
        case AccessLevel::Administrator: return "Administrator";
        default: return "Employee";
    }
}

AccessLevel Employee::accessLevelFromString(const std::string& str)
{
    if (str == "0" || str == "Guest") return AccessLevel::Guest;
    if (str == "1" || str == "Employee") return AccessLevel::Employee;
    if (str == "2" || str == "Manager") return AccessLevel::Manager;
    if (str == "3" || str == "Administrator" || str == "Admin") return AccessLevel::Administrator;

    try
    {
        int val = std::stoi(str);
        if (val >= 0 && val <= 3)
        {
            return static_cast<AccessLevel>(val);
        }
    }
    catch (...)
    {
    }

    throw std::invalid_argument("Unknown AccessLevel value: " + str);
}
