#ifndef EMPLOYEES_H
#define EMPLOYEES_H

#include <string>
#include <vector>

enum class AccessLevel
{
    Guest,
    Employee,
    Manager,
    Administrator
};

class Employee
{
    private:
        int id{};
        std::string name;
        std::string role;
        AccessLevel accessLevel{AccessLevel::Employee};
        char branch{};
    public:
        Employee(int id, std::string name, std::string role, AccessLevel accessLevel);
        ~Employee();
        std::string getName();
        int getID();
        std::string getRole();
        AccessLevel getAccesslevel();

};

// class IEmployeeRepository
// {
// public:
//     virtual ~IEmployeeRepository() = default;

//     virtual bool insert(const Employee& employee) = 0;
//     virtual bool update(const Employee& employee) = 0;
//     virtual bool removeById(std::int32_t id) = 0;
// };

#endif