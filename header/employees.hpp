#ifndef EMPLOYEES_H
#define EMPLOYEES_H

#include <string>
#include <vector>
// FINAL?
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

// Implement this interface using the chosen database backend.
class IEmployeeDatabase
{
public:
    virtual ~IEmployeeDatabase() = default;

    // Match all employee fields, not just the employee ID.
    // Database failures must throw rather than report a mismatch.
    virtual bool matches(const Employee& employee) const = 0;
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