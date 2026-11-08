#ifndef EMPLOYEES_H
#define EMPLOYEES_H

#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

enum class AccessLevel
{
    Guest = 0,
    Employee = 1,
    Manager = 2,
    Administrator = 3
};

class Employee
{
private:
    int id{0};
    std::string name;
    std::string role;
    AccessLevel accessLevel{AccessLevel::Employee};
    char branch{'B'};

public:
    Employee(int id = 0, std::string name = "", std::string role = "", AccessLevel accessLevel = AccessLevel::Employee, char branch = 'B');
    ~Employee();

    std::string getName() const;
    int getID() const;
    std::string getRole() const;
    AccessLevel getAccesslevel() const;
    char getBranch() const;

    void setID(int newId);
    void setName(const std::string& newName);
    void setRole(const std::string& newRole);
    void setAccessLevel(AccessLevel newLevel);
    void setBranch(char newBranch);

    bool operator==(const Employee& other) const;
    bool operator!=(const Employee& other) const;

    // Serialize employee to delimited payload: "id|name|role|accessLevel|branch"
    std::string toPayloadString() const;

    // Parse employee from delimited payload
    static Employee fromPayloadString(const std::string& payload);

    // Helpers for AccessLevel string conversion
    static std::string accessLevelToString(AccessLevel level);
    static AccessLevel accessLevelFromString(const std::string& str);
};

// Interface for employee database verification
class IEmployeeDatabase
{
public:
    virtual ~IEmployeeDatabase() = default;

    // Match all employee fields, not just the employee ID.
    // Database failures must throw rather than report a mismatch.
    virtual bool matches(const Employee& employee) const = 0;
};

// In-memory implementation of IEmployeeDatabase for testing and operation
class InMemoryEmployeeDatabase : public IEmployeeDatabase
{
private:
    std::vector<Employee> m_records;

public:
    InMemoryEmployeeDatabase() = default;

    void addEmployee(const Employee& employee)
    {
        m_records.push_back(employee);
    }

    void clear()
    {
        m_records.clear();
    }

    const std::vector<Employee>& getRecords() const
    {
        return m_records;
    }

    bool matches(const Employee& employee) const override
    {
        for (const auto& emp : m_records)
        {
            if (emp.getID() == employee.getID() &&
                emp.getName() == employee.getName() &&
                emp.getRole() == employee.getRole() &&
                emp.getAccesslevel() == employee.getAccesslevel() &&
                emp.getBranch() == employee.getBranch())
            {
                return true;
            }
        }
        return false;
    }
};

#endif
