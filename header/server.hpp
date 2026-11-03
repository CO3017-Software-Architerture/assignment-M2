#ifndef SERVER_HPP
#define SERVER_HPP

#include <cstdint>

#include "barrier.hpp"
#include "employees.hpp"

namespace server
{
    #pragma region INTERFACES 
    Barrier barrier;
    #pragma endregion
    // Read a file within directory. Reject absolute filenames and path traversal.
    // Throw std::runtime_error if the file cannot be accessed or read.
    std::vector<std::uint8_t> loadImage(
        const std::string& directory,
        const std::string& filename);

    // Decode one QR code from encoded image bytes (not raw pixels).
    // Throw std::runtime_error for unsupported images or unsuccessful decoding.
    std::string scanImage(const std::vector<std::uint8_t>& imageData);

    // Parse a decrypted, structured employee payload; throw std::invalid_argument
    // for malformed fields. The wire format must be agreed with the QR generator:
    // its current delimiter-free encrypted payload cannot be parsed unambiguously.
    Employee parseEmployee(const std::string& payload);

    // Return false for missing or mismatched records; propagate database errors.
    bool verifyEmployeeWithDatabase(
        const Employee& employee,
        const IEmployeeDatabase& database);

    // Check the exact payload bytes, excluding the checksum field. The algorithm
    // and checksum encoding must be agreed with the producer before implementation.
    // A checksum detects corruption; it does not authenticate an employee.
    bool verifyChecksum(
        const std::string& payload,
        const std::string& expectedChecksum);
}

#endif
