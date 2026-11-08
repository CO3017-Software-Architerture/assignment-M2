#ifndef SERVER_HPP
#define SERVER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>
#include <memory>

#include "employees.hpp"
#include "barrier.hpp"
#include "crypto.hpp"

/**
 * ============================================================================
 * TMC KIOSK-SERVER ACCESS CONTROLLER
 * Merged Kiosk & Server Architecture for Access Control & Turnstile Decision
 * ============================================================================
 * Pipeline:
 *   1. Read QR (via image file / decoded image bytes / raw scanner payload)
 *   2. Optional Decryption (ChaCha20 symmetric stream cipher)
 *   3. Checksum verification (CRITICAL: validates integrity BEFORE touching database)
 *   4. Extract & parse employee data
 *   5. Query employee database
 *   6. Turnstile gate opening decision (triggers physical barrier)
 * ============================================================================
 */

namespace server
{
    /// Access control evaluation result
    struct AccessDecision
    {
        bool granted{false};
        std::string message;
        std::optional<Employee> employee;
        bool checksumVerified{false};
        bool databaseVerified{false};
        bool gateOpened{false};
    };

    // ------------------------------------------------------------------------
    // 1. File & Image I/O
    // ------------------------------------------------------------------------

    /// Read raw file bytes within directory. Rejects absolute paths and path traversal ("..").
    /// Throws std::runtime_error if the file cannot be accessed or read.
    std::vector<std::uint8_t> loadImage(
        const std::string& directory,
        const std::string& filename);

    /// Decode QR code from encoded image bytes into string payload.
    /// Throws std::runtime_error for unsupported image formats or decode failure.
    std::string scanImage(const std::vector<std::uint8_t>& imageData);

    // ------------------------------------------------------------------------
    // 2. Cryptographic Helpers (ChaCha20)
    // ------------------------------------------------------------------------

    /// Decrypt ChaCha20 ciphertext payload into plain text string.
    std::string decryptPayload(
        const std::string& ciphertext,
        const uint8_t key[32],
        const uint8_t nonce[12],
        uint32_t counter = 1);

    // ------------------------------------------------------------------------
    // 3. Checksum Computation & Verification
    // ------------------------------------------------------------------------

    /// Calculate standard CRC32 checksum formatted as an 8-character hex string.
    std::string calculateChecksum(const std::string& payload);

    /// Verify payload integrity against expected checksum.
    /// Returns true if checksum matches, false otherwise.
    /// NOTE: Checksum verification MUST run before querying the database.
    bool verifyChecksum(
        const std::string& payload,
        const std::string& expectedChecksum);

    /// Extract data payload and checksum from a formatted token (e.g. "DATA#CHECKSUM" or "DATA|CHECKSUM")
    bool extractPayloadAndChecksum(
        const std::string& fullToken,
        std::string& outData,
        std::string& outChecksum);

    // ------------------------------------------------------------------------
    // 4. Employee Payload Parsing
    // ------------------------------------------------------------------------

    /// Parse a structured employee payload (format: "id|name|role|accessLevel|branch").
    /// Throws std::invalid_argument for malformed fields.
    Employee parseEmployee(const std::string& payload);

    // ------------------------------------------------------------------------
    // 5. Database Verification
    // ------------------------------------------------------------------------

    /// Match employee against the database.
    /// Returns true if employee exists and matches all fields; false otherwise.
    /// Propagates database exceptions.
    bool verifyEmployeeWithDatabase(
        const Employee& employee,
        const IEmployeeDatabase& database);

    // ------------------------------------------------------------------------
    // 6. Turnstile Gate Decision
    // ------------------------------------------------------------------------

    /// Evaluate access verification and trigger the turnstile barrier.
    /// Opens the barrier if verified is true; closes/keeps closed otherwise.
    bool decideGateAccess(
        bool isEmployeeVerified,
        Barrier& barrier);

    // ------------------------------------------------------------------------
    // 7. Complete Kiosk-Server Access Pipelines
    // ------------------------------------------------------------------------

    /// Full pipeline from QR payload containing embedded checksum ("data#checksum" or "data|checksum"):
    /// 1. Extract payload and checksum
    /// 2. Verify checksum (Rejects corrupted data BEFORE touching the database)
    /// 3. Parse employee data
    /// 4. Verify employee with database
    /// 5. Make gate decision and trigger barrier
    AccessDecision processAccess(
        const std::string& qrPayloadWithChecksum,
        const IEmployeeDatabase& database,
        Barrier& barrier);

    /// Full pipeline with explicit payload and expected checksum
    AccessDecision processAccess(
        const std::string& qrData,
        const std::string& expectedChecksum,
        const IEmployeeDatabase& database,
        Barrier& barrier);

    /// Full pipeline for encrypted QR codes:
    /// 1. Decrypt ChaCha20 payload
    /// 2. Extract & verify checksum (before touching DB)
    /// 3. Parse employee
    /// 4. Query database
    /// 5. Trigger turnstile gate
    AccessDecision processEncryptedAccess(
        const std::string& encryptedPayload,
        const uint8_t key[32],
        const uint8_t nonce[12],
        const IEmployeeDatabase& database,
        Barrier& barrier,
        uint32_t counter = 1);

    /// Full pipeline end-to-end starting from an image file:
    /// loadImage -> scanImage -> verifyChecksum -> queryDB -> OpenGate
    AccessDecision processAccessFromImage(
        const std::string& directory,
        const std::string& filename,
        const IEmployeeDatabase& database,
        Barrier& barrier);

    // ------------------------------------------------------------------------
    // 8. Merged Kiosk-Server Controller Class
    // ------------------------------------------------------------------------

    class KioskServer
    {
    private:
        const IEmployeeDatabase& m_database;
        Barrier& m_barrier;

    public:
        KioskServer(const IEmployeeDatabase& database, Barrier& barrier);

        /// Process a QR token string with embedded checksum
        AccessDecision processQrPayload(const std::string& payloadWithChecksum);

        /// Process separate data and checksum
        AccessDecision processQrPayload(const std::string& payload, const std::string& expectedChecksum);

        /// Process an encrypted QR code payload
        AccessDecision processEncryptedQrPayload(
            const std::string& encryptedPayload,
            const uint8_t key[32],
            const uint8_t nonce[12],
            uint32_t counter = 1);

        /// Process an image file from storage
        AccessDecision processImageFile(const std::string& directory, const std::string& filename);

        Barrier& getBarrier() { return m_barrier; }
        const Barrier& getBarrier() const { return m_barrier; }
        const IEmployeeDatabase& getDatabase() const { return m_database; }
    };
}

#endif // SERVER_HPP
