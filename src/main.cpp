#include <iostream>
#include <cassert>

#include "..\header\main.hpp"
#include "..\header\qrgen.hpp"
#include "..\header\server.hpp"

const uint8_t KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

int tc_01()
{
    std::cout<<"---TEST CASE 01----\n";
    Employee staf01(0,"mjnk","Admin",AccessLevel::Administrator);
    std::string cipher = qrgen::generateCode(staf01);
    std::cout<<qrgen::generateCode(staf01)<<'\n';

    std::cout<<"decrypt part"<<'\n';
    crypto::Nonce nonce{};
    std::copy_n(
        reinterpret_cast<const uint8_t*>(cipher.data()),
        nonce.size(),
        nonce.begin());
    const std::string ciphertext = cipher.substr(nonce.size());
    std::string decrypted =
        crypto::ChaCha20Cipher::decrypt(ciphertext, KEY, nonce.data());
    std::cout<<decrypted<<'\n';
    std::cout<<"--------------------\n";
    return 0;
}

int tc_02_kiosk_server_pipeline()
{
    std::cout << "\n---TEST CASE 02: KIOSK-SERVER ACCESS PIPELINE----\n";

    // 1. Setup Employee Database with registered employee
    InMemoryEmployeeDatabase db;
    Employee emp1(101, "Nguyen Van A", "Staff", AccessLevel::Employee, 'B');
    db.addEmployee(emp1);

    Barrier barrier;
    server::KioskServer kiosk(db, barrier);

    // 2. Prepare valid payload: "id|name|role|accessLevel|branch" + checksum
    std::string validData = emp1.toPayloadString();
    std::string validChecksum = server::calculateChecksum(validData);
    std::string validToken = validData + "#" + validChecksum;

    std::cout << "[Test 2.1] Processing valid QR token: " << validToken << "\n";
    server::AccessDecision result1 = kiosk.processQrPayload(validToken);

    std::cout << "  Granted: " << std::boolalpha << result1.granted << "\n";
    std::cout << "  Checksum Verified: " << result1.checksumVerified << "\n";
    std::cout << "  Database Verified: " << result1.databaseVerified << "\n";
    std::cout << "  Gate Opened: " << result1.gateOpened << " (Barrier state: " << barrier.isOpen() << ")\n";
    std::cout << "  Message: " << result1.message << "\n";
    assert(result1.granted == true);
    assert(barrier.isOpen() == true);

    // Reset barrier
    barrier.CloseGate();

    // 3. Test corrupted payload (tampered checksum)
    std::cout << "\n[Test 2.2] Processing corrupted token (tampered checksum)...\n";
    std::string corruptedToken = validData + "#BADCHECKSUM";
    server::AccessDecision result2 = kiosk.processQrPayload(corruptedToken);

    std::cout << "  Granted: " << result2.granted << "\n";
    std::cout << "  Checksum Verified: " << result2.checksumVerified << "\n";
    std::cout << "  Database Verified: " << result2.databaseVerified << " (Should be false: DB not hit!)\n";
    std::cout << "  Gate Opened: " << result2.gateOpened << "\n";
    std::cout << "  Message: " << result2.message << "\n";
    assert(result2.granted == false);
    assert(result2.checksumVerified == false);
    assert(result2.databaseVerified == false);
    assert(barrier.isOpen() == false);

    // 4. Test valid checksum but employee NOT registered in database
    std::cout << "\n[Test 2.3] Processing unknown employee with valid checksum...\n";
    Employee empUnknown(999, "Intruder", "Unknown", AccessLevel::Guest, 'L');
    std::string unknownData = empUnknown.toPayloadString();
    std::string unknownToken = unknownData + "#" + server::calculateChecksum(unknownData);
    server::AccessDecision result3 = kiosk.processQrPayload(unknownToken);

    std::cout << "  Granted: " << result3.granted << "\n";
    std::cout << "  Checksum Verified: " << result3.checksumVerified << "\n";
    std::cout << "  Database Verified: " << result3.databaseVerified << "\n";
    std::cout << "  Gate Opened: " << result3.gateOpened << "\n";
    std::cout << "  Message: " << result3.message << "\n";
    assert(result3.granted == false);
    assert(result3.checksumVerified == true);
    assert(result3.databaseVerified == false);
    assert(barrier.isOpen() == false);

    std::cout << "\n--- ALL KIOSK-SERVER PIPELINE TESTS PASSED! ---\n\n";
    return 0;
}

int main()
{
    tc_01();
    tc_02_kiosk_server_pipeline();
    return 0;
}
