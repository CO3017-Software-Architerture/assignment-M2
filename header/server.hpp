#ifndef SERVER_HPP
#define SERVER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory>

#include "qrgen.hpp"
#include "Verifier.hpp"
#include "barrier.hpp"

namespace server
{
    /// Access control evaluation result
    /// not implemented yet might be deleted next commit
    struct AccessDecision
    {
        bool granted{false};
        std::string message;
        key_id_t key_id;
        bool checksumVerified{false};
        bool databaseVerified{false};
        bool gateOpened{false};
    };

    // ------------------------------------------------------------------------
    // 1. File & Image I/O
    // ------------------------------------------------------------------------

    /*
     * Read full string from stdin/File if possible
     * Output: string inputed 
    */
    [[nodiscard]] std::string scanImage();

    /*
     * Input: String from scan image
     * Output: parsed QRContent 
    */
    qrgen::QRContent parseQR(std:: string);



    // ------------------------------------------------------------------------
    // 6. Turnstile Gate Decision
    // ------------------------------------------------------------------------

    /// Evaluate access verification via Verifier::handle_scan() and trigger the turnstile barrier.
    /// Opens the barrier if verified is true; closes/keeps closed otherwise.
    /// Expected output = output of handle_scan()
    bool decideGateAccess(
        qrgen::QRContent qr,
        Direction direction,
        Barrier barrier
        );

    /// @brief Main function that gonna loop inf until terminated. Read input->handle_scan->output_decision
    int main(int argc, char const *argv[]);
}

#endif // SERVER_HPP
