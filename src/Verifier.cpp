#include "Verifier.hpp"

void Verifier::handle_scan()
{
    // TODO
}

bool Verifier::check_timestamp(std::uint32_t ts, Clock::time_point now)
{
    return false;
}

bool Verifier::log_event(Decision decision, key_id_t key_id, Direction direction, Clock::time_point timestamp = Clock::now())
{
    // TODO: Implement logging of the access decision event with relevant details
    // Suggested: file reading or writing to a log file or console output
    // SQLite or DB logging if you are feeling cool ig
}

void Verifier::open_gate()
{
}
