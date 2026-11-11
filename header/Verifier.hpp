#include "NonceCache.hpp"
#include "PassbackCache.hpp"
#include "main.hpp"

class Verifier
{
private:
    NonceCache& m_nonceCache;
    PassbackCache& m_passbackCache;
    Barrier& m_barrier;
public:
    Verifier(NonceCache& nonceCache, PassbackCache& passbackCache)
        : m_nonceCache(nonceCache), m_passbackCache(passbackCache) {}
    
    ~Verifier() = default;

    void handle_scan()
    {
        // TODO: Implement the verification logic for the scanned QR code
        // m_nonceCache.purge_expired(timestamp);
    }

    bool check_timestamp(std::uint32_t ts, clock::time_point now = clock::now())
    {
    }

    bool log_event(Decision decision, key_id_t key_id, Direction direction, clock::time_point timestamp = clock::now())
    {
        // TODO: Implement logging of the access decision event with relevant details
        // Suggested: file reading or writing to a log file or console output
        // SQLite or DB logging if you are feeling cool ig
    }

    void open_gate()
    {
        // TODO: hook into the Barrier class to open the gate
    }

};