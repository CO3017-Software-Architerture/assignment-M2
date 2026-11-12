#include "NonceCache.hpp"
#include "PassbackCache.hpp"
#include "barrier.hpp"
#include "main.hpp"

class Verifier
{
private:
    NonceCache& m_nonceCache;
    PassbackCache& m_passbackCache;
    Barrier& m_barrier;
public:
    Verifier(NonceCache& nonceCache, PassbackCache& passbackCache, Barrier& barrier)
        : m_nonceCache(nonceCache), m_passbackCache(passbackCache), m_barrier(barrier) {}
    
    ~Verifier() = default;

    void handle_scan();

    bool check_timestamp(std::uint32_t ts, clock::time_point now = clock::now());

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