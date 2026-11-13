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

    bool check_timestamp(std::uint32_t ts, clock::time_point now);

    bool log_event(Decision decision, key_id_t key_id, Direction direction, clock::time_point timestamp);

    void open_gate();

};