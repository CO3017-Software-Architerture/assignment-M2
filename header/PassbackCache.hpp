#include "main.hpp"
#include <map>

enum class Location
{
    IN,
    OUT
};

class PassbackCache
{
public:
    using passback_map_t = std::map<key_id_t, Location>;
private:
    passback_map_t m_passbackMap;


public:
    PassbackCache() = default;
    ~PassbackCache() = default;

    bool check_anti_passback(key_id_t key_id, Direction direction)
    {
        // TODO: Implement the anti-passback logic based on the direction and key_id
    }

    bool commit_passback(key_id_t key_id, Direction direction)
    {
        // TODO: Update the passback state for the given key_id and direction
    }

    bool reset_passback(key_id_t key_id)
    {
        // TODO: Reset the passback state for the given key_id
    }
};