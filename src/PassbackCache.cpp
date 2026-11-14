#include "PassbackCache.hpp"

bool PassbackCache::check_anti_passback(key_id_t key_id, Direction direction) const
{
    const auto entry = m_passbackMap.find(key_id);
    const auto target = direction == Direction::IN ? Location::IN : Location::OUT;
    return entry == m_passbackMap.end() || entry->second != target;
}

bool PassbackCache::commit_passback(key_id_t key_id, Direction direction)
{
    if (!check_anti_passback(key_id, direction))
        return false;

    m_passbackMap.insert_or_assign(key_id, direction == Direction::IN ? Location::IN : Location::OUT);
    return true;
}

bool PassbackCache::reset_passback(key_id_t key_id)
{
    return m_passbackMap.erase(key_id) != 0;
}
