#pragma once

#include "PassbackStore.hpp"
#include "domain.hpp"
#include <cstdint>
#include <map>

enum class Location
{
    IN,
    OUT
};

class PassbackCache : public IPassbackStore
{
public:
    using passback_map_t = std::map<key_id_t, Location>;
private:
    passback_map_t m_passbackMap;

public:
    PassbackCache() = default;
    ~PassbackCache() override = default;

    // Returns true when the direction is allowed without changing state.
    bool check_anti_passback(key_id_t key_id, Direction direction) const override;

    // Returns true when state is committed; false when the direction is disallowed.
    bool commit_passback(key_id_t key_id, Direction direction) override;

    // Returns true when an existing state was removed; false when no state existed.
    bool reset_passback(key_id_t key_id) override;
};