#ifndef SERVER_HPP
#define SERVER_HPP

#include "Verifier.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace server
{
    struct ScanRequest
    {
        Direction direction;
        std::string qr_text;
    };

    Verifier::KeyCache load_key_file(const std::string& path);
    std::optional<Direction> parse_direction(std::string_view token);
    std::optional<ScanRequest> parse_scan_line(std::string_view line);
} // namespace server

#endif // SERVER_HPP