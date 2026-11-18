#include "Verifier.hpp"
#include "client.hpp"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    class NullBuffer final : public std::streambuf
    {
    protected:
        int_type overflow(int_type character) override
        {
            return traits_type::not_eof(character);
        }
    };

    class ScopedLogSilencer
    {
    public:
        ScopedLogSilencer() : m_previous(std::clog.rdbuf(&m_nullBuffer)) {}
        ~ScopedLogSilencer() { std::clog.rdbuf(m_previous); }

    private:
        NullBuffer m_nullBuffer;
        std::streambuf* m_previous;
    };

    struct SecretKeyWiper
    {
        client::secret_key_t& key;
        ~SecretKeyWiper() { sodium_memzero(key.data(), key.size()); }
    };

    struct Workload
    {
        Verifier::KeyCache keys;
        std::vector<std::string> qr_codes;
        Verifier::Clock::time_point scan_time;
    };

    Workload make_workload(std::size_t employee_count)
    {
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
            Verifier::Clock::now().time_since_epoch());

        Workload workload;
        workload.scan_time = Verifier::Clock::time_point{seconds};
        workload.qr_codes.reserve(employee_count);

        for (std::size_t i = 0; i < employee_count; ++i)
        {
            qrgen::PublicKey public_key{};
            client::secret_key_t secret_key{};
            SecretKeyWiper wipe_secret_key{secret_key};
            if (crypto_sign_keypair(public_key.data(), secret_key.data()) != 0)
                throw std::runtime_error("Failed to generate a test key pair");

            const auto key_id = qrgen::derive_key_id(public_key);
            if (!workload.keys.emplace(key_id, public_key).second)
                throw std::runtime_error("Generated a duplicate test key ID");

            const auto timestamp = static_cast<std::uint32_t>(seconds.count());
            const auto payload = client::build_payload(
                key_id, timestamp, client::random_nonce());
            const auto message = client::build_signed_message(payload);
            const auto signature = client::sign(secret_key, message);

            std::vector<std::uint8_t> token;
            token.reserve(payload.size() + signature.size());
            token.insert(token.end(), payload.begin(), payload.end());
            token.insert(token.end(), signature.begin(), signature.end());
            workload.qr_codes.push_back(client::encode_qr_text(token));
        }

        return workload;
    }

    std::chrono::microseconds percentile(
        const std::vector<std::chrono::microseconds>& sorted_latencies,
        std::size_t percentile_value)
    {
        const auto rank = (sorted_latencies.size() * percentile_value + 99) / 100;
        return sorted_latencies[rank - 1];
    }

    bool run_burst(std::size_t employee_count)
    {
        auto workload = make_workload(employee_count);
        NonceCache nonce_cache;
        PassbackCache passback_cache;
        Barrier barrier;
        Verifier verifier(nonce_cache, passback_cache, barrier, workload.keys);
        const NonceCache::Clock::time_point replay_time{};
        std::vector<std::chrono::microseconds> latencies;
        latencies.reserve(employee_count);

        ScopedLogSilencer silence_logs;
        const auto burst_start = std::chrono::steady_clock::now();
        for (const auto& qr : workload.qr_codes)
        {
            const auto scan_start = std::chrono::steady_clock::now();
            const auto decision = verifier.handle_scan(
                qr, Direction::IN, workload.scan_time, replay_time);
            const auto scan_end = std::chrono::steady_clock::now();
            latencies.push_back(
                std::chrono::duration_cast<std::chrono::microseconds>(scan_end - scan_start));

            if (decision != Decision::ALLOW)
                return false;
        }
        const auto burst_end = std::chrono::steady_clock::now();

        std::sort(latencies.begin(), latencies.end());
        const auto elapsed =
            std::chrono::duration<double>(burst_end - burst_start).count();
        const auto throughput = elapsed > 0.0 ? employee_count / elapsed : 0.0;

        std::cout << employee_count << " employees, all scans ready at burst start\n"
                  << "  Result: " << latencies.size() << '/' << employee_count
                  << " ALLOW\n"
                  << "  Burst processing time: " << elapsed << " s\n"
                  << "  Throughput: " << throughput << " scans/s\n"
                  << "  Handler latency p50/p95/p99: "
                  << percentile(latencies, 50).count() << '/'
                  << percentile(latencies, 95).count() << '/'
                  << percentile(latencies, 99).count() << " us\n";
        return true;
    }
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    try
    {
        if (!run_burst(600) || !run_burst(800))
        {
            std::cerr << "Load test failed: a valid employee scan was not allowed\n";
            return 1;
        }
    }
    catch (const std::exception& error)
    {
        std::cerr << "Load test failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
