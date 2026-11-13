#include "client.hpp"

client::LoadedSecretKey client::load_secret_key(const std::string &path)
{
    return client::LoadedSecretKey();
}

std::uint32_t client::unix_time()
{
    return std::uint32_t();
}

nonce_t client::random_nonce()
{
    return nonce_t();
}

client::payload_t client::build_payload(key_id_t key_id, std::uint32_t timestamp, const nonce_t &nonce)
{
    return payload_t();
}

std::vector<std::uint8_t> client::build_signed_message(const payload_t &payload)
{
    return std::vector<std::uint8_t>();
}

client::signature_t client::sign(const secret_key_t &secret_key, const std::vector<std::uint8_t> &message)
{
    return signature_t();
}

std::string client::encode_qr_text(const std::vector<std::uint8_t> &bytes)
{
    return std::string();
}

std::string client::generate_qr(const secret_key_t &secret_key, key_id_t key_id)
{
    return std::string();
}

void client::qr_refresh_loop(const secret_key_t &secret_key, key_id_t key_id)
{
}
int main(int argc, char const *argv[])
{
    
    return 0;
}
