#pragma once

#include <string>
#include <memory>
#include <vector>

namespace crypto
{
    // RAII PIMPL wrappers
    struct KeyPair
    {
        std::string pub_pem;
        std::string priv_pem;
    };

    std::unique_ptr<KeyPair> generate_rsa_keypair(int bits = 2048);

    // PEM getters
    std::string get_public_pem(const KeyPair &);
    std::string get_private_pem(const KeyPair &);

    // Loaders (return OpenSSL-managed pointers via PIMPL; here we expose APIs that take PEM strings)
    using Bytes = std::vector<unsigned char>;

    bool rsa_encrypt_oaep(const std::string &pub_pem, const Bytes &plaintext, Bytes &ciphertext);
    bool rsa_decrypt_oaep(const std::string &priv_pem, const Bytes &ciphertext, Bytes &plaintext);

    bool rsa_sign_pss(const std::string &priv_pem, const Bytes &message, Bytes &signature);
    bool rsa_verify_pss(const std::string &pub_pem, const Bytes &message, const Bytes &signature);

    // Base64 helpers (URL-safe not required; standard base64 is fine)
    std::string b64encode(const Bytes &in);
    Bytes b64decode(const std::string &s);

    // Simple JSON helpers (very small — not a full parser; just enough for our fixed payloads)
    std::string json_escape(const std::string &s);
    std::string json_field(const std::string &name, const std::string &value);
    std::string json_obj(std::initializer_list<std::pair<std::string, std::string>> fields);

    // Tiny extractor: finds value for "key" in a flat JSON with string values only.
    bool json_get(const std::string &json, const std::string &key, std::string &out);

    // Utilities
    std::string sha256_hex(const std::string &s); // for logging integrity

} // namespace crypto
