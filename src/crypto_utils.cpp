#include "rsa_demo_cpp/crypto_utils.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <map>

// RAII wrappers for OpenSSL pointers
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;



namespace crypto
{
    std::unique_ptr<KeyPair> generate_rsa_keypair(int bits)
    {
        std::unique_ptr<KeyPair> kp(new KeyPair);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx)
            return nullptr;
        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }
        EVP_PKEY_CTX_free(ctx);

        // Write private PEM
        BIO *mem = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(mem, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(mem, &bptr);
        kp->priv_pem.assign(bptr->data, bptr->length);
        BIO_free(mem);

        // Write public PEM
        mem = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(mem, pkey);
        BIO_get_mem_ptr(mem, &bptr);
        kp->pub_pem.assign(bptr->data, bptr->length);
        BIO_free(mem);

        EVP_PKEY_free(pkey);
        return kp;
    }

    std::string get_public_pem(const KeyPair &k)
    {
        return k.pub_pem;
    }
    std::string get_private_pem(const KeyPair &k)
    {
        return k.priv_pem;
    }

    static EVP_PKEY *load_pub(const std::string &pem)
    {
        BIO *b = BIO_new_mem_buf(pem.data(), (int)pem.size());
        EVP_PKEY *k = PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr);
        BIO_free(b);
        return k;
    }
    static EVP_PKEY *load_priv(const std::string &pem)
    {
        BIO *b = BIO_new_mem_buf(pem.data(), (int)pem.size());
        EVP_PKEY *k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
        BIO_free(b);
        return k;
    }

    bool rsa_encrypt_oaep(const std::string &pub_pem, const Bytes &plaintext, Bytes &ciphertext)
    {
        ciphertext.clear();

        EVP_PKEY_ptr pub(load_pub(pub_pem), EVP_PKEY_free);
        if (!pub)
            return false;

        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(pub.get(), nullptr), EVP_PKEY_CTX_free);
        if (!ctx)
            return false;

        if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
            return false;
        if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
            return false;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0)
            return false;
#endif

        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0)
            return false;

        ciphertext.resize(outlen);
        if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0)
            return false;

        ciphertext.resize(outlen);
        return true;
    }

    bool rsa_decrypt_oaep(const std::string &priv_pem, const Bytes &ciphertext, Bytes &plaintext)
    {
        plaintext.clear();

        EVP_PKEY_ptr priv(load_priv(priv_pem), EVP_PKEY_free);
        if (!priv)
            return false;

        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(priv.get(), nullptr), EVP_PKEY_CTX_free);
        if (!ctx)
            return false;

        if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
            return false;
        if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
            return false;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0)
            return false;
#endif

        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0)
            return false;

        plaintext.resize(outlen);
        if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0)
            return false;

        plaintext.resize(outlen);
        return true;
    }

    bool rsa_sign_pss(const std::string &priv_pem, const Bytes &msg, Bytes &sig)
    {
        sig.clear();

        EVP_PKEY_ptr priv(load_priv(priv_pem), EVP_PKEY_free);
        if (!priv)
            return false;

        EVP_MD_CTX_ptr mctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!mctx)
            return false;

        if (EVP_DigestSignInit(mctx.get(), nullptr, EVP_sha256(), nullptr, priv.get()) <= 0)
            return false;

        EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(mctx.get());
        if (!pctx)
            return false;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            return false;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0) // saltlen = hashlen
            return false;

        if (EVP_DigestSignUpdate(mctx.get(), msg.data(), msg.size()) <= 0)
            return false;

        size_t siglen = 0;
        if (EVP_DigestSignFinal(mctx.get(), nullptr, &siglen) <= 0)
            return false;

        sig.resize(siglen);
        if (EVP_DigestSignFinal(mctx.get(), sig.data(), &siglen) <= 0)
            return false;

        sig.resize(siglen);
        return true;
    }

    bool rsa_verify_pss(const std::string &pub_pem, const Bytes &msg, const Bytes &signature)
    {
        EVP_PKEY_ptr pub(load_pub(pub_pem), EVP_PKEY_free);
        if (!pub)
            return false;

        EVP_MD_CTX_ptr mctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!mctx)
            return false;

        if (EVP_DigestVerifyInit(mctx.get(), nullptr, EVP_sha256(), nullptr, pub.get()) <= 0)
            return false;

        EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(mctx.get());
        if (!pctx)
            return false;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            return false;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0)
            return false;

        if (EVP_DigestVerifyUpdate(mctx.get(), msg.data(), msg.size()) <= 0)
            return false;

        int rc = EVP_DigestVerifyFinal(mctx.get(), signature.data(), signature.size());
        return rc == 1; // 1 = valid, 0 = invalid, <0 = error
    }

    std::string b64encode(const Bytes &in)
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO *mem = BIO_new(BIO_s_mem());
        BIO_push(b64, mem);
        BIO_write(b64, in.data(), (int)in.size());
        BIO_flush(b64);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        std::string out(bptr->data, bptr->length);
        BIO_free_all(b64);
        return out;
    }
    Bytes b64decode(const std::string &s)
    {
        Bytes out(s.size(), 0);
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO *mem = BIO_new_mem_buf(s.data(), (int)s.size());
        BIO_push(b64, mem);
        int n = BIO_read(b64, out.data(), (int)out.size());
        if (n < 0)
            n = 0;
        out.resize(n);
        BIO_free_all(b64);
        return out;
    }

    // ultra-small JSON helpers (flat, string-only)
    std::string json_escape(const std::string &s)
    {
        std::ostringstream oss;
        for (char c : s)
        {
            switch (c)
            {
            case '\\':
                oss << "\\\\";
                break;
            case '"':
                oss << "\\\"";
                break;
            case '\n':
                oss << "\\n";
                break;
            case '\r':
                oss << "\\r";
                break;
            case '\t':
                oss << "\\t";
                break;
            default:
                oss << c;
                break;
            }
        }
        return oss.str();
    }
    std::string json_field(const std::string &name, const std::string &value)
    {
        return "\"" + name + "\":\"" + json_escape(value) + "\"";
    }
    std::string json_obj(std::initializer_list<std::pair<std::string, std::string>> fields)
    {
        std::ostringstream oss;
        oss << "{";
        bool first = true;
        for (auto &kv : fields)
        {
            if (!first)
                oss << ",";
            first = false;
            oss << json_field(kv.first, kv.second);
        }
        oss << "}";
        return oss.str();
    }

    static bool extract_string_field(const std::string &json, const std::string &key, std::string &out)
    {
        // naive: search for "key":"...". Safe enough for demo input we control.
        std::string pat = "\"" + key + "\":\"";
        auto p = json.find(pat);
        if (p == std::string::npos)
            return false;
        p += pat.size();
        std::ostringstream val;
        for (size_t i = p; i < json.size(); ++i)
        {
            char c = json[i];
            if (c == '\\')
            { // simple unescape of \" and \\ and \n\r\t
                if (i + 1 < json.size())
                {
                    char n = json[i + 1];
                    if (n == '"' || n == '\\')
                    {
                        val << n;
                        i++;
                    }
                    else if (n == 'n')
                    {
                        val << '\n';
                        i++;
                    }
                    else if (n == 'r')
                    {
                        val << '\r';
                        i++;
                    }
                    else if (n == 't')
                    {
                        val << '\t';
                        i++;
                    }
                    else
                    {
                        val << n;
                        i++;
                    }
                }
            }
            else if (c == '"')
            {
                out = val.str();
                return true;
            }
            else
            {
                val << c;
            }
        }
        return false;
    }

    bool json_get(const std::string &json, const std::string &key, std::string &out)
    {
        return extract_string_field(json, key, out);
    }

    std::string sha256_hex(const std::string &s)
    {
        unsigned char md[32];
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, s.data(), s.size());
        EVP_DigestFinal_ex(ctx, md, nullptr);
        EVP_MD_CTX_free(ctx);
        std::ostringstream oss;
        for (int i = 0; i < 32; i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)md[i];
        return oss.str();
    }

} // namespace crypto
