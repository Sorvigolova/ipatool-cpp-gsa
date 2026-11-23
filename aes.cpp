#include "aes.h"
#include <mbedtls/version.h>   // MBEDTLS_VERSION_MAJOR

// AES-GCM. Output is byte-identical to the previous OpenSSL EVP implementation
// for the same key/iv/aad/plaintext, so existing account files stay decryptable.
//
// Two backends, chosen by mbedTLS major version:
//   • 2.x / 3.x — the legacy low-level mbedtls_gcm_* API.
//   • 4.x       — those APIs were removed; crypto moved to PSA (TF-PSA-Crypto),
//                 so we go through psa_aead_*. PSA appends the tag to the
//                 ciphertext, which we split/join to keep our (ct, tag) shape.
// The algorithm and parameters are the same either way → identical bytes.

#if MBEDTLS_VERSION_MAJOR >= 4
#  include <psa/crypto.h>

namespace {
// psa_crypto_init() is idempotent; run it once per process on first use.
void ensure_psa() {
    static const psa_status_t s = psa_crypto_init();
    (void)s;
}
} // namespace

namespace aes {

GcmOutput gcm_encrypt(const Bytes& key, const Bytes& iv,
                      const Bytes& plaintext, const Bytes& aad) {
    ensure_psa();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_key_id_t k = 0;
    if (psa_import_key(&attr, key.data(), key.size(), &k) != PSA_SUCCESS)
        throw std::runtime_error("aes::gcm_encrypt: key import failed");

    Bytes  out(plaintext.size() + 16);   // ciphertext || 16-byte tag
    size_t olen = 0;
    psa_status_t s = psa_aead_encrypt(
        k, PSA_ALG_GCM, iv.data(), iv.size(),
        aad.data(), aad.size(),
        plaintext.data(), plaintext.size(),
        out.data(), out.size(), &olen);
    psa_destroy_key(k);
    if (s != PSA_SUCCESS || olen < 16)
        throw std::runtime_error("aes::gcm_encrypt: encryption failed");

    size_t ctlen = olen - 16;
    return { Bytes(out.begin(), out.begin() + ctlen),
             Bytes(out.begin() + ctlen, out.begin() + olen) };
}

Bytes gcm_decrypt(const Bytes& key, const Bytes& iv,
                  const Bytes& ciphertext, const Bytes& tag,
                  const Bytes& aad) {
    ensure_psa();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_key_id_t k = 0;
    if (psa_import_key(&attr, key.data(), key.size(), &k) != PSA_SUCCESS)
        throw std::runtime_error("aes::gcm_decrypt: key import failed");

    // PSA wants ciphertext||tag as one buffer.
    Bytes in;
    in.reserve(ciphertext.size() + tag.size());
    in.insert(in.end(), ciphertext.begin(), ciphertext.end());
    in.insert(in.end(), tag.begin(), tag.end());

    Bytes  plain(ciphertext.size());
    size_t olen = 0;
    psa_status_t s = psa_aead_decrypt(
        k, PSA_ALG_GCM, iv.data(), iv.size(),
        aad.data(), aad.size(),
        in.data(), in.size(),
        plain.data(), plain.size(), &olen);
    psa_destroy_key(k);
    if (s != PSA_SUCCESS)
        throw std::runtime_error("aes::gcm_decrypt: authentication tag mismatch");
    plain.resize(olen);
    return plain;
}

// AES-256-CBC + PKCS#7 (GSA spd). PSA one-shot takes IV prepended to the input
// and strips PKCS#7 on finish; matches the previous OpenSSL EVP behaviour.
Bytes cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext) {
    ensure_psa();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_PKCS7);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_key_id_t k = 0;
    if (psa_import_key(&attr, key.data(), key.size(), &k) != PSA_SUCCESS)
        throw std::runtime_error("aes::cbc_decrypt: key import failed");

    // PSA one-shot expects IV || ciphertext as a single input buffer.
    Bytes in;
    in.reserve(iv.size() + ciphertext.size());
    in.insert(in.end(), iv.begin(), iv.end());
    in.insert(in.end(), ciphertext.begin(), ciphertext.end());

    Bytes  out(ciphertext.size());   // plaintext is <= ciphertext (padding removed)
    size_t olen = 0;
    psa_status_t s = psa_cipher_decrypt(
        k, PSA_ALG_CBC_PKCS7, in.data(), in.size(),
        out.data(), out.size(), &olen);
    psa_destroy_key(k);
    if (s != PSA_SUCCESS)
        throw std::runtime_error("aes::cbc_decrypt: decryption failed (bad key or padding)");
    out.resize(olen);
    return out;
}

} // namespace aes

#else  // ── mbedTLS 2.x / 3.x: legacy low-level GCM ─────────────────────────────
#  include <mbedtls/gcm.h>
#  include <mbedtls/cipher.h>

namespace aes {

GcmOutput gcm_encrypt(const Bytes& key, const Bytes& iv,
                      const Bytes& plaintext, const Bytes& aad) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                           key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&ctx);
        throw std::runtime_error("aes::gcm_encrypt: setkey failed");
    }

    Bytes ct(plaintext.size());
    Bytes tag(16);
    int rc = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(),
        iv.data(), iv.size(),
        aad.data(), aad.size(),
        plaintext.data(), ct.data(),
        tag.size(), tag.data());
    mbedtls_gcm_free(&ctx);

    if (rc != 0)
        throw std::runtime_error("aes::gcm_encrypt: encryption failed");
    return {ct, tag};
}

Bytes gcm_decrypt(const Bytes& key, const Bytes& iv,
                  const Bytes& ciphertext, const Bytes& tag,
                  const Bytes& aad) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                           key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&ctx);
        throw std::runtime_error("aes::gcm_decrypt: setkey failed");
    }

    Bytes plain(ciphertext.size());
    int rc = mbedtls_gcm_auth_decrypt(
        &ctx, ciphertext.size(),
        iv.data(), iv.size(),
        aad.data(), aad.size(),
        tag.data(), tag.size(),
        ciphertext.data(), plain.data());
    mbedtls_gcm_free(&ctx);

    // MBEDTLS_ERR_GCM_AUTH_FAILED (or any non-zero) → tag mismatch / corruption.
    if (rc != 0)
        throw std::runtime_error("aes::gcm_decrypt: authentication tag mismatch");
    return plain;
}

// AES-256-CBC + PKCS#7 (GSA spd). The mbedtls_cipher layer validates and strips
// PKCS#7 on finish; matches the previous OpenSSL EVP behaviour.
Bytes cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext) {
    const mbedtls_cipher_info_t* info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if (!info)
        throw std::runtime_error("aes::cbc_decrypt: AES-256-CBC unavailable");

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    Bytes  out(ciphertext.size() + 16);   // headroom; trimmed to real length below
    size_t olen = 0, finlen = 0;

    int rc = mbedtls_cipher_setup(&ctx, info);
    if (rc == 0) rc = mbedtls_cipher_setkey(&ctx, key.data(),
                          static_cast<int>(key.size() * 8), MBEDTLS_DECRYPT);
    if (rc == 0) rc = mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);
    if (rc == 0) rc = mbedtls_cipher_set_iv(&ctx, iv.data(), iv.size());
    if (rc == 0) rc = mbedtls_cipher_reset(&ctx);
    if (rc == 0) rc = mbedtls_cipher_update(&ctx, ciphertext.data(), ciphertext.size(),
                          out.data(), &olen);
    if (rc == 0) rc = mbedtls_cipher_finish(&ctx, out.data() + olen, &finlen);
    mbedtls_cipher_free(&ctx);

    // MBEDTLS_ERR_CIPHER_INVALID_PADDING (or any non-zero) → wrong key / corruption.
    if (rc != 0)
        throw std::runtime_error("aes::cbc_decrypt: decryption failed (bad key or padding)");
    out.resize(olen + finlen);
    return out;
}

} // namespace aes

#endif
