#pragma once
// srp.h — SRP-6a client for Apple Grand Slam (GSA).
//
// RFC-5054 Appendix A 2048-bit group, g = 2, SHA-256. Apple "s2k" x-derivation:
//   x  = SHA256( salt || SHA256( ":" || PBKDF2-SHA256( SHA256(password), salt, iters, 32 ) ) )
//   M1 = SHA256( (H(N) xor H(g)) || H(email) || salt || A || B || K )
// Every big-endian value is zero-padded to len(N) = 256 bytes before hashing.
//
// Pure math over mbedtls_mpi (pImpl hides the bignum type) — no HTTP, no plist.
// Reuses the project's sha2 (SHA-256 / PBKDF2) and protect (RNG); no OpenSSL.

#include <vector>
#include <string>
#include <cstdint>

namespace srp {
using Bytes = std::vector<uint8_t>;

class Client {
public:
    Client();                                    // random private a, A = g^a mod N
    ~Client();
    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    // Client public key A (256 bytes, zero-padded) — goes into the "A2k" field.
    const Bytes& A() const;

    // Consume the server challenge (salt s, server public B, PBKDF2 iters) and
    // the credentials; derive the session key K and client proof M1.
    // Throws std::runtime_error on a malformed challenge (e.g. B mod N == 0).
    void process_challenge(const std::string& email,
                           const std::string& password,
                           const Bytes&       salt,
                           const Bytes&       B,
                           int                iters);

    const Bytes& K()  const;   // session key SHA256(S), 32 bytes — spd key/iv source
    const Bytes& M1() const;   // client proof, 32 bytes — goes into "M1"

private:
    struct Impl;
    Impl* p;
};

// Deterministic self-test against fixed vectors (compare with srp_test.py).
// Prints each intermediate to stderr. Development aid only.
void selftest();

} // namespace srp
