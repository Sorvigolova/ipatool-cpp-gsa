// srp.cpp — SRP-6a client for Apple GSA. SKELETON (not implemented yet).
//
// Implementation plan (all over mbedtls_mpi; reuse sha2:: and protect::):
//   N   = RFC-5054 Appendix A 2048-bit prime, g = 2, N_LEN = 256
//   a   = 32 random bytes (protect::secure_random);  A = g^a mod N
//   k   = SHA256( pad(N) || pad(g) )
//   u   = SHA256( pad(A) || pad(B) )
//   x   = SHA256( salt || SHA256( ":" || PBKDF2(SHA256(pwd), salt, iters, 32) ) )
//   S   = (B - k*g^x)^(a + u*x) mod N
//   K   = SHA256( pad(S) )
//   M1  = SHA256( (H(N) xor H(g)) || H(email_lowercased) || salt || pad(A) || pad(B) || K )
//
// Keep an RAII wrapper around mbedtls_mpi so no path leaks (unlike the old
// OpenSSL BN code, which leaked the inner BNs on exception paths).

#include "srp.h"
#include <stdexcept>
#include <cstdio>

namespace srp {

struct Client::Impl {
    Bytes A;   // client public key (padded to 256)
    Bytes K;   // session key (32)
    Bytes M1;  // client proof (32)
    // TODO: hold the private a (mbedtls_mpi) between construction and challenge.
};

Client::Client() : p(new Impl) {
    // TODO: pick random a, compute A = g^a mod N, fill p->A.
}

Client::~Client() { delete p; }

const Bytes& Client::A()  const { return p->A;  }
const Bytes& Client::K()  const { return p->K;  }
const Bytes& Client::M1() const { return p->M1; }

void Client::process_challenge(const std::string& /*email*/,
                               const std::string& /*password*/,
                               const Bytes& /*salt*/,
                               const Bytes& /*B*/,
                               int /*iters*/) {
    throw std::runtime_error("srp::Client::process_challenge: not implemented yet");
}

void selftest() {
    fprintf(stderr, "[srp] selftest: not implemented yet\n");
}

} // namespace srp
