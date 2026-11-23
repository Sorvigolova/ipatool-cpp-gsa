// srp.cpp — SRP-6a client for Apple GSA, over mbedtls_mpi.
//
// Ported 1:1 from the validated OpenSSL reference (cross-checked against
// srp_test.py). RFC-5054 Appendix A 2048-bit group, g = 2, SHA-256.
//   k  = SHA256( pad(N) || pad(g) )
//   u  = SHA256( pad(A) || pad(B) )
//   x  = SHA256( salt || SHA256( ":" || PBKDF2(SHA256(pwd), salt, iters, 32) ) )
//   S  = (B - k*g^x)^(a + u*x) mod N ;  K = SHA256( pad(S) )
//   M1 = SHA256( (H(N) xor H(pad(g))) || H(email_lc) || salt || pad(A) || pad(B) || K )
// Every big-endian value is zero-padded to len(N) = 256 before hashing.
//
// Crypto via sha2:: (SHA-256 / PBKDF2) + protect:: (RNG); bignum via mbedtls_mpi.
// No OpenSSL. mbedtls_mpi is wrapped in an RAII type so no path leaks.

#include "srp.h"
#include "sha2.h"
#include "protect.h"
#include <mbedtls/version.h>       // MBEDTLS_VERSION_MAJOR
// mbedtls_mpi (bignum) is a public header on 2.x/3.x. In 4.x the low-level crypto
// moved to TF-PSA-Crypto and bignum became a "private" header whose prototypes are
// gated behind MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS (the opt-in for private APIs);
// the symbols are still exported from libmbedcrypto, so we opt in and include it.
#if MBEDTLS_VERSION_MAJOR >= 4
#  define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#  include <mbedtls/private/bignum.h>
#else
#  include <mbedtls/bignum.h>
#endif
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <string>

namespace srp {
namespace {

// RFC-5054 Appendix A / pysrp NG_2048 prime (NOT the RFC-3526 IKE prime), g = 2.
const unsigned char SRP_N_2048[256] = {
    0xac,0x6b,0xdb,0x41,0x32,0x4a,0x9a,0x9b,0xf1,0x66,0xde,0x5e,0x13,0x89,0x58,0x2f,
    0xaf,0x72,0xb6,0x65,0x19,0x87,0xee,0x07,0xfc,0x31,0x92,0x94,0x3d,0xb5,0x60,0x50,
    0xa3,0x73,0x29,0xcb,0xb4,0xa0,0x99,0xed,0x81,0x93,0xe0,0x75,0x77,0x67,0xa1,0x3d,
    0xd5,0x23,0x12,0xab,0x4b,0x03,0x31,0x0d,0xcd,0x7f,0x48,0xa9,0xda,0x04,0xfd,0x50,
    0xe8,0x08,0x39,0x69,0xed,0xb7,0x67,0xb0,0xcf,0x60,0x95,0x17,0x9a,0x16,0x3a,0xb3,
    0x66,0x1a,0x05,0xfb,0xd5,0xfa,0xaa,0xe8,0x29,0x18,0xa9,0x96,0x2f,0x0b,0x93,0xb8,
    0x55,0xf9,0x79,0x93,0xec,0x97,0x5e,0xea,0xa8,0x0d,0x74,0x0a,0xdb,0xf4,0xff,0x74,
    0x73,0x59,0xd0,0x41,0xd5,0xc3,0x3e,0xa7,0x1d,0x28,0x1e,0x44,0x6b,0x14,0x77,0x3b,
    0xca,0x97,0xb4,0x3a,0x23,0xfb,0x80,0x16,0x76,0xbd,0x20,0x7a,0x43,0x6c,0x64,0x81,
    0xf1,0xd2,0xb9,0x07,0x87,0x17,0x46,0x1a,0x5b,0x9d,0x32,0xe6,0x88,0xf8,0x77,0x48,
    0x54,0x45,0x23,0xb5,0x24,0xb0,0xd5,0x7d,0x5e,0xa7,0x7a,0x27,0x75,0xd2,0xec,0xfa,
    0x03,0x2c,0xfb,0xdb,0xf5,0x2f,0xb3,0x78,0x61,0x60,0x27,0x90,0x04,0xe5,0x7a,0xe6,
    0xaf,0x87,0x4e,0x73,0x03,0xce,0x53,0x29,0x9c,0xcc,0x04,0x1c,0x7b,0xc3,0x08,0xd8,
    0x2a,0x56,0x98,0xf3,0xa8,0xd0,0xc3,0x82,0x71,0xae,0x35,0xf8,0xe9,0xdb,0xfb,0xb6,
    0x94,0xb5,0xc8,0x03,0xd8,0x9f,0x7a,0xe4,0x35,0xde,0x23,0x6d,0x52,0x5f,0x54,0x75,
    0x9b,0x65,0xe3,0x72,0xfc,0xd6,0x8e,0xf2,0x0f,0xa7,0x11,0x1f,0x9e,0x4a,0xff,0x73
};
constexpr size_t N_LEN = 256;

[[noreturn]] void fail(const char* w) { throw std::runtime_error(std::string("srp: ") + w); }
void chk(int rc, const char* w)        { if (rc != 0) fail(w); }

// RAII wrapper around mbedtls_mpi (no leaks on any path).
struct Mpi {
    mbedtls_mpi v;
    Mpi()  { mbedtls_mpi_init(&v); }
    ~Mpi() { mbedtls_mpi_free(&v); }
    Mpi(const Mpi&)            = delete;
    Mpi& operator=(const Mpi&) = delete;
    mbedtls_mpi*       get()       { return &v; }
    const mbedtls_mpi* get() const { return &v; }
};

Bytes to_padded(const Mpi& x, size_t len) {
    Bytes out(len);
    chk(mbedtls_mpi_write_binary(x.get(), out.data(), len), "mpi write");
    return out;
}
void from_bin(Mpi& x, const uint8_t* d, size_t n) {
    chk(mbedtls_mpi_read_binary(x.get(), d, n), "mpi read");
}
void from_bin(Mpi& x, const Bytes& b) { from_bin(x, b.data(), b.size()); }

Bytes sha(const Bytes& b)       { return sha2::digest(b); }
Bytes sha(const std::string& s) { return sha2::digest(s); }

Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes r; r.reserve(a.size() + b.size());
    r.insert(r.end(), a.begin(), a.end());
    r.insert(r.end(), b.begin(), b.end());
    return r;
}

// Apple s2k x-derivation. Shared by process_challenge() and selftest().
Bytes derive_x(const std::string& password, const Bytes& salt, int iters) {
    const Bytes hp = sha(password);                                   // SHA256(password)
    const std::string hp_s(reinterpret_cast<const char*>(hp.data()), hp.size());
    const Bytes p_hash = sha2::pbkdf2(hp_s, salt.data(),
                                      static_cast<int>(salt.size()), iters, 32);
    Bytes colon_p; colon_p.push_back(':');
    colon_p.insert(colon_p.end(), p_hash.begin(), p_hash.end());
    return sha(concat(salt, sha(colon_p)));                           // SHA256(salt || SHA256(":"||p))
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

// M1 = SHA256( (H(N) xor H(pad(g))) || H(email_lc) || salt || pad(A) || pad(B) || K )
Bytes compute_M1(const Bytes& N_bytes, const Bytes& g_padded,
                 const std::string& email, const Bytes& salt,
                 const Bytes& A_pad, const Bytes& B_pad, const Bytes& K) {
    const Bytes HN = sha(N_bytes), Hg = sha(g_padded);
    Bytes xum(32);
    for (int i = 0; i < 32; ++i) xum[i] = HN[i] ^ Hg[i];
    const Bytes h_em = sha(lower(email));
    Bytes in;
    in.reserve(32 + 32 + salt.size() + N_LEN + N_LEN + 32);
    in.insert(in.end(), xum.begin(),   xum.end());
    in.insert(in.end(), h_em.begin(),  h_em.end());
    in.insert(in.end(), salt.begin(),  salt.end());
    in.insert(in.end(), A_pad.begin(), A_pad.end());
    in.insert(in.end(), B_pad.begin(), B_pad.end());
    in.insert(in.end(), K.begin(),     K.end());
    return sha(in);
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────

struct Client::Impl {
    Mpi   N, g, a, A;
    Bytes A_bytes;   // pad(A), 256
    Bytes K_;        // 32
    Bytes M1_;       // 32
};

Client::Client() : p(new Impl) {
    from_bin(p->N, SRP_N_2048, N_LEN);
    chk(mbedtls_mpi_lset(p->g.get(), 2), "g=2");
    uint8_t ab[32];
    secure_random(ab, sizeof ab);                 // private a (protect.h, global)
    from_bin(p->a, ab, sizeof ab);
    chk(mbedtls_mpi_exp_mod(p->A.get(), p->g.get(), p->a.get(), p->N.get(), nullptr),
        "A = g^a mod N");
    p->A_bytes = to_padded(p->A, N_LEN);
}

Client::~Client() { delete p; }

const Bytes& Client::A()  const { return p->A_bytes; }
const Bytes& Client::K()  const { return p->K_;  }
const Bytes& Client::M1() const { return p->M1_; }

void Client::process_challenge(const std::string& email,
                               const std::string& password,
                               const Bytes&       salt,
                               const Bytes&       B_raw,
                               int                iters) {
    if (B_raw.empty() || salt.empty()) fail("empty salt or B");

    const Bytes N_bytes  = to_padded(p->N, N_LEN);
    const Bytes g_padded = to_padded(p->g, N_LEN);

    Mpi B; from_bin(B, B_raw);
    const Bytes B_padded = to_padded(B, N_LEN);

    // SRP-6a safety: abort if B mod N == 0.
    { Mpi t; chk(mbedtls_mpi_mod_mpi(t.get(), B.get(), p->N.get()), "B mod N");
      if (mbedtls_mpi_cmp_int(t.get(), 0) == 0) fail("B mod N == 0"); }

    Mpi k; { Bytes kb = sha(concat(N_bytes,  g_padded)); from_bin(k, kb); }
    Mpi u; { Bytes ub = sha(concat(p->A_bytes, B_padded)); from_bin(u, ub); }
    Mpi x; { Bytes xb = derive_x(password, salt, iters);  from_bin(x, xb); }

    // v = g^x ; kv = k*v mod N ; Bkv = (B - kv) mod N  (normalized to [0, N))
    Mpi gx; chk(mbedtls_mpi_exp_mod(gx.get(), p->g.get(), x.get(), p->N.get(), nullptr), "g^x");
    Mpi kv; chk(mbedtls_mpi_mul_mpi(kv.get(), k.get(), gx.get()),      "k*v");
            chk(mbedtls_mpi_mod_mpi(kv.get(), kv.get(), p->N.get()),   "kv mod N");
    Mpi Bkv; chk(mbedtls_mpi_sub_mpi(Bkv.get(), B.get(), kv.get()),    "B - kv");
             chk(mbedtls_mpi_mod_mpi(Bkv.get(), Bkv.get(), p->N.get()), "Bkv mod N");
             if (mbedtls_mpi_cmp_int(Bkv.get(), 0) < 0)
                 chk(mbedtls_mpi_add_mpi(Bkv.get(), Bkv.get(), p->N.get()), "Bkv + N");

    // exp = a + u*x
    Mpi ux; chk(mbedtls_mpi_mul_mpi(ux.get(), u.get(), x.get()),       "u*x");
    Mpi e;  chk(mbedtls_mpi_add_mpi(e.get(),  p->a.get(), ux.get()),   "a + u*x");

    // S = Bkv^e mod N ; K = SHA256(pad(S))
    Mpi S; chk(mbedtls_mpi_exp_mod(S.get(), Bkv.get(), e.get(), p->N.get(), nullptr), "S");
    p->K_  = sha(to_padded(S, N_LEN));
    p->M1_ = compute_M1(N_bytes, g_padded, email, salt, p->A_bytes, B_padded, p->K_);
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic self-test — fixed a/b/salt, must match srp_test.py byte-for-byte.
void selftest() {
    const std::string password = "testpassword123";
    const std::string email    = "test@icloud.com";
    const Bytes salt  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                         0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    const int   iters = 20000;
    const Bytes a_fix(32, 0x42);
    const Bytes b_fix(32, 0x43);

    auto hx = [](const Bytes& b, size_t n = 0) {
        static const char* d = "0123456789abcdef";
        std::string s; size_t c = n ? std::min(b.size(), n) : b.size();
        for (size_t i = 0; i < c; ++i) { s += d[b[i] >> 4]; s += d[b[i] & 15]; }
        return s;
    };

    Mpi N; from_bin(N, SRP_N_2048, N_LEN);
    Mpi g; chk(mbedtls_mpi_lset(g.get(), 2), "g=2");
    const Bytes N_bytes  = to_padded(N, N_LEN);
    const Bytes g_padded = to_padded(g, N_LEN);

    // Client A = g^a
    Mpi a; from_bin(a, a_fix);
    Mpi A; chk(mbedtls_mpi_exp_mod(A.get(), g.get(), a.get(), N.get(), nullptr), "A");
    const Bytes A_pad = to_padded(A, N_LEN);

    Mpi k; { Bytes kb = sha(concat(N_bytes, g_padded)); from_bin(k, kb); }
    Mpi x; { Bytes xb = derive_x(password, salt, iters); from_bin(x, xb); }

    // Server B = (k*v + g^b) mod N, v = g^x
    Mpi v;  chk(mbedtls_mpi_exp_mod(v.get(),  g.get(), x.get(),  N.get(), nullptr), "v");
    Mpi b;  from_bin(b, b_fix);
    Mpi gb; chk(mbedtls_mpi_exp_mod(gb.get(), g.get(), b.get(),  N.get(), nullptr), "g^b");
    Mpi kv; chk(mbedtls_mpi_mul_mpi(kv.get(), k.get(), v.get()),      "k*v");
            chk(mbedtls_mpi_mod_mpi(kv.get(), kv.get(), N.get()),     "kv mod N");
    Mpi B;  chk(mbedtls_mpi_add_mpi(B.get(), kv.get(), gb.get()),     "kv+g^b");
            chk(mbedtls_mpi_mod_mpi(B.get(), B.get(), N.get()),       "B mod N");
    const Bytes B_pad = to_padded(B, N_LEN);

    Mpi u; { Bytes ub = sha(concat(A_pad, B_pad)); from_bin(u, ub); }

    // S = (B - kv)^(a + u*x) mod N
    Mpi Bkv; chk(mbedtls_mpi_sub_mpi(Bkv.get(), B.get(), kv.get()),   "B-kv");
             chk(mbedtls_mpi_mod_mpi(Bkv.get(), Bkv.get(), N.get()),  "Bkv mod N");
             if (mbedtls_mpi_cmp_int(Bkv.get(), 0) < 0)
                 chk(mbedtls_mpi_add_mpi(Bkv.get(), Bkv.get(), N.get()), "Bkv+N");
    Mpi ux; chk(mbedtls_mpi_mul_mpi(ux.get(), u.get(), x.get()),      "u*x");
    Mpi e;  chk(mbedtls_mpi_add_mpi(e.get(), a.get(), ux.get()),      "a+ux");
    Mpi S;  chk(mbedtls_mpi_exp_mod(S.get(), Bkv.get(), e.get(), N.get(), nullptr), "S");
    const Bytes K  = sha(to_padded(S, N_LEN));
    const Bytes M1 = compute_M1(N_bytes, g_padded, email, salt, A_pad, B_pad, K);

    fprintf(stderr, "=== srp selftest (compare with srp_test.py) ===\n");
    fprintf(stderr, "A[0..7] : %s\n", hx(A_pad, 8).c_str());
    fprintf(stderr, "B[0..7] : %s\n", hx(B_pad, 8).c_str());
    fprintf(stderr, "K       : %s\n", hx(K).c_str());
    fprintf(stderr, "M1      : %s\n", hx(M1).c_str());
}

} // namespace srp
