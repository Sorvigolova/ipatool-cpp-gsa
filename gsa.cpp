// gsa.cpp — Apple Grand Slam Authentication client. SKELETON (not implemented).
//
// Handshake plan (GsService2, body wrapped in { Header:{Version}, Request:{...} }):
//   1. cpd = make_cpd(anisette)                       // anisette echoed into body
//   2. init:     Request { A2k, cpd, ps:[s2k,s2k_fo], u:email, o:"init" }
//               → Response { s(salt), B, i(iters), c }
//   3. srp::Client c; c.process_challenge(email, password, salt, B, iters)
//   4. complete: Request { M1:c.M1(), c, cpd, u:email, o:"complete" }
//               → Response { spd(enc), Status }
//   5. check_status(ec): -22421 → "Bad Apple ID or password"; -22020 → AuthCodeRequired
//   6. spd = aes::cbc_decrypt( sha2::hmac(K,"extra data key:"),
//                              sha2::hmac(K,"extra data iv:")[:16], spd_enc )
//   7. if spd["status-code"] == 409 → 2FA: read sm/adsid/GsIdmsToken;
//         authCode empty → throw AuthCodeRequired; else do_2fa_validate → re-run login
//   8. Result.pet = spd t/com.apple.gs.idms.pet/token  (verbatim, carries "PET")
//      Result.adsid = spd DsPrsId|adsid ; names fn/ln ; storeFront from headers
//
// Crypto all via sha2:: / aes:: / srp:: (mbedtls) + protect:: RNG — no OpenSSL.

#include "gsa.h"
#include "srp.h"
#include "plist.h"
#include "sha2.h"
#include "aes.h"

GsaClient::Result GsaClient::login(const std::string& /*email*/,
                                   const std::string& /*password*/,
                                   const AnisetteData& /*anisette*/,
                                   const std::string& /*authCode*/) {
    throw IpaError("GSA login: not implemented yet");
}
