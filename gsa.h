#pragma once
// gsa.h — Apple Grand Slam Authentication (GSA) client.
//
// Two-step SRP-6a handshake against
//   https://gsa.apple.com/grandslam/GsService2
// returning a short-lived PET (password-equivalent token). The caller feeds the
// PET verbatim as the `password` of the iTunes native authenticate to obtain the
// store X-Token — the PET already carries Apple's trailing "PET" tag, so it is
// passed through unchanged (no concatenation, no re-encoding).
//
// Anisette is produced LOCALLY from the emulated CoreADI (AppStore::gsa_anisette);
// this client never runs an external exe or a public anisette server. It composes
// HttpClient as its transport — the embedded Apple CA bundle and cookies live on
// that HttpClient, so GsaClient stays pure protocol (SRP + GsService2 plist).

#include "http_client.h"
#include "ipatool.h"       // IpaError, AuthCodeRequired
#include "protect.h"       // SecureString (PET encrypted in memory)
#include <string>
#include <map>
#include <functional>

// Anisette headers for the GSA / MidService flow (X-Apple-I-MD family).
// Filled by AppStore::gsa_anisette() from AdiRequestOTP(gsaMachineDSID).
struct AnisetteData {
    std::string otp;            // X-Apple-I-MD        (base64 OTP)
    std::string machineID;      // X-Apple-I-MD-M      (base64 Machine ID)
    std::string localUserUUID;  // X-Apple-I-MD-LU     (hex SHA-256 of identifier)
    std::string routingInfo;    // X-Apple-I-MD-RINFO  (decimal)
    std::string deviceID;       // X-Mme-Device-Id
    std::string clientInfo;     // X-MMe-Client-Info
    std::string serialNo;       // X-Apple-I-SRL-NO
    std::string clientTime;     // X-Apple-I-Client-Time (ISO-8601 UTC; auto if empty)
    std::string locale   = "en_US";
    std::string timezone = "UTC";

    bool is_complete() const { return !otp.empty() && !machineID.empty(); }
};

// Fetch + parse the GSA "bag" (its `urls` map). Bootstrap GET that needs only the
// client-info header (tested: X-MMe-Client-Info alone gives 200; LU / Device-Id
// are not required and no anisette OTP is involved — the bag can't depend on being
// provisioned, since the provisioning URLs live in it). Shared by GsaClient
// (gsService/validateCode) and the AppStore provisioning (Mid*) paths. Best-
// effort: returns an empty map on any failure, and callers then throw (no fallbacks).
std::map<std::string, std::string> gsa_fetch_bag(const HttpClient& http,
    const std::string& clientInfo, bool debug = false);

class GsaClient {
public:
    explicit GsaClient(const HttpClient& http, bool debug = false)
        : m_http(http), m_debug(debug) {}

    // Prime the bag cache from a caller that already fetched it once (e.g. AppStore
    // reusing its cached bag across login_gsa calls), so lookup_bag() does no GET.
    void set_bag(std::map<std::string, std::string> bag) { m_bag = std::move(bag); }

    // Supplies the 6-digit 2FA code on demand. Invoked (once) right after Apple's
    // push has been triggered, from inside login(), so the whole 2FA exchange —
    // init/complete → 409 → push → code → validate → PET — resolves in a single
    // call instead of throwing and re-running SRP from scratch. Return the code, or
    // "" to abort (login() then throws AuthCodeRequired as before). The CLI wires
    // std::getline here; a GUI marshals its dialog onto the login thread.
    using CodeProvider = std::function<std::string()>;

    // Result of a successful GSA login. `pet` is the only field the store path
    // actually needs; the rest is useful context for logging / future use.
    struct Result {
        SecureString pet;         // com.apple.gs.idms.pet token, AES-GCM in memory
        std::string adsid;        // DsPrsId / adsid
        std::string gsIdmsToken;  // GsIdmsToken (X-Apple-Identity-Token source)
        std::string firstName;
        std::string lastName;
        std::string storeFront;   // if the server returned one
    };

    // Full SRP-6a handshake.
    //   - throws IpaError("Incorrect Apple ID or password") on GSA ec -22421/-22406
    // 2FA resolution, in order of what the caller supplies:
    //   1. authCode non-empty  → validate it directly (no push; the code was already
    //      obtained out-of-band, e.g. --auth-code or a prior run's push).
    //   2. getCode provided    → trigger the push, call getCode() for the code, then
    //      go straight to validate using this handshake's dsid/GsIdmsToken — no
    //      redundant init/complete. Validate returns the fresh token set in its
    //      response headers, so the PET is harvested straight from x-apple-pe-token:
    //      the whole 2FA login is ONE SRP round. (If that header is ever absent, it
    //      falls back to a second trusted authenticate to mint the PET.)
    //   3. neither             → trigger the push and throw AuthCodeRequired, for the
    //      legacy two-call contract (caller re-invokes login() with the code).
    Result login(const std::string&  email,
                 const std::string&  password,
                 const AnisetteData& anisette,
                 const std::string&  authCode = "",
                 const CodeProvider& getCode  = nullptr);

private:
    const HttpClient& m_http;
    bool              m_debug;

    // GSA config "bag": urls (and some cfgs) fetched once from the bootstrap
    // endpoint and cached. The bag is the source of truth for every GSA/Mid URL
    // (gsService, validateCode, midStart/FinishProvisioning, …) — Apple
    // moves these, and not all share the gsa.apple.com host, so we read full URLs
    // by key instead of composing paths. Populated by lookup_bag() on first use.
    std::map<std::string, std::string> m_bag;

    // Fetch + cache the bag. MUST be a bare GET (UA only, NO anisette headers):
    // anisette provisioning needs the Mid* URLs that live in the bag, so the bag
    // cannot itself depend on anisette (chicken-and-egg). If the fetch fails the
    // bag stays empty and endpoint() throws — there are no hard-coded fallbacks.
    void lookup_bag(const AnisetteData& a);   // identity headers come from `a`

    // Full URL for a bag key. Throws IpaError if the bag lacks it (or wasn't
    // fetched) — the bag is the single source of truth, no fallback.
    std::string endpoint(const std::string& key) const;
};
