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
#include <string>
#include <map>

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
// (gsService/validateCode) and the AppStore provisioning/postData paths. Best-
// effort: returns an empty map on any failure, and callers fall back to defaults.
std::map<std::string, std::string> gsa_fetch_bag(const HttpClient& http,
    const std::string& clientInfo, bool debug = false);

class GsaClient {
public:
    explicit GsaClient(const HttpClient& http, bool debug = false)
        : m_http(http), m_debug(debug) {}

    // Result of a successful GSA login. `pet` is the only field the store path
    // actually needs; the rest is useful context for logging / future use.
    struct Result {
        std::string pet;          // com.apple.gs.idms.pet token, verbatim
        std::string adsid;        // DsPrsId / adsid
        std::string gsIdmsToken;  // GsIdmsToken (X-Apple-Identity-Token source)
        std::string firstName;
        std::string lastName;
        std::string storeFront;   // if the server returned one
        std::string hbToken;      // X-Apple-HB-Token for the post-login postData heartbeat
                                  // (from complete's spd, refreshed from validate on 2FA)
    };

    // Full SRP-6a handshake.
    //   - throws AuthCodeRequired when 2FA is needed and authCode is empty
    //     (Apple has already pushed the code by then)
    //   - throws IpaError("Bad Apple ID or password") on GSA ec -22421
    // Call again with the 6-digit code to finish. Stateless: re-runs SRP after a
    // successful validate (the handshake is cheap), so the GUI can drive it as
    // two calls without holding server state between them.
    Result login(const std::string&  email,
                 const std::string&  password,
                 const AnisetteData& anisette,
                 const std::string&  authCode = "");

private:
    const HttpClient& m_http;
    bool              m_debug;

    // GSA config "bag": urls (and some cfgs) fetched once from the bootstrap
    // endpoint and cached. The bag is the source of truth for every GSA/Mid URL
    // (gsService, validateCode, midStart/FinishProvisioning, postData, …) — Apple
    // moves these, and not all share the gsa.apple.com host, so we read full URLs
    // by key instead of composing paths. Populated by lookup_bag() on first use.
    std::map<std::string, std::string> m_bag;

    // Fetch + cache the bag. MUST be a bare GET (UA only, NO anisette headers):
    // anisette provisioning needs the Mid* URLs that live in the bag, so the bag
    // cannot itself depend on anisette (chicken-and-egg). Best-effort — on failure
    // m_bag stays empty and endpoint() falls back to the hard-coded defaults.
    void lookup_bag(const AnisetteData& a);   // identity headers come from `a`

    // Full URL for a bag key, or `fallback` if the bag lacks it / wasn't fetched.
    std::string endpoint(const std::string& key, const std::string& fallback) const;
};
