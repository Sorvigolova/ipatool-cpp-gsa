// gsa.cpp — Apple Grand Slam Authentication (GSA) client.
//
// Two-step SRP-6a handshake against gsa.apple.com/grandslam/GsService2:
//   init     → { s(salt), B, i(iters), c }
//   complete → { spd (AES-256-CBC, key/iv from the SRP session key K), Status }
// spd carries the PET (com.apple.gs.idms.pet) that the caller passes verbatim as
// the iTunes native authenticate `password`.
//
// Ported from the validated OpenSSL reference onto the project's mbedtls crypto
// (srp::, sha2::, aes::) and plist helpers — no OpenSSL. 2FA never reads stdin:
// it throws AuthCodeRequired so the GUI can supply the code and call again.

#include "gsa.h"
#include "srp.h"
#include "plist.h"
#include "sha2.h"
#include "aes.h"
#include "protect.h"     // secure_random (global)
#include <map>
#include <string>
#include <ctime>
#include <cstdio>
#include <cstdint>

namespace {
using std::string;

// Bootstrap endpoint — the ONE URL that must stay hard-coded: the bag that
// supplies every other GSA/Mid URL is fetched from here, so it can't come from
// the bag itself. A bare GET (no anisette); see GsaClient::lookup_bag.
constexpr const char* GSA_LOOKUP   = "https://gsa.apple.com/grandslam/GsService2/lookup";
// Fallbacks used only when the bag fetch failed or lacks the key.
constexpr const char* GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2";
constexpr const char* GSA_VALIDATE = "https://gsa.apple.com/grandslam/GsService2/validate";
constexpr const char* ITUNES_UA =
    "iTunes/12.11.3 (Windows; Microsoft Windows 10 x64 Professional Edition "
    "(Build 19041); x64) AppleWebKit/7611.3.10.1.16";

// plist.h has no Data getter — small local one.
Bytes dict_data(const PlistDict& d, const string& key) {
    auto it = d.find(key);
    if (it == d.end() || !it->second.isData()) return {};
    return it->second.data();
}

string iso8601_now() {
    time_t now = std::time(nullptr);
    struct tm t{};
#ifdef _WIN32
    gmtime_s(&t, &now);
#else
    gmtime_r(&now, &t);
#endif
    char buf[32];
    snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    return buf;
}

string gen_uuid() {
    uint8_t b[16];
    secure_random(b, sizeof b);
    b[6] = (b[6] & 0x0F) | 0x40;   // version 4
    b[8] = (b[8] & 0x3F) | 0x80;   // variant
    char buf[37];
    snprintf(buf, sizeof buf,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
             b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    return buf;
}

string country_of(const string& locale) {   // "en_US"/"en-US" → "US"
    for (char sep : {'_', '-'}) {
        size_t p = locale.find(sep);
        if (p != string::npos && p + 1 < locale.size()) return locale.substr(p + 1);
    }
    return "US";
}

// cpd — anisette data echoed inside the plist body. GSA silently rejects
// (HTTP 200, empty body) when cpd is absent even if the headers are correct.
// NOTE(identity): capp is still the Xcode auth widget (AltStore lineage) while
// the UA is iTunes-Windows. Coherent-identity cleanup is a follow-up; this is
// the proven-working combination, so the port keeps it as-is.
PlistDict make_cpd(const AnisetteData& a) {
    PlistDict cpd;
    cpd["bootstrap"] = PlistValue::makeBool(true);
    cpd["icscrec"]   = PlistValue::makeBool(true);
    cpd["pbe"]       = PlistValue::makeBool(false);
    cpd["prkgen"]    = PlistValue::makeBool(true);
    cpd["svct"]      = PlistValue::makeString("iCloud");
    cpd["X-Apple-I-Device-Configuration-Mode"] = PlistValue::makeString("Default");
    cpd["X-Apple-I-ReAuth"]       = PlistValue::makeBool(false);
    cpd["X-Apple-I-Request-UUID"] = PlistValue::makeString(gen_uuid());
    cpd["loc"]  = PlistValue::makeString(a.locale);
    cpd["cou"]  = PlistValue::makeString(country_of(a.locale));
    cpd["dc"]   = PlistValue::makeString("PC");
    cpd["dec"]  = PlistValue::makeBool(true);
    cpd["capp"] = PlistValue::makeString("com.apple.gs.xcode.auth");
    cpd["ptkn"] = PlistValue::makeString("");
    cpd["prtn"] = PlistValue::makeString("R1");
    cpd["at"]   = PlistValue::makeString("");
    cpd["X-Apple-I-MD"]          = PlistValue::makeString(a.otp);
    cpd["X-Apple-I-MD-M"]        = PlistValue::makeString(a.machineID);
    cpd["X-Apple-I-MD-LU"]       = PlistValue::makeString(a.localUserUUID);
    int64_t rinfo = 0;
    if (!a.routingInfo.empty()) { try { rinfo = std::stoll(a.routingInfo); } catch (...) {} }
    cpd["X-Apple-I-MD-RINFO"]    = PlistValue::makeInt(rinfo);
    cpd["X-Apple-I-SRL-NO"]      = PlistValue::makeString(a.serialNo);
    cpd["X-Apple-I-Client-Time"] = PlistValue::makeString(a.clientTime);
    cpd["X-Apple-Locale"]        = PlistValue::makeString(a.locale);
    cpd["X-Apple-I-TimeZone"]    = PlistValue::makeString(a.timezone);
    if (!a.clientInfo.empty()) cpd["X-MMe-Client-Info"] = PlistValue::makeString(a.clientInfo);
    if (!a.deviceID.empty())   cpd["X-Mme-Device-Id"]   = PlistValue::makeString(a.deviceID);
    return cpd;
}

// Headers for GsService2 init/complete. Most anisette fields live in cpd now;
// only the machine ID (+ client-info / device-id) stay in headers.
std::map<string, string> build_headers(const AnisetteData& a) {
    std::map<string, string> h = {
        {"Content-Type",    "text/x-xml-plist"},
        {"Accept",          "*/*"},
        {"User-Agent",      ITUNES_UA},
        {"Accept-Language", "en-US,en;q=0.9"},
        {"X-Apple-I-MD-M",  a.machineID},
    };
    if (!a.clientInfo.empty()) h["X-MMe-Client-Info"] = a.clientInfo;
    if (!a.deviceID.empty())   h["X-Mme-Device-Id"]   = a.deviceID;
    return h;
}

// Headers for the 2FA validate GET. identity = base64(dsid:GsIdmsToken).
std::map<string, string> build_2fa_headers(const AnisetteData& a,
                                           const string& dsid, const string& idms) {
    const string raw = dsid + ":" + idms;
    std::map<string, string> h;
    h["Accept"]                 = "text/x-xml-plist";
    h["Content-Type"]           = "text/x-xml-plist";
    h["User-Agent"]             = "Xcode";
    h["Accept-Language"]        = "en-us";
    h["X-Apple-App-Info"]       = "com.apple.gs.xcode.auth";
    h["X-Xcode-Version"]        = "11.2 (11B41)";
    h["X-Apple-Identity-Token"] = base64_encode(
        reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    h["X-Apple-I-MD"]           = a.otp;
    h["X-Apple-I-MD-M"]         = a.machineID;
    h["X-Apple-I-MD-LU"]        = a.localUserUUID;
    if (!a.routingInfo.empty()) h["X-Apple-I-MD-RINFO"] = a.routingInfo;
    h["X-Apple-I-Client-Time"]  = a.clientTime;
    h["X-Apple-Locale"]         = a.locale;
    h["X-Apple-I-TimeZone"]     = a.timezone;
    if (!a.clientInfo.empty())  h["X-MMe-Client-Info"]  = a.clientInfo;
    if (!a.deviceID.empty())    h["X-Mme-Device-Id"]    = a.deviceID;
    return h;
}

// Response Status.ec check. -22421 = bad password; -22020 = needs 2FA.
void check_status(const PlistDict& d, const char* step) {
    const PlistDict* look = &d;
    PlistDict resp;
    if (d.count("Response") && d.at("Response").isDict()) { resp = d.at("Response").dictVal; look = &resp; }
    auto it = look->find("Status");
    if (it == look->end() || !it->second.isDict()) return;
    const PlistDict& st = it->second.dictVal;
    const int64_t ec = dict_int(st, "ec");
    if (ec == 0) return;
    if (ec == -22421) throw IpaError("Bad Apple ID or password");
    if (ec == -22020) throw AuthCodeRequired();
    throw IpaError(string("GSA ") + step + " error " + std::to_string(ec)
                   + ": " + dict_str(st, "em"));
}

// 2FA validate: GET GsService2/validate with security-code. Apple returns HTTP
// 200 even on error, so the body's ec must be checked.
bool do_2fa_validate(const HttpClient& http, bool dbg, const string& validateUrl,
                     const string& dsid, const string& idms,
                     const string& code, const AnisetteData& a) {
    auto hdrs = build_2fa_headers(a, dsid, idms);
    hdrs["security-code"] = code;
    const HttpResponse r = http.get(validateUrl, hdrs);
    if (dbg) fprintf(stderr, "[gsa] 2fa validate status=%d\n", r.statusCode);
    if (r.statusCode != 200) return false;
    if (!r.body.empty()) {
        try {
            const PlistDict rd = decode_plist(r.body);
            if (dict_int(rd, "ec") != 0) return false;
        } catch (...) {}
    }
    return true;
}

PlistDict wrap_request(const PlistDict& req) {
    PlistDict hdr;  hdr["Version"] = PlistValue::makeString("1.0.1");
    PlistDict w;    w["Header"]  = PlistValue::makeDict(hdr);
                    w["Request"] = PlistValue::makeDict(req);
    return w;
}
PlistDict response_of(const PlistDict& outer) {
    return outer.count("Response") ? dict_dict(outer, "Response") : outer;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────

// Bare GET of the GSA bag — UA only, NO anisette (see header). Best-effort:
// any failure leaves m_bag empty and endpoint() falls back to the defaults.
void GsaClient::lookup_bag() {
    if (!m_bag.empty()) return;
    std::map<string, string> h = {
        {"User-Agent", ITUNES_UA},
        {"Accept",     "*/*"},
    };
    HttpResponse r;
    try { r = m_http.get(GSA_LOOKUP, h); }
    catch (...) { if (m_debug) fprintf(stderr, "[gsa] bag lookup: request failed\n"); return; }
    if (r.statusCode != 200 || r.body.empty()) {
        if (m_debug) fprintf(stderr, "[gsa] bag lookup: HTTP %d\n", r.statusCode);
        return;
    }
    try {
        const PlistDict root = response_of(decode_plist(r.body));
        const PlistDict urls = dict_dict(root, "urls");
        for (const auto& kv : urls)
            if (kv.second.isString() && !kv.second.str().empty())
                m_bag[kv.first] = kv.second.str();
    } catch (...) {
        if (m_debug) fprintf(stderr, "[gsa] bag lookup: parse failed\n");
        m_bag.clear();
        return;
    }
    if (m_debug) fprintf(stderr, "[gsa] bag: %zu urls cached\n", m_bag.size());
}

std::string GsaClient::endpoint(const std::string& key, const std::string& fallback) const {
    auto it = m_bag.find(key);
    return (it != m_bag.end() && !it->second.empty()) ? it->second : fallback;
}

// ─────────────────────────────────────────────────────────────────────────────

GsaClient::Result GsaClient::login(const std::string&  email,
                                   const std::string&  password,
                                   const AnisetteData& anisette,
                                   const std::string&  authCode) {
    AnisetteData ani = anisette;
    if (ani.clientTime.empty()) ani.clientTime = iso8601_now();
    const PlistDict cpd  = make_cpd(ani);
    const auto      hdrs = build_headers(ani);

    // Resolve endpoints from the bag (bootstrap GET), with hard-coded fallbacks.
    lookup_bag();
    const string gsSvc  = endpoint("gsService",    GSA_ENDPOINT);
    const string valUrl = endpoint("validateCode", GSA_VALIDATE);

    // ── init ──────────────────────────────────────────────────────────────
    srp::Client cli;                       // random a, computes A
    PlistDict ri;
    ri["A2k"] = PlistValue::makeData(cli.A());
    ri["cpd"] = PlistValue::makeDict(cpd);
    ri["ps"]  = PlistValue::makeArray({ PlistValue::makeString("s2k"),
                                        PlistValue::makeString("s2k_fo") });
    ri["u"]   = PlistValue::makeString(email);
    ri["o"]   = PlistValue::makeString("init");

    const HttpResponse r1 = m_http.post(gsSvc, encode_plist_xml(wrap_request(ri)), hdrs);
    if (r1.statusCode != 200) throw IpaError("GSA init: HTTP " + std::to_string(r1.statusCode));
    const PlistDict d1o = decode_plist(r1.body);
    check_status(d1o, "init");
    const PlistDict d1 = response_of(d1o);

    const Bytes  salt  = dict_data(d1, "s");
    const Bytes  B_raw = dict_data(d1, "B");
    const string sc1   = dict_str(d1, "c");
    int iters = static_cast<int>(dict_int(d1, "i"));
    if (iters <= 0) iters = 20000;
    if (B_raw.empty() || salt.empty() || sc1.empty())
        throw IpaError("GSA init: incomplete server response");

    // ── SRP ───────────────────────────────────────────────────────────────
    cli.process_challenge(email, password, salt, B_raw, iters);

    // ── complete ──────────────────────────────────────────────────────────
    PlistDict rc;
    rc["M1"]  = PlistValue::makeData(cli.M1());
    rc["c"]   = PlistValue::makeString(sc1);
    rc["cpd"] = PlistValue::makeDict(cpd);
    rc["o"]   = PlistValue::makeString("complete");
    rc["u"]   = PlistValue::makeString(email);

    const HttpResponse r2 = m_http.post(gsSvc, encode_plist_xml(wrap_request(rc)), hdrs);
    if (r2.statusCode != 200) throw IpaError("GSA complete: HTTP " + std::to_string(r2.statusCode));
    const PlistDict d2o = decode_plist(r2.body);
    check_status(d2o, "complete");
    const PlistDict d2 = response_of(d2o);

    const string result = dict_str(d2, "Result");
    if (result == "TwoFactorAuthentication" || result == "TwoStepVerification") {
        if (authCode.empty()) throw AuthCodeRequired();
    } else if (!result.empty() && result != "Allow") {
        if (result == "RepairRequired")
            throw IpaError("Apple ID needs repair at appleid.apple.com");
        throw IpaError("GSA: unexpected Result = " + result);
    }

    // ── spd decrypt (AES-256-CBC, key/iv from K) ───────────────────────────
    const Bytes spd_enc = dict_data(d2, "spd");
    if (spd_enc.empty()) throw IpaError("GSA: spd missing — SRP key mismatch?");
    Bytes dk  = sha2::hmac(cli.K(), std::string("extra data key:"));
    Bytes div = sha2::hmac(cli.K(), std::string("extra data iv:"));
    div.resize(16);
    const Bytes spd_plain = aes::cbc_decrypt(dk, div, spd_enc);
    const PlistDict spd = decode_plist(std::string(spd_plain.begin(), spd_plain.end()));

    // ── 2FA (status-code 409 inside spd) ───────────────────────────────────
    if (dict_int(spd, "status-code") == 409) {
        if (authCode == "__2fa_done__")
            throw IpaError("GSA 2FA: still 409 after validation");
        const string dsid = dict_str(spd, "adsid");
        const string tok  = dict_str(spd, "GsIdmsToken");
        if (authCode.empty()) throw AuthCodeRequired();   // GUI supplies the code
        if (!do_2fa_validate(m_http, m_debug, valUrl, dsid, tok, authCode, ani))
            throw IpaError("GSA 2FA: invalid code");
        return login(email, password, anisette, "__2fa_done__");  // fresh SRP, now trusted
    }

    // ── build Result ───────────────────────────────────────────────────────
    Result res;
    res.adsid = dict_str(spd, "adsid");
    if (res.adsid.empty()) res.adsid = dict_str(spd, "DsPrsId");

    res.gsIdmsToken = dict_str(spd, "GsIdmsToken");
    if (res.gsIdmsToken.empty()) res.gsIdmsToken = dict_str(spd, "idms_token");
    if (res.gsIdmsToken.empty()) res.gsIdmsToken = dict_str(spd, "acntToken");

    res.firstName = dict_str(spd, "fn");
    res.lastName  = dict_str(spd, "ln");
    if (res.firstName.empty() && res.lastName.empty()) {
        auto ai = spd.find("acctInfo");
        if (ai != spd.end() && ai->second.isDict()) {
            res.firstName = dict_str(ai->second.dictVal, "firstName");
            res.lastName  = dict_str(ai->second.dictVal, "lastName");
        }
    }

    // PET: spd t/com.apple.gs.idms.pet/token (already carries the "PET" tag).
    {
        auto t = spd.find("t");
        if (t != spd.end() && t->second.isDict()) {
            auto p = t->second.dictVal.find("com.apple.gs.idms.pet");
            if (p != t->second.dictVal.end() && p->second.isDict())
                res.pet = dict_str(p->second.dictVal, "token");
        }
    }
    if (res.pet.empty()) throw IpaError("GSA: PET missing from spd");

    for (auto& hk : {"x-apple-store-front", "x-apple-storefront"}) {
        auto it = r2.headers.find(hk);
        if (it != r2.headers.end() && !it->second.empty()) { res.storeFront = it->second; break; }
    }

    if (m_debug)
        fprintf(stderr, "[gsa] login ok: adsid=%s pet=%.16s...\n",
                res.adsid.c_str(), res.pet.c_str());
    return res;
}
