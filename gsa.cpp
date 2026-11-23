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
#include "path_utf8.h"   // ipt::write_err_utf8 — UTF-8-safe --debug output
#include <map>
#include <string>
#include <sstream>
#include <ctime>
#include <cstdio>
#include <cstdint>

namespace {
using std::string;

// Bootstrap endpoint — the ONE URL that must stay hard-coded: the bag that
// supplies every other GSA/Mid URL is fetched from here, so it can't come from
// the bag itself. A bare GET (no anisette); see GsaClient::lookup_bag.
constexpr const char* GSA_LOOKUP   = "https://gsa.apple.com/grandslam/GsService2/lookup";
// GsService2 / bag-lookup User-Agent. GsService2 is an AuthKit/GSA endpoint —
// on macOS akd owns it — so for a coherent Mac machine (our anisette/provisioning
// already present as akd) these calls use the akd UA, not iTunes-Windows. The 2FA
// validate keeps "Xcode", matching its com.apple.gs.xcode.auth app-info.
constexpr const char* GSA_UA =
    "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0";

// plist.h has no Data getter — small local one.
Bytes dict_data(const PlistDict& d, const string& key) {
    auto it = d.find(key);
    if (it == d.end() || !it->second.isData()) return {};
    return it->second.data();
}

// --debug request/response traces (URL + headers + body), matching the auth
// flow's dumps. GSA bodies carry SRP proofs (A2k/M1), not the plaintext password,
// but the HEADERS do carry secrets — the identity token on requests; the PET
// (x-apple-pe-token), HB and session keys on the validate response — so header
// values are masked via ipt::mask_header_value. (The one-time 2FA security-code
// is deliberately left visible — it's consumed immediately and worthless in a log.)
void dbg_dump_req(const char* label, const char* method, const string& url,
                  const std::map<string, string>& headers, const string& body = "") {
    std::ostringstream o;
    o << "[gsa] -- " << label << " request --\n[gsa] " << method << " " << url
      << "\n[gsa] headers:\n";
    for (const auto& kv : headers)
        o << "  " << kv.first << ": " << ipt::mask_header_value(kv.first, kv.second) << "\n";
    if (!body.empty()) {
        // The init/complete body carries the Apple ID under <key>u</key> and the
        // serial under <key>X-Apple-I-SRL-NO</key>; the rest is SRP proof + device
        // anisette. Mask the e-mail and serial, show the rest.
        std::string shown = body;
        ipt::mask_plist_field(shown, "u");
        ipt::mask_plist_field(shown, "X-Apple-I-SRL-NO");
        o << "[gsa] body (" << body.size() << " bytes):\n" << shown << "\n";
    }
    ipt::write_err_utf8(o.str());
}

void dbg_dump_resp(const char* label, const HttpResponse& r) {
    std::ostringstream o;
    o << "[gsa] -- " << label << " response --\n[gsa] status: " << r.statusCode
      << "\n[gsa] headers:\n";
    for (const auto& kv : r.headers)
        o << "  " << kv.first << ": " << ipt::mask_header_value(kv.first, kv.second) << "\n";
    o << "[gsa] body (" << r.body.size() << " bytes):\n"
      << (r.body.empty() ? "<empty>" : r.body) << "\n";
    ipt::write_err_utf8(o.str());
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
// Identity is now coherently Mac/akd: capp is the Xcode auth widget and the
// GsService2 UA is akd (see GSA_UA), matching the akd anisette/provisioning and
// the "Xcode" 2FA validate.
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
    if (!a.deviceID.empty())   cpd["X-Mme-Device-Id"]   = PlistValue::makeString(a.deviceID);
    return cpd;
}

// Headers for GsService2 init/complete. The anisette fields (incl. the machine ID)
// live in cpd now; only client-info / device-id ride along as headers.
std::map<string, string> build_headers(const AnisetteData& a) {
    std::map<string, string> h = {
        {"Content-Type",    "text/x-xml-plist"},
        {"Accept",          "*/*"},
        {"User-Agent",      GSA_UA},
        {"Accept-Language", "en-US"},
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

// Response Status.ec check. -22421/-22406 = bad password, -20970 = unknown Apple ID,
// -22020 = needs 2FA.
void check_status(const PlistDict& d, const char* step) {
    const PlistDict* look = &d;
    PlistDict resp;
    if (d.count("Response") && d.at("Response").isDict()) { resp = d.at("Response").dictVal; look = &resp; }
    auto it = look->find("Status");
    if (it == look->end() || !it->second.isDict()) return;
    const PlistDict& st = it->second.dictVal;
    const int64_t ec = dict_int(st, "ec");
    if (ec == 0) return;
    // Wrong credentials — one clean message instead of the raw "GSA <step> error …":
    //   -22421 (init) / -22406 (complete) = wrong password,
    //   -20970                            = unknown Apple ID / bad account info.
    // Collapsing them also avoids revealing whether the email exists (anti-enumeration).
    if (ec == -22421 || ec == -22406 || ec == -20970)
        throw IpaError("Incorrect Apple ID or password");
    if (ec == -22020) throw AuthCodeRequired();
    throw IpaError(string("GSA ") + step + " error " + std::to_string(ec)
                   + ": " + dict_str(st, "em"));
}

// 2FA validate: GET GsService2/validate with security-code. Apple returns HTTP
// 200 even on error, so the body's ec must be checked.
bool do_2fa_validate(const HttpClient& http, bool dbg, const string& validateUrl,
                     const string& dsid, const string& idms,
                     const string& code, const AnisetteData& a,
                     string& outPet) {
    outPet.clear();
    auto hdrs = build_2fa_headers(a, dsid, idms);
    hdrs["security-code"] = code;
    if (dbg) dbg_dump_req("GSA 2fa validate", "GET", validateUrl, hdrs);
    const HttpResponse r = http.get(validateUrl, hdrs);
    if (dbg) dbg_dump_resp("GSA 2fa validate", r);
    if (r.statusCode != 200) return false;
    if (!r.body.empty()) {
        try {
            const PlistDict rd = decode_plist(r.body);
            if (dict_int(rd, "ec") != 0) return false;   // -21669 = wrong code
        } catch (...) {}
    }
    // Apple returns the fresh token set in the validate response headers once the
    // code checks out. x-apple-pe-token is base64("com.apple.gs.idms.pet:" + token);
    // the token after the tag is the very same opaque PET a second SRP's spd would
    // carry (the spd's `t` dict is just the parsed form of these headers). Harvest
    // it so the caller can skip the re-authenticate entirely.
    auto it = r.headers.find("x-apple-pe-token");
    if (it != r.headers.end() && !it->second.empty()) {
        const std::vector<uint8_t> dec = base64_decode(it->second);
        const std::string s(dec.begin(), dec.end());
        static const std::string pfx = "com.apple.gs.idms.pet:";
        if (s.rfind(pfx, 0) == 0) outPet = s.substr(pfx.size());
    }
    return true;
}

// Trigger the 2FA push to the account's trusted devices. GSA does NOT push
// automatically on the complete 409 — pypush shows an explicit GET to
// /auth/verify/trusteddevice (same Xcode identity headers as validate). The
// response is just an HTML form; the side effect — the code appearing on the
// devices — is the point, so the body is ignored.
void trigger_trusted_device(const HttpClient& http, bool dbg, const string& url,
                            const string& dsid, const string& idms, const AnisetteData& a) {
    auto hdrs = build_2fa_headers(a, dsid, idms);
    if (dbg) dbg_dump_req("GSA trigger 2FA (trusteddevice)", "GET", url, hdrs);
    const HttpResponse r = http.get(url, hdrs);
    // The response is an HTML verification page (with embedded JS) that we never
    // parse — only the GET firing matters. Dumping it floods the console with
    // unreadable markup, so log just status + size, not the body.
    if (dbg)
        ipt::write_err_utf8("[gsa] trigger 2FA (trusteddevice): HTTP " +
                            std::to_string(r.statusCode) + " (" +
                            std::to_string(r.body.size()) + " bytes HTML, not shown)\n");
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

// Bare GET of the GSA bag — UA only, NO anisette (see header). On failure the
// returned map is empty; login() then throws (no hard-coded fallbacks).
std::map<std::string, std::string> gsa_fetch_bag(const HttpClient& http,
    const std::string& clientInfo, bool debug) {
    std::map<std::string, std::string> bag;
    std::map<string, string> h = {
        {"User-Agent", GSA_UA},
        {"Accept",     "*/*"},
    };
    // Tested: client-info alone yields 200 (LU / Device-Id are not required, and
    // no anisette OTP is involved — the machine need not be provisioned).
    if (!clientInfo.empty()) h["X-MMe-Client-Info"] = clientInfo;
    if (debug) dbg_dump_req("GSA bag lookup", "GET", GSA_LOOKUP, h);
    HttpResponse r;
    try { r = http.get(GSA_LOOKUP, h); }
    catch (...) { if (debug) fprintf(stderr, "[gsa] bag lookup: request failed\n"); return bag; }
    if (r.statusCode != 200 || r.body.empty()) {
        if (debug) fprintf(stderr, "[gsa] bag lookup: HTTP %d (%zu B)\n", r.statusCode, r.body.size());
        return bag;
    }
    try {
        const PlistDict root = response_of(decode_plist(r.body));
        const PlistDict urls = dict_dict(root, "urls");
        for (const auto& kv : urls)
            if (kv.second.isString() && !kv.second.str().empty())
                bag[kv.first] = kv.second.str();
    } catch (...) {
        if (debug) fprintf(stderr, "[gsa] bag lookup: parse failed\n");
        bag.clear();
        return bag;
    }
    // Compact summary (like the AppStore native-bag debug) instead of the ~21 KB body.
    if (debug) {
        auto clip = [](const std::string& s) {
            return s.size() > 110 ? s.substr(0, 110) + "…" : s;
        };
        std::string rep = "bag lookup: HTTP " + std::to_string(r.statusCode) + ", " +
                          std::to_string(r.body.size()) + " B, " +
                          std::to_string(bag.size()) + " urls";
        for (const char* k : { "gsService", "validateCode", "trustedDeviceSecondaryAuth",
                               "midStartProvisioning", "midFinishProvisioning" }) {
            auto it = bag.find(k);
            rep += "\n        " + std::string(k) + " = "
                 + (it == bag.end() ? "<absent>" : clip(it->second));
        }
        ipt::write_err_utf8("[gsa] " + rep + "\n");
    }
    return bag;
}

void GsaClient::lookup_bag(const AnisetteData& a) {
    if (m_bag.empty())
        m_bag = gsa_fetch_bag(m_http, a.clientInfo, m_debug);
}

std::string GsaClient::endpoint(const std::string& key) const {
    auto it = m_bag.find(key);
    if (it == m_bag.end() || it->second.empty())
        throw IpaError("GSA bag has no URL for '" + key + "'");
    return it->second;
}

// ─────────────────────────────────────────────────────────────────────────────

GsaClient::Result GsaClient::login(const std::string&  email,
                                   const std::string&  password,
                                   const AnisetteData& anisette,
                                   const std::string&  authCode,
                                   const CodeProvider& getCode) {
    AnisetteData ani = anisette;
    if (ani.clientTime.empty()) ani.clientTime = iso8601_now();
    const PlistDict cpd  = make_cpd(ani);
    const auto      hdrs = build_headers(ani);

    // Resolve every endpoint from the bag (bootstrap GET) — no fallbacks. If the
    // bag didn't load, fail loudly rather than POST to a stale hard-coded URL.
    lookup_bag(ani);
    if (m_bag.empty()) throw IpaError("GSA bag lookup failed — cannot resolve endpoints");
    const string gsSvc    = endpoint("gsService");
    const string valUrl   = endpoint("validateCode");
    const string trustUrl = endpoint("trustedDeviceSecondaryAuth");

    // ── init ──────────────────────────────────────────────────────────────
    srp::Client cli;                       // random a, computes A
    PlistDict ri;
    ri["A2k"] = PlistValue::makeData(cli.A());
    ri["cpd"] = PlistValue::makeDict(cpd);
    ri["ps"]  = PlistValue::makeArray({ PlistValue::makeString("s2k"),
                                        PlistValue::makeString("s2k_fo") });
    ri["u"]   = PlistValue::makeString(email);
    ri["o"]   = PlistValue::makeString("init");

    const string initBody = encode_plist_xml(wrap_request(ri));
    if (m_debug) dbg_dump_req("GSA init", "POST", gsSvc, hdrs, initBody);
    const HttpResponse r1 = m_http.post(gsSvc, initBody, hdrs);
    if (m_debug) dbg_dump_resp("GSA init", r1);
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

    const string completeBody = encode_plist_xml(wrap_request(rc));
    if (m_debug) dbg_dump_req("GSA complete", "POST", gsSvc, hdrs, completeBody);
    const HttpResponse r2 = m_http.post(gsSvc, completeBody, hdrs);
    if (m_debug) dbg_dump_resp("GSA complete", r2);
    if (r2.statusCode != 200) throw IpaError("GSA complete: HTTP " + std::to_string(r2.statusCode));
    const PlistDict d2o = decode_plist(r2.body);
    check_status(d2o, "complete");
    const PlistDict d2 = response_of(d2o);

    // TwoFactor/TwoStep/Allow all fall through to the spd 409 handling below
    // (that's where the push is triggered); only a genuinely bad Result stops here.
    const string result = dict_str(d2, "Result");
    if (!result.empty() && result != "Allow"
        && result != "TwoFactorAuthentication" && result != "TwoStepVerification") {
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
    // The decrypted spd holds the PET/HB tokens plus account PII (name, phone, …),
    // so never dump its body — just confirm the decrypt and the auth status-code.
    if (m_debug)
        fprintf(stderr, "[gsa] spd decrypted (%zu bytes), status-code=%lld\n",
                spd_plain.size(), static_cast<long long>(dict_int(spd, "status-code")));

    // ── 2FA (status-code 409 inside spd) ───────────────────────────────────
    if (dict_int(spd, "status-code") == 409) {
        if (authCode == "__2fa_done__")
            throw IpaError("GSA 2FA: still 409 after validation");
        const string dsid = dict_str(spd, "adsid");
        const string tok  = dict_str(spd, "GsIdmsToken");

        // The code to validate. A caller-supplied authCode (e.g. --auth-code, or a
        // GUI using the two-call contract) is used verbatim and skips the push —
        // it was obtained out-of-band. Otherwise we must trigger Apple's push here,
        // since nothing arrives without the explicit /auth/verify/trusteddevice GET.
        string code = authCode;
        if (code.empty()) {
            trigger_trusted_device(m_http, m_debug, trustUrl, dsid, tok, ani);
            // Single-session path: ask for the code now and validate against THIS
            // handshake's dsid/token — no second init/complete before validate.
            if (getCode) code = getCode();
            // No provider (or the user aborted): fall back to the two-call contract.
            if (code.empty()) throw AuthCodeRequired();
        }

        string petFromValidate;
        if (!do_2fa_validate(m_http, m_debug, valUrl, dsid, tok, code, ani, petFromValidate))
            throw IpaError("Incorrect verification code");   // GSA validate ec -21669

        // Fast path: the validate response already handed us the PET (x-apple-pe-token),
        // so there is no need to re-run SRP — the whole 2FA login is one handshake.
        if (!petFromValidate.empty()) {
            if (m_debug)
                ipt::write_err_utf8("[gsa] PET harvested from validate response "
                                    "(skipping re-auth)\n");
            Result res;
            res.adsid       = dsid;
            res.gsIdmsToken = tok;
            res.pet.set(petFromValidate);
            return res;
        }
        // Fallback: no pe-token header (older edge?) — device is trusted, so re-auth
        // once to mint the PET the classic way.
        return login(email, password, anisette, "__2fa_done__");
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

    // PET lives in spd's "t" dict: com.apple.gs.idms.pet/token (~5 min; the native
    // authenticate password, already carrying Apple's "PET" tag).
    {
        auto t = spd.find("t");
        if (t != spd.end() && t->second.isDict()) {
            auto p = t->second.dictVal.find("com.apple.gs.idms.pet");
            if (p != t->second.dictVal.end() && p->second.isDict())
                res.pet.set(dict_str(p->second.dictVal, "token"));
        }
    }
    if (res.pet.empty()) throw IpaError("GSA: PET missing from spd");

    for (auto& hk : {"x-apple-store-front", "x-apple-storefront"}) {
        auto it = r2.headers.find(hk);
        if (it != r2.headers.end() && !it->second.empty()) { res.storeFront = it->second; break; }
    }

    if (m_debug)
        fprintf(stderr, "[gsa] login ok: adsid=%s pet=<%zu bytes, hidden>\n",
                res.adsid.c_str(), res.pet.get().size());
    return res;
}
