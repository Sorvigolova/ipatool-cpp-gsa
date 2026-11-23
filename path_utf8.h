#pragma once
// Cross-platform UTF-8 path handling.
//
// Inside the program every path is a UTF-8 std::string. On POSIX that is also
// the native filesystem encoding, so paths pass straight through. On Windows the
// narrow CRT (fopen, std::fstream built from a std::string, std::filesystem::path
// built from a std::string) interprets narrow paths in the *active ANSI code
// page*, not UTF-8 — so any non-ASCII path (e.g. Cyrillic "D:\Даунлоадер\...")
// fails to open. These helpers convert UTF-8 → UTF-16 and use the wide APIs.
//
//   ipt::fs_path(utf8)        → std::filesystem::path for fs:: ops and fstreams
//   ipt::fopen_utf8(path,mode)→ FILE* (uses _wfopen on Windows)
//   ipt::utf8_to_wide(utf8)   → std::wstring (Windows only; for minizip iowin32)

#include <string>
#include <filesystem>
#include <cstdio>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <io.h>      // _isatty / _fileno
#endif

namespace ipt {

// ── --debug secret masking ──────────────────────────────────────────────────
// Replace a secret with asterisks of EQUAL length, so a shared --debug log shows
// the real length instead of a misleading fixed count. Empty stays empty.
inline std::string mask_stars(const std::string& s) {
    return std::string(s.size(), '*');
}

// Case-insensitive test: is this HTTP header a credential / account identifier
// that must be masked in --debug dumps? The remaining device-identity anisette
// headers (X-Apple-I-MD-M / -LU / -RINFO, X-Mme-Device-Id) are left visible on
// purpose, so the emulated machine is still debuggable.
inline bool is_secret_header(const std::string& name) {
    std::string n;
    n.reserve(name.size());
    for (char c : name) n.push_back((c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c);
    // Note: security-code (the 2FA code) is intentionally NOT masked — it's
    // one-time and consumed immediately, so it has no value in a log.
    static const char* const kSecret[] = {
        "x-token", "x-dsid", "x-apple-i-srl-no",   // serial number
        "x-apple-identity-token", "x-apple-pe-token", "x-apple-hb-token",
        "x-apple-gs-token", "x-apple-session-key", "x-apple-encrypted-session-key",
        "x-apple-i-ck",
        "x-apple-i-md",    // OTP, GSA machine (exact; -M/-LU/-RINFO stay visible)
        "x-apple-amd",     // OTP, anon DSID-1 machine (exact; -M stays visible)
    };
    for (const char* k : kSecret)
        if (n == k) return true;
    return false;
}

// Header value for a --debug dump: masked (equal-length) if sensitive, else as-is.
inline std::string mask_header_value(const std::string& name, const std::string& value) {
    return is_secret_header(name) ? mask_stars(value) : value;
}

// Mask the value of a plist <key>KEY</key> entry — whether <string> or <integer>
// — with equal-length asterisks, for --debug dumps. Masks every occurrence; a
// key whose value is not a string/integer (e.g. <true/>) is left untouched.
// Operates on a copy of the body, so breaking XML well-formedness is harmless.
inline void mask_plist_field(std::string& out, const std::string& key) {
    const std::string kKey = "<key>" + key + "</key>";
    size_t pos = 0;
    while ((pos = out.find(kKey, pos)) != std::string::npos) {
        size_t tag = out.find('<', pos + kKey.size());   // skip whitespace to value tag
        if (tag == std::string::npos) break;
        size_t open, close;
        if (out.compare(tag, 8, "<string>") == 0) {
            open  = tag + 8;
            close = out.find("</string>", open);
        } else if (out.compare(tag, 9, "<integer>") == 0) {
            open  = tag + 9;
            close = out.find("</integer>", open);
        } else {
            pos += kKey.size();   // value isn't a string/integer — nothing to mask
            continue;
        }
        if (close == std::string::npos) break;
        out.replace(open, close - open, std::string(close - open, '*'));
        pos = close;   // value length unchanged, so close is still valid
    }
}

#if defined(_WIN32)

inline std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

inline std::filesystem::path fs_path(const std::string& utf8) {
    return std::filesystem::path(utf8_to_wide(utf8));
}

inline FILE* fopen_utf8(const std::string& path, const char* mode) {
    std::wstring wmode;
    for (const char* p = mode; *p; ++p) wmode.push_back(static_cast<wchar_t>(*p));
    return _wfopen(utf8_to_wide(path).c_str(), wmode.c_str());
}

// UTF-16 → UTF-8.
inline std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        s.data(), n, nullptr, nullptr);
    return s;
}

// Convert a filesystem path back to UTF-8 (path::string() would return the
// active ANSI code page on Windows, re-mangling non-ASCII).
inline std::string to_utf8(const std::filesystem::path& p) {
    return wide_to_utf8(p.wstring());
}

// Write UTF-8 text to stderr so it renders on a real Windows console (which
// otherwise reads raw UTF-8 bytes as its OEM code page → mojibake). On a console
// we go through WriteConsoleW (UTF-16); a redirected stderr (file/pipe) keeps the
// raw UTF-8 bytes.
inline void write_err_utf8(const std::string& s) {
    if (_isatty(_fileno(stderr))) {
        std::wstring w = utf8_to_wide(s);
        HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
        if (h != INVALID_HANDLE_VALUE && !w.empty()) {
            DWORD written = 0;
            WriteConsoleW(h, w.data(), static_cast<DWORD>(w.size()), &written, nullptr);
            return;
        }
    }
    std::fwrite(s.data(), 1, s.size(), stderr);
}

#else  // POSIX — UTF-8 is the native encoding

inline std::filesystem::path fs_path(const std::string& utf8) {
    return std::filesystem::path(utf8);
}

inline FILE* fopen_utf8(const std::string& path, const char* mode) {
    return std::fopen(path.c_str(), mode);
}

inline std::string to_utf8(const std::filesystem::path& p) {
    return p.string();
}

inline void write_err_utf8(const std::string& s) {
    std::fwrite(s.data(), 1, s.size(), stderr);
}

#endif

}  // namespace ipt
