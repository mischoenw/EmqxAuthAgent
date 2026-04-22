#include "cert_parser.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

// Split s on delimiter, but treat \<char> as an escaped single character
// (never split on an escaped delimiter).
static std::vector<std::string> split_unescaped(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::string current;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            current += s[i];
            current += s[i + 1];
            ++i;
        } else if (s[i] == delim) {
            parts.push_back(current);
            current.clear();
        } else {
            current += s[i];
        }
    }
    parts.push_back(current);
    return parts;
}

// Decode a hex nibble character to its integer value.
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Unescape an RFC 2253 attribute value.
// Handles \XX (two-hex-digit byte) and \<special> (literal character).
// Also handles #hexstring values (entire value hex-encoded).
static std::string unescape_value(const std::string& val) {
    if (val.empty()) return val;

    // #hexstring: entire value is hex-encoded bytes
    if (val[0] == '#' && val.size() >= 3 && (val.size() - 1) % 2 == 0) {
        std::string decoded;
        bool valid = true;
        for (size_t i = 1; i < val.size(); i += 2) {
            int hi = hex_nibble(val[i]);
            int lo = hex_nibble(val[i + 1]);
            if (hi < 0 || lo < 0) { valid = false; break; }
            decoded += static_cast<char>((hi << 4) | lo);
        }
        if (valid) return decoded;
    }

    std::string result;
    result.reserve(val.size());
    for (size_t i = 0; i < val.size(); ++i) {
        if (val[i] == '\\' && i + 1 < val.size()) {
            char next = val[i + 1];
            int hi = hex_nibble(next);
            if (hi >= 0 && i + 2 < val.size()) {
                int lo = hex_nibble(val[i + 2]);
                if (lo >= 0) {
                    result += static_cast<char>((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            // \<special> — strip the backslash
            result += next;
            ++i;
        } else {
            result += val[i];
        }
    }
    return result;
}

static std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return s;
}

// Strip leading and trailing ASCII spaces/tabs.
static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t");
    return s.substr(start, end - start + 1);
}

// Parse OpenSSL slash-delimited format: /CN=foo/OU=bar/O=Baz
static std::unordered_map<std::string, std::vector<std::string>>
parse_slash_format(const std::string& dn) {
    std::unordered_map<std::string, std::vector<std::string>> result;
    // Split on '/' — first token will be empty (string starts with '/')
    auto parts = split_unescaped(dn.substr(1), '/');
    for (const auto& part : parts) {
        if (part.empty()) continue;
        auto eq = part.find('=');
        if (eq == std::string::npos) continue;
        std::string attr = to_upper(trim(part.substr(0, eq)));
        std::string val  = unescape_value(trim(part.substr(eq + 1)));
        result[attr].push_back(val);
    }
    return result;
}

// Parse RFC 2253 comma-delimited format: CN=foo,OU=bar,O=Baz
static std::unordered_map<std::string, std::vector<std::string>>
parse_rfc2253(const std::string& dn) {
    std::unordered_map<std::string, std::vector<std::string>> result;
    auto rdns = split_unescaped(dn, ',');
    for (const auto& rdn : rdns) {
        // Multi-valued RDNs use '+' as separator (e.g. OU=sensors+O=overlay)
        auto avas = split_unescaped(rdn, '+');
        for (const auto& ava : avas) {
            auto eq = ava.find('=');
            if (eq == std::string::npos) continue;
            std::string attr = to_upper(trim(ava.substr(0, eq)));
            std::string val  = unescape_value(trim(ava.substr(eq + 1)));
            result[attr].push_back(val);
        }
    }
    return result;
}

std::unordered_map<std::string, std::vector<std::string>>
parse_dn_raw(const std::string& dn_string) {
    if (dn_string.empty()) return {};
    if (!dn_string.empty() && dn_string[0] == '/') {
        return parse_slash_format(dn_string);
    }
    return parse_rfc2253(dn_string);
}

ParsedDN extract_cert_fields(const std::string& cert_subject,
                             const std::string& cert_cn) {
    ParsedDN result;
    auto raw = parse_dn_raw(cert_subject);

    auto it_o = raw.find("O");
    if (it_o != raw.end()) result.o_values = it_o->second;

    auto it_ou = raw.find("OU");
    if (it_ou != raw.end()) result.ou_values = it_ou->second;

    auto it_cn = raw.find("CN");
    if (it_cn != raw.end() && !it_cn->second.empty()) {
        result.cn = it_cn->second[0];
    } else {
        result.cn = cert_cn;
    }

    return result;
}
