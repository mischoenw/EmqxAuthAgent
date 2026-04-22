#pragma once
#include "models.h"
#include <string>
#include <vector>
#include <unordered_map>

// Parse a DN string (RFC 2253 comma format or OpenSSL slash format) into its
// attribute lists. Attribute type keys are normalized to uppercase.
std::unordered_map<std::string, std::vector<std::string>>
parse_dn_raw(const std::string& dn_string);

// High-level entry point: extracts O, OU, and CN fields from the DN string.
// cert_cn is used as a fallback if no CN is found in cert_subject.
ParsedDN extract_cert_fields(const std::string& cert_subject,
                             const std::string& cert_cn = "");
