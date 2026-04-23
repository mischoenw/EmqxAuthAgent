#include "topic_matcher.h"
#include <stdexcept>
#include <mutex>
#include <vector>
#include <string>

static std::unordered_map<std::string, std::regex> s_pattern_cache;
static std::mutex s_cache_mutex;

static std::string regex_escape(const std::string& s) {
    static const std::regex meta(R"([.^$|()\[\]{}*+?\\])");
    return std::regex_replace(s, meta, R"(\$&)");
}

static std::vector<std::string> split_slash(const std::string& s) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (c == '/') { parts.push_back(cur); cur.clear(); }
        else           { cur += c; }
    }
    parts.push_back(cur);
    return parts;
}

static bool has_any_placeholder(const std::string& pattern) {
    return pattern.find("{cn}") != std::string::npos ||
           pattern.find("{o}")  != std::string::npos ||
           pattern.find("{ou}") != std::string::npos;
}

// Regex that never matches anything — used when a placeholder value is invalid
// (e.g. contains '/' which would span multiple MQTT topic levels).
static std::regex never_match() {
    return std::regex("a^", std::regex::optimize);
}

// Build a regex from an MQTT topic pattern.
// Placeholders are substituted at segment level to avoid double-escaping:
//   {cn}, {o}, {ou} → regex_escape(value)  (one escape pass, not two)
// A placeholder value containing '/' returns never_match() because '/' is
// not a valid character within a single MQTT topic level.
static std::regex build_pattern_regex(const std::string& pattern,
                                      const TopicPlaceholders& ph) {
    auto segs = split_slash(pattern);
    std::string re;

    for (size_t i = 0; i < segs.size(); ++i) {
        const auto& seg = segs[i];

        // '#' check must come before the '/' separator so we don't add an
        // extra slash before the optional-suffix group.
        if (seg == "#") {
            if (i == 0) re = ".*";
            else        re += "(?:/.*)?";
            break;
        }

        if (i > 0) re += '/';

        if (seg == "+") {
            re += "[^/]+";
        } else if (seg == "{cn}") {
            if (ph.cn.find('/') != std::string::npos) return never_match();
            re += regex_escape(ph.cn);
        } else if (seg == "{o}") {
            if (ph.o.find('/') != std::string::npos) return never_match();
            re += regex_escape(ph.o);
        } else if (seg == "{ou}") {
            if (ph.ou.find('/') != std::string::npos) return never_match();
            re += regex_escape(ph.ou);
        } else {
            re += regex_escape(seg);
        }
    }

    return std::regex("^" + re + "$", std::regex::optimize);
}

void validate_topic_pattern(const std::string& pattern) {
    if (pattern.empty())
        throw std::invalid_argument("Topic pattern must not be empty");

    auto segs = split_slash(pattern);
    for (size_t i = 0; i + 1 < segs.size(); ++i) {
        if (segs[i] == "#")
            throw std::invalid_argument(
                "# wildcard must be the last segment: " + pattern);
    }
}

void precompile_static_pattern(const std::string& pattern) {
    if (has_any_placeholder(pattern)) return;
    std::lock_guard<std::mutex> lock(s_cache_mutex);
    if (!s_pattern_cache.count(pattern))
        s_pattern_cache.emplace(pattern, build_pattern_regex(pattern, {}));
}

bool matches_topic(const std::string& pattern,
                   const std::string& topic,
                   const TopicPlaceholders& ph) {
    if (!has_any_placeholder(pattern)) {
        std::lock_guard<std::mutex> lock(s_cache_mutex);
        auto it = s_pattern_cache.find(pattern);
        if (it != s_pattern_cache.end())
            return std::regex_match(topic, it->second);

        auto re = build_pattern_regex(pattern, {});
        auto [ins_it, _] = s_pattern_cache.emplace(pattern, re);
        return std::regex_match(topic, ins_it->second);
    }

    // Placeholder patterns compiled at request time (values vary per device).
    auto re = build_pattern_regex(pattern, ph);
    return std::regex_match(topic, re);
}
