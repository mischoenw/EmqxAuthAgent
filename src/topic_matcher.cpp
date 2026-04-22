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

static std::string substitute_cn(const std::string& pattern, const std::string& cn) {
    const std::string placeholder = "{cn}";
    std::string result;
    std::string escaped = regex_escape(cn);
    size_t pos = 0;
    while (true) {
        size_t found = pattern.find(placeholder, pos);
        if (found == std::string::npos) { result += pattern.substr(pos); break; }
        result += pattern.substr(pos, found - pos);
        result += escaped;
        pos = found + placeholder.size();
    }
    return result;
}

// Build a std::regex from an MQTT topic pattern (after {cn} substitution).
// Rules:
//   +  → matches exactly one topic level ([^/]+)
//   #  → must be last segment; matches the current level and anything below
//          "sensors/#" → ^sensors(?:/.*)?$
//          "#"         → ^.*$
static std::regex build_pattern_regex(const std::string& resolved_pattern) {
    auto segs = split_slash(resolved_pattern);
    std::string re;

    for (size_t i = 0; i < segs.size(); ++i) {
        const auto& seg = segs[i];

        if (seg == "#") {
            // Must be last segment (validated separately).
            if (i == 0) {
                // Bare '#': match everything.
                re = ".*";
            } else {
                // Pattern like "foo/bar/#": already have "foo/bar" in re,
                // append optional slash + anything.
                re += "(?:/.*)?";
            }
            break;
        }

        if (i > 0) re += '/';

        if (seg == "+") {
            re += "[^/]+";
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
    if (pattern.find("{cn}") != std::string::npos) return;
    std::lock_guard<std::mutex> lock(s_cache_mutex);
    if (!s_pattern_cache.count(pattern))
        s_pattern_cache.emplace(pattern, build_pattern_regex(pattern));
}

bool matches_topic(const std::string& pattern,
                   const std::string& topic,
                   const std::string& cn) {
    bool has_placeholder = pattern.find("{cn}") != std::string::npos;

    if (!has_placeholder) {
        std::lock_guard<std::mutex> lock(s_cache_mutex);
        auto it = s_pattern_cache.find(pattern);
        if (it != s_pattern_cache.end())
            return std::regex_match(topic, it->second);

        auto re = build_pattern_regex(pattern);
        auto [ins_it, _] = s_pattern_cache.emplace(pattern, re);
        return std::regex_match(topic, ins_it->second);
    }

    // {cn} patterns compiled on the fly (CN varies per device)
    std::string resolved = substitute_cn(pattern, cn);
    auto re = build_pattern_regex(resolved);
    return std::regex_match(topic, re);
}
