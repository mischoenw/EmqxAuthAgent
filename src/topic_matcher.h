#pragma once
#include <string>
#include <regex>
#include <unordered_map>

// Certificate-derived values substituted into topic patterns.
struct TopicPlaceholders {
    std::string cn;  // {cn} → certificate Common Name
    std::string o;   // {o}  → first certificate O value
    std::string ou;  // {ou} → first certificate OU value
};

// Returns true if topic matches pattern.
// Pattern may contain MQTT wildcards (+ and #) and the placeholders
// {cn}, {o}, {ou} — each replaced with the corresponding cert field value.
bool matches_topic(const std::string& pattern,
                   const std::string& topic,
                   const TopicPlaceholders& ph = {});

// Validates a topic pattern at rules-load time.
// Throws std::invalid_argument if # appears in a non-terminal position,
// or if the pattern is empty.
void validate_topic_pattern(const std::string& pattern);

// Pre-compile and cache static patterns (those without any {placeholder}).
// Called at rules-load time so request-time matching is fast.
void precompile_static_pattern(const std::string& pattern);
