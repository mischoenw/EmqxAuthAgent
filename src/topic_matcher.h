#pragma once
#include <string>
#include <regex>
#include <unordered_map>

// Returns true if topic matches pattern.
// Pattern may contain MQTT wildcards (+ and #) and the {cn} placeholder.
// {cn} is replaced with the literal cn value before matching.
bool matches_topic(const std::string& pattern,
                   const std::string& topic,
                   const std::string& cn = "");

// Validates a topic pattern at rules-load time.
// Throws std::invalid_argument if # appears in a non-terminal position,
// or if the pattern is empty.
void validate_topic_pattern(const std::string& pattern);

// Pre-compiled cache for static patterns (no {cn}).
// Call precompile_static_pattern at startup; matches_topic uses the cache automatically.
void precompile_static_pattern(const std::string& pattern);
