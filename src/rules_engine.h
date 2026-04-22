#pragma once
#include "models.h"
#include <string>
#include <vector>
#include <shared_mutex>
#include <stdexcept>

// Thrown when rules.yaml contains invalid content.
struct RulesValidationError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class RulesEngine {
public:
    explicit RulesEngine(const std::string& config_path);

    // Evaluate an authorization request. Thread-safe (shared reader lock).
    AuthzResult authorize(const AuthzRequest& req) const;

    // Reload rules from the config file. Thread-safe (exclusive lock).
    void reload();

    size_t rules_count() const;

private:
    std::string config_path_;
    std::vector<Rule> rules_;
    mutable std::shared_mutex rules_mutex_;

    static std::vector<Rule> load_rules(const std::string& path);
};
