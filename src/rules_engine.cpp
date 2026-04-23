#include "rules_engine.h"
#include "cert_parser.h"
#include "topic_matcher.h"
#include <yaml-cpp/yaml.h>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <mutex>

static std::string str_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

static int compute_specificity(const std::string& o, const std::string& ou) {
    int score = 0;
    if (!o.empty()  && o  != "*") score += 2;
    if (!ou.empty() && ou != "*") score += 4;
    return score;
}

static std::vector<std::string> load_str_list(const YAML::Node& node,
                                               const std::string& rule_id,
                                               const std::string& field) {
    if (!node || node.IsNull()) return {};
    if (!node.IsSequence())
        throw RulesValidationError("Rule '" + rule_id + "': field '" + field +
                                   "' must be a list");
    std::vector<std::string> result;
    for (const auto& item : node) {
        std::string pattern = item.as<std::string>();
        try { validate_topic_pattern(pattern); }
        catch (const std::invalid_argument& e) {
            throw RulesValidationError("Rule '" + rule_id + "', field '" +
                                       field + "': " + e.what());
        }
        result.push_back(pattern);
    }
    return result;
}

std::vector<Rule> RulesEngine::load_rules(const std::string& path) {
    YAML::Node doc;
    try {
        doc = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw RulesValidationError("Failed to parse rules file: " +
                                   std::string(e.what()));
    }

    auto rules_node = doc["rules"];
    if (!rules_node || !rules_node.IsSequence())
        throw RulesValidationError("rules.yaml: top-level 'rules' must be a list");

    std::vector<Rule> rules;
    for (const auto& rn : rules_node) {
        if (!rn["id"])
            throw RulesValidationError("Every rule must have an 'id' field");

        Rule r;
        r.id = rn["id"].as<std::string>();
        if (r.id.empty())
            throw RulesValidationError("Rule id must not be empty");

        const auto& match = rn["match"];
        if (match) {
            if (match["o"])  r.match_o  = match["o"].as<std::string>();
            if (match["ou"]) r.match_ou = match["ou"].as<std::string>();
        }
        // Normalise "*" and absent to empty string (wildcard sentinel)
        if (r.match_o  == "*") r.match_o  = "";
        if (r.match_ou == "*") r.match_ou = "";

        r.specificity = compute_specificity(r.match_o, r.match_ou);

        auto allow_node = rn["allow"];
        auto deny_node  = rn["deny"];

        r.topics.publish_allow   = load_str_list(allow_node ? allow_node["publish"]   : YAML::Node(), r.id, "allow.publish");
        r.topics.subscribe_allow = load_str_list(allow_node ? allow_node["subscribe"] : YAML::Node(), r.id, "allow.subscribe");
        r.topics.publish_deny    = load_str_list(deny_node  ? deny_node["publish"]    : YAML::Node(), r.id, "deny.publish");
        r.topics.subscribe_deny  = load_str_list(deny_node  ? deny_node["subscribe"]  : YAML::Node(), r.id, "deny.subscribe");

        // Pre-compile static patterns (no {cn}) for this rule
        for (auto& p : r.topics.publish_allow)   precompile_static_pattern(p);
        for (auto& p : r.topics.subscribe_allow) precompile_static_pattern(p);
        for (auto& p : r.topics.publish_deny)    precompile_static_pattern(p);
        for (auto& p : r.topics.subscribe_deny)  precompile_static_pattern(p);

        rules.push_back(std::move(r));
    }

    // Stable sort descending by specificity (YAML order as tiebreaker)
    std::stable_sort(rules.begin(), rules.end(),
                     [](const Rule& a, const Rule& b) {
                         return a.specificity > b.specificity;
                     });

    return rules;
}

static bool identity_matches(const Rule& rule, const ParsedDN& dn) {
    // O match
    if (!rule.match_o.empty()) {
        std::string want = str_lower(rule.match_o);
        bool found = false;
        for (const auto& v : dn.o_values) {
            if (str_lower(v) == want) { found = true; break; }
        }
        if (!found) return false;
    }
    // OU match
    if (!rule.match_ou.empty()) {
        std::string want = str_lower(rule.match_ou);
        bool found = false;
        for (const auto& v : dn.ou_values) {
            if (str_lower(v) == want) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

static AuthzResult evaluate(const std::vector<Rule>& rules,
                             const ParsedDN& dn,
                             const std::string& topic,
                             const std::string& action) {
    bool is_publish = (action == "publish");

    // Build placeholder values from the first O and OU in the cert DN.
    TopicPlaceholders ph;
    ph.cn = dn.cn;
    ph.o  = dn.o_values.empty()  ? "" : dn.o_values[0];
    ph.ou = dn.ou_values.empty() ? "" : dn.ou_values[0];

    for (const auto& rule : rules) {
        if (!identity_matches(rule, dn)) continue;

        const auto& deny_list  = is_publish ? rule.topics.publish_deny   : rule.topics.subscribe_deny;
        const auto& allow_list = is_publish ? rule.topics.publish_allow  : rule.topics.subscribe_allow;

        // Explicit deny within matched rule wins over allow
        for (const auto& pat : deny_list) {
            if (matches_topic(pat, topic, ph)) {
                std::cout << "[DENY] rule=" << rule.id
                          << " o=" << ph.o << " ou=" << ph.ou << " cn=" << ph.cn
                          << " topic=" << topic << " action=" << action
                          << " deny_pattern=" << pat << "\n";
                return AuthzResult::Deny;
            }
        }
        for (const auto& pat : allow_list) {
            if (matches_topic(pat, topic, ph)) {
                std::cout << "[ALLOW] rule=" << rule.id
                          << " o=" << ph.o << " ou=" << ph.ou << " cn=" << ph.cn
                          << " topic=" << topic << " action=" << action
                          << " allow_pattern=" << pat << "\n";
                return AuthzResult::Allow;
            }
        }
        // Identity matched but no topic pattern matched → fall through to
        // less-specific rule (enables layered O+OU / O-only rules)
    }

    std::cout << "[DENY] no matching rule"
              << " o=" << ph.o << " ou=" << ph.ou << " cn=" << ph.cn
              << " topic=" << topic << " action=" << action << "\n";
    return AuthzResult::Deny;
}

RulesEngine::RulesEngine(const std::string& config_path)
    : config_path_(config_path), rules_(load_rules(config_path)) {}

AuthzResult RulesEngine::authorize(const AuthzRequest& req) const {
    std::shared_lock lock(rules_mutex_);
    ParsedDN dn = extract_cert_fields(req.cert_subject, req.cert_cn);
    return evaluate(rules_, dn, req.topic, req.action);
}

void RulesEngine::reload() {
    auto new_rules = load_rules(config_path_);
    std::unique_lock lock(rules_mutex_);
    rules_ = std::move(new_rules);
}

size_t RulesEngine::rules_count() const {
    std::shared_lock lock(rules_mutex_);
    return rules_.size();
}
