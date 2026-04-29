#pragma once
#include <string>
#include <vector>

// Set to true when LOG_LEVEL=DEBUG. Read by http_handler and rules_engine.
extern bool g_debug;

struct AuthzRequest {
    std::string username;
    std::string clientid;
    std::string peerhost;
    std::string topic;
    std::string action;       // "publish" | "subscribe"
    std::string cert_subject; // Full DN: "CN=d,OU=sensors,O=AcmeCorp"
    std::string cert_cn;      // Optional CN shortcut from EMQX
};

struct ParsedDN {
    std::vector<std::string> o_values;
    std::vector<std::string> ou_values;
    std::string cn;
};

struct TopicRuleSet {
    std::vector<std::string> publish_allow;
    std::vector<std::string> publish_deny;
    std::vector<std::string> subscribe_allow;
    std::vector<std::string> subscribe_deny;
};

struct Rule {
    std::string id;
    std::string match_o;   // "" = wildcard (any)
    std::string match_ou;  // "" = wildcard (any)
    TopicRuleSet topics;
    int specificity; // O+OU=6, OU-only=4, O-only=2, wildcard=0
};

enum class AuthzResult { Allow, Deny };
