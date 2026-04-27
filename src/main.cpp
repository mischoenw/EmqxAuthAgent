#include "http_handler.h"
#include "rules_engine.h"
#include <libwebsockets.h>
#include <iostream>
#include <cstdlib>
#include <csignal>
#include <memory>
#include <string>

static volatile bool s_interrupted = false;

static void sigint_handler(int) { s_interrupted = true; }

int main() {
    // Configuration from environment variables
    const char* rules_env = std::getenv("RULES_CONFIG");
    const char* port_env  = std::getenv("PORT");
    const char* log_env   = std::getenv("LOG_LEVEL");
    const char* bind_env  = std::getenv("BIND_ADDR");

    std::string rules_path  = rules_env ? rules_env : "config/rules.yaml";
    int         port        = port_env  ? std::atoi(port_env) : 8000;
    const char* bind_addr   = bind_env  ? bind_env  : "127.0.0.1";

    // Suppress lws internal logs unless LOG_LEVEL=DEBUG
    if (!log_env || std::string(log_env) != "DEBUG") {
        lws_set_log_level(LLL_ERR | LLL_WARN, nullptr);
    }

    // Load rules
    std::unique_ptr<RulesEngine> engine;
    try {
        engine = std::make_unique<RulesEngine>(rules_path);
        std::cout << "[INFO] Loaded " << engine->rules_count()
                  << " rules from " << rules_path << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Failed to load rules: " << e.what() << "\n";
        return 1;
    }

    // lws protocol list — must be null-terminated
    const lws_protocols protocols[] = {
        http_protocol,
        { nullptr, nullptr, 0, 0, 0, nullptr, 0 }
    };

    lws_context_creation_info info{};
    info.port      = port;
    info.iface     = bind_addr;
    info.protocols = protocols;
    info.user      = engine.get(); // accessible via lws_context_user()
    info.options   = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

    lws_context* context = lws_create_context(&info);
    if (!context) {
        std::cerr << "[FATAL] Failed to create lws context\n";
        return 1;
    }

    std::cout << "[INFO] EmqxAuthAgent listening on " << bind_addr << ":" << port << "\n";

    std::signal(SIGINT,  sigint_handler);
    std::signal(SIGTERM, sigint_handler);

    while (!s_interrupted) {
        if (lws_service(context, 100) < 0) break;
    }

    lws_context_destroy(context);
    std::cout << "[INFO] Shutdown complete\n";
    return 0;
}
