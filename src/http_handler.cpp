#include "http_handler.h"
#include <nlohmann/json.hpp>
#include <cstring>
#include <iostream>
#include <cstdlib>

using json = nlohmann::json;

// Maximum body size we accept (16 KB is ample for an EMQX auth request).
static constexpr size_t MAX_BODY = 16 * 1024;

static RulesEngine* get_engine(lws* wsi) {
    return static_cast<RulesEngine*>(lws_context_user(lws_get_context(wsi)));
}

// Send a complete HTTP response and close the connection.
static int send_response(lws* wsi, int http_status,
                         const std::string& body,
                         const std::string& content_type = "application/json") {
    std::string headers;
    headers.reserve(256);

    unsigned char buf[LWS_PRE + 4096];
    unsigned char* p   = buf + LWS_PRE;
    unsigned char* end = buf + sizeof(buf) - LWS_PRE;

    if (lws_add_http_common_headers(wsi, http_status,
                                    content_type.c_str(),
                                    body.size(), &p, end))
        return 1;

    if (lws_finalize_write_http_header(wsi, buf + LWS_PRE, &p, end))
        return 1;

    // Write body
    std::vector<unsigned char> body_buf(LWS_PRE + body.size());
    std::memcpy(body_buf.data() + LWS_PRE, body.data(), body.size());
    lws_write(wsi, body_buf.data() + LWS_PRE,
              body.size(), LWS_WRITE_HTTP_FINAL);

    if (lws_http_transaction_completed(wsi)) return -1;
    return 0;
}

static std::string make_response(const AuthzResponse& r) {
    json resp = {{"result", r.result == AuthzResult::Allow ? "allow" : "deny"}};
    return resp.dump();
}

static std::string make_deny() { return R"({"result":"deny"})"; }

static AuthzRequest parse_request(const json& j) {
    AuthzRequest req;
    req.username     = j.value("username",     "");
    req.clientid     = j.value("clientid",     "");
    req.peerhost     = j.value("peerhost",     "");
    req.topic        = j.value("topic",        "");
    req.action       = j.value("action",       "");
    req.cert_subject = j.value("cert_dn",  "");
    req.cert_cn      = j.value("cert_cn",  "");
    return req;
}

static bool valid_action(const std::string& a) {
    return a == "publish" || a == "subscribe";
}

int http_callback(lws* wsi, lws_callback_reasons reason,
                  void* user, void* in, size_t len) {
    auto* sd = static_cast<SessionData*>(user);

    switch (reason) {

    case LWS_CALLBACK_HTTP: {
        // 'in' points to the URI path, len is its length.
        std::string uri(static_cast<const char*>(in), len);

        // Strip query string if present
        auto q = uri.find('?');
        if (q != std::string::npos) uri = uri.substr(0, q);

        bool is_post = lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) > 0;

        if (g_debug)
            std::cout << "[DEBUG] " << (is_post ? "POST" : "GET") << " " << uri << std::endl;

        if (uri == "/mqtt/authz" && is_post) {
            return 0;
        }
        if (uri == "/health" && !is_post) {
            return send_response(wsi, HTTP_STATUS_NO_CONTENT, "");
        }
        if (uri == "/admin/reload" && is_post) {
            sd->is_reload = true;
            return 0;
        }

        return send_response(wsi, HTTP_STATUS_NOT_FOUND, R"({"error":"not found"})");
    }

    case LWS_CALLBACK_HTTP_BODY: {
        if (!sd) return 0;
        if (sd->body.size() + len > MAX_BODY) {
            send_response(wsi, 413,
                          R"({"error":"body too large"})");
            return -1;
        }
        sd->body.append(static_cast<const char*>(in), len);
        return 0;
    }

    case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
        if (!sd) return 0;

        if (sd->is_reload) {
            // Validate bearer token
            const char* admin_token = std::getenv("ADMIN_TOKEN");
            char auth_buf[256] = {};
            lws_hdr_copy(wsi, auth_buf, sizeof(auth_buf),
                         WSI_TOKEN_HTTP_AUTHORIZATION);
            std::string auth_header(auth_buf);
            std::string expected = "Bearer ";
            expected += (admin_token ? admin_token : "");

            if (!admin_token || auth_header != expected) {
                return send_response(wsi, HTTP_STATUS_FORBIDDEN,
                                     R"({"error":"forbidden"})");
            }
            auto* engine = get_engine(wsi);
            if (engine) {
                try {
                    engine->reload();
                    json resp = {{"status", "reloaded"},
                                 {"rules_count", engine->rules_count()}};
                    return send_response(wsi, HTTP_STATUS_OK, resp.dump());
                } catch (const std::exception& e) {
                    json err = {{"error", std::string("reload failed: ") + e.what()}};
                    return send_response(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
                                        err.dump());
                }
            }
            return send_response(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
                                 R"({"error":"engine unavailable"})");
        }

        // Normal authorization request
        auto* engine = get_engine(wsi);
        if (!engine)
            return send_response(wsi, HTTP_STATUS_OK, make_deny());

        try {
            auto j   = json::parse(sd->body);
            auto req = parse_request(j);

            if (g_debug) {
                std::cout << "[DEBUG] request"
                          << " action="       << req.action
                          << " topic="        << req.topic
                          << " client="       << req.clientid
                          << " peerhost="     << req.peerhost
                          << " cert_subject=" << req.cert_subject
                          << " cert_cn="      << req.cert_cn
                          << "\n[DEBUG] payload " << sd->body << std::endl;
            }

            if (!valid_action(req.action) || req.topic.empty()) {
                if (g_debug)
                    std::cout << "[DEBUG] reject — invalid action or empty topic" << std::endl;
                return send_response(wsi, HTTP_STATUS_OK, make_deny());
            }

            AuthzResponse resp = engine->authorize(req);
            return send_response(wsi, HTTP_STATUS_OK, make_response(resp));

        } catch (const std::exception& e) {
            if (g_debug)
                std::cout << "[DEBUG] parse error: " << e.what()
                          << " payload=" << sd->body << std::endl;
            // Malformed JSON or missing fields → deny (EMQX must always get 200)
            return send_response(wsi, HTTP_STATUS_OK, make_deny());
        }
    }

    case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
    case LWS_CALLBACK_CLOSED_HTTP:
        break;

    default:
        break;
    }
    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const lws_protocols http_protocol = {
    "http",
    http_callback,
    sizeof(SessionData),
    MAX_BODY,
    0, nullptr, 0
};
