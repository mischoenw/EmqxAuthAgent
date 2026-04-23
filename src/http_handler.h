#pragma once
#include "rules_engine.h"
#include <libwebsockets.h>
#include <string>

// Per-connection state stored by libwebsockets in the session data area.
struct SessionData {
    std::string body;          // accumulates request body chunks
    std::string response;      // serialized JSON response
    bool        complete{false}; // true once body is fully received
    bool        is_reload{false};// true for POST /admin/reload
};

// lws protocol definition — register this in the lws_protocols array in main.
extern const lws_protocols http_protocol;

// The RulesEngine pointer is passed via lws_context user data.
// http_callback reads it as: static_cast<RulesEngine*>(lws_context_user(lws_get_context(wsi)))
int http_callback(lws* wsi, lws_callback_reasons reason,
                  void* user, void* in, size_t len);
