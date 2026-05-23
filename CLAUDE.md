# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this service does

EmqxAuthAgent is a C++17 HTTP authorization agent for EMQX MQTT broker. EMQX calls it via HTTP POST for every publish/subscribe attempt, forwarding the client's mTLS certificate DN. The agent evaluates `config/rules.yaml` and replies `{"result":"allow"}` or `{"result":"deny"}`.

The service binds to `127.0.0.1` only, requires mTLS (client cert verified against `SSL_CA`), and is deployed on-premise under supervisord.

## Build

**Prerequisites:** `cmake ≥ 3.20`, `conan 2.x`, `ninja`, `g++`, `perl`, `make`

```bash
# One-time: install Conan deps (slow — compiles libwebsockets/OpenSSL from source)
conan profile detect --force
conan install . --build=missing -s build_type=Release -s compiler.cppstd=17 --output-folder=cmake-build

# Configure
cmake -B cmake-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake-build/conan_toolchain.cmake

# Build binary only
cmake --build cmake-build --target emqx-auth-agent

# Build + run all tests
cmake --build cmake-build --target run_tests
ctest --test-dir cmake-build --output-on-failure

# Run a single test binary directly (GTest filter)
./cmake-build/tests/run_tests --gtest_filter='RulesEngineTest.CnMatchAllow'
```

`BUILD_TESTING=OFF` skips the test target (used in the Docker builder stage).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `RULES_CONFIG` | `config/rules.yaml` | Path to rules file |
| `PORT` | `8000` | Listen port |
| `BIND_ADDR` | `127.0.0.1` | Listen address |
| `LOG_LEVEL` | `INFO` | Set to `DEBUG` for full request/decision logs |
| `SSL_CERT` | *(required)* | Server TLS certificate |
| `SSL_KEY` | *(required)* | Server private key |
| `SSL_CA` | *(required)* | CA chain to verify client certs (mTLS) |
| `ADMIN_TOKEN` | — | Bearer token for `POST /admin/reload` |

The binary refuses to start if `SSL_CERT`, `SSL_KEY`, or `SSL_CA` are unset.

## HTTP endpoints

- `POST /mqtt/authz` — main authorization endpoint (called by EMQX)
- `GET  /health` — `{"status":"ok","rules_count":N}`
- `POST /admin/reload` — hot-reload `rules.yaml`; requires `Authorization: Bearer <ADMIN_TOKEN>`

## Request JSON fields

EMQX sends (see `emqx_config_example/authorization.conf`):

```json
{ "username": "...", "clientid": "...", "peerhost": "...",
  "topic": "...", "action": "publish|subscribe",
  "cert_dn": "<full DN>", "cert_cn": "<CN only>" }
```

`cert_dn` is the full RFC 2253 or OpenSSL-slash DN string. `cert_cn` is a shortcut; the parser uses it as fallback if CN cannot be found in `cert_dn`.

## Architecture

```
EMQX broker  →  POST /mqtt/authz
                     │
               http_handler.cpp        ← libwebsockets callback; accumulates
                     │                    body chunks, parses JSON
               rules_engine.cpp        ← loads rules.yaml, evaluates with
                     │                    shared_mutex for hot-reload safety
         ┌───────────┴──────────┐
   cert_parser.cpp        topic_matcher.cpp
   (DN → ParsedDN)        (MQTT wildcards + {o}/{ou}/{cn} substitution)
```

**Data flow:**
1. `http_handler` parses JSON → `AuthzRequest`
2. `cert_parser::extract_cert_fields` turns `cert_dn` → `ParsedDN` (O values, OU values, CN)
3. `rules_engine::evaluate` iterates rules sorted by specificity, checks identity then topic patterns
4. Returns `allow` or `deny`

**Rule specificity scoring** (higher = evaluated first):

| Fields set | Score |
|---|---|
| O + OU + CN | 7 |
| O + OU | 6 |
| OU + CN | 5 |
| O + CN | 3 |
| OU only | 4 |
| O only | 2 |
| CN only | 1 |
| none (wildcard) | 0 |

Rules with equal specificity keep their YAML order (stable sort).

**Fall-through:** if an identity matches a rule but no topic pattern fires, evaluation continues to the next rule. This enables layered rules (e.g. a specific OU rule for certain topics + a catch-all O rule for the rest).

**Topic patterns** support:
- `+` — single MQTT level wildcard
- `#` — multi-level wildcard (must be the last segment)
- `{o}`, `{ou}`, `{cn}` — substituted from the cert DN at match time
- Static patterns (no placeholders) are pre-compiled and cached at rules-load time

## `config/rules.yaml` format

```yaml
rules:
  - id: unique-rule-id
    match:           # all fields optional; omit or use "*" = wildcard
      o:  ExactOrg   # case-insensitive, matches any O value in the cert
      ou: ExactUnit  # case-insensitive, matches any OU value in the cert
      cn: device-01  # case-insensitive, exact match on CN
    allow:
      publish:   ["/{o}/{ou}/#"]
      subscribe: ["/{o}/{ou}/#"]
    deny:
      publish:   ["/forbidden/#"]
```

Within a matched rule, `deny` patterns are checked before `allow` — explicit deny wins. Reload without restart: `POST /admin/reload`.

## `src/globals.cpp`

Defines `bool g_debug`. This file must be compiled into **both** the main binary and the test binary (`run_tests`) because `rules_engine.cpp` references `g_debug` and is linked into both. Adding a new source file that uses `g_debug` requires no changes here; but if you add a new cmake target that links `rules_engine.cpp`, add `src/globals.cpp` to it as well.

## CI / Docker

CI runs on push to `main` and `claude/**` branches:
1. **Build & Test** job — Conan deps cached in `~/.conan2/p`, runs `ctest`
2. **Docker Build & Push** job — multi-stage build, pushes to `ghcr.io/mischoenw/emqxauthagent`

Docker tags: `latest` (main), `v1.2.3` (semver tags), `sha-<short>` (always).

The Dockerfile has three stages: `builder` (compiles binary, `BUILD_TESTING=OFF`), `test-runner` (inherits builder, runs tests), `runtime` (minimal Debian + binary).

## On-premise deployment

Binary path: `/opt/emqx_authz_agent/bin/emqx-auth-agent`  
Supervisor config: `emqx-auth-agent.conf` → `/etc/supervisor/conf.d/`  
SSL files under `/opt/emqx_authz_agent/ssl/` — `private.key`, `public.pem`, `ca-chain.pem`

```bash
# After editing rules.yaml, reload without restart:
curl -sk --cert ssl/public.pem --key ssl/private.key \
  -X POST https://127.0.0.1:7777/admin/reload \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

## Authorization smoke test

```bash
./test-authz.sh   # requires mosquitto-clients and ssl/consumer.pub + ssl/consumer.key
```

Connects to `mqtt.mmbr.dev:8884`, extracts O/OU from the cert automatically, and verifies publish/subscribe allow+deny in 6 checks.

## Development workflow

**Always follow this process for every change:**

1. **Branch**: develop on the designated `claude/**` feature branch (e.g. `claude/emqx-mtls-topic-auth-gjaDm`). Never commit directly to `main`.
2. **Commit**: use clear, descriptive commit messages.
3. **Push**: `git push -u origin <branch-name>`
4. **PR**: after every push, create a pull request targeting `main` using `mcp__github__create_pull_request`. This is mandatory — every push must be followed by a PR.
