# EmqxAuthAgent

An external HTTP authorization agent for [EMQX](https://www.emqx.io/) that enforces topic access control based on the **mTLS client certificate** of each connecting device.

EMQX calls the agent on every publish and subscribe attempt. The agent inspects the certificate's Distinguished Name (DN) fields — Organization (`O`), Organizational Unit (`OU`), and Common Name (`CN`) — and evaluates a YAML rule file to return `allow` or `deny`.

## How it works

```
MQTT Device  ──mTLS──▶  EMQX Broker  ──HTTP POST──▶  EmqxAuthAgent
  (cert DN)                                              (rules.yaml)
                                                              │
                                                    ◀── allow / deny
```

1. The MQTT client connects to EMQX with a client certificate.
2. EMQX forwards the certificate DN and the requested topic/action to the agent via HTTP.
3. The agent matches the DN against rules and responds `{"result":"allow"}` or `{"result":"deny"}`.
4. EMQX enforces the decision — on denial it disconnects the client (`deny_action = disconnect`).

## Prerequisites

- EMQX 5.x with an mTLS listener configured (`verify = verify_peer`)
- A PKI where each device certificate carries meaningful `O`, `OU`, and/or `CN` values
- Linux/AMD64 host for the agent process

## Installation

### 1. Get the binary

Pull the pre-built image from GitHub Container Registry and extract the binary:

```bash
echo YOUR_GITHUB_PAT | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
docker pull ghcr.io/mischoenw/emqxauthagent:latest

docker create --name tmp ghcr.io/mischoenw/emqxauthagent:latest
docker cp tmp:/usr/local/bin/emqx-auth-agent /opt/emqx_authz_agent/bin/emqx-auth-agent
docker rm tmp

chmod +x /opt/emqx_authz_agent/bin/emqx-auth-agent
```

### 2. Create a dedicated user

```bash
useradd -r -s /bin/false -g emqxauthzagent emqxauthzagent
chown -R emqxauthzagent:emqxauthzagent /opt/emqx_authz_agent
```

### 3. Place TLS files

The agent opens an **HTTPS + mTLS** socket — both the server certificate and the CA used to verify incoming clients are required at startup.

```
/opt/emqx_authz_agent/ssl/private.key     # server private key
/opt/emqx_authz_agent/ssl/public.pem      # server certificate
/opt/emqx_authz_agent/ssl/ca-chain.pem    # CA chain to verify client certs
```

### 4. Write `rules.yaml`

```
/opt/emqx_authz_agent/config/rules.yaml
```

See [Configuring rules](#configuring-rules) below.

### 5. Install the supervisor unit

Copy `emqx-auth-agent.conf` to `/etc/supervisor/conf.d/` and reload:

```bash
supervisorctl reread
supervisorctl update
supervisorctl status emqx-auth-agent
```

The bundled `emqx-auth-agent.conf` sets all required environment variables and runs the process as `emqxauthzagent`.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `RULES_CONFIG` | `config/rules.yaml` | Path to the rules file |
| `PORT` | `8000` | TCP port to listen on |
| `BIND_ADDR` | `127.0.0.1` | Listen address (loopback by default) |
| `LOG_LEVEL` | `INFO` | Set to `DEBUG` to log every request, payload, and rule decision |
| `SSL_CERT` | *(required)* | Path to the server TLS certificate |
| `SSL_KEY` | *(required)* | Path to the server private key |
| `SSL_CA` | *(required)* | Path to the CA chain for verifying client certificates |
| `ADMIN_TOKEN` | — | Bearer token required for `POST /admin/reload` |

The process exits immediately at startup if `SSL_CERT`, `SSL_KEY`, or `SSL_CA` are not set.

## Configuring rules

Edit `/opt/emqx_authz_agent/config/rules.yaml`. Changes take effect after a reload (no restart needed):

```bash
curl -sk --cert ssl/public.pem --key ssl/private.key \
  -X POST https://127.0.0.1:7777/admin/reload \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

### Rule structure

```yaml
rules:
  - id: unique-rule-id          # required, must be unique
    match:                      # all fields optional — omit or use "*" for wildcard
      o:  ExactOrg              # matches O field in the client certificate DN
      ou: ExactUnit             # matches OU field
      cn: device-hostname       # matches CN field
    allow:
      publish:   ["topic/pattern/#"]
      subscribe: ["topic/pattern/#"]
    deny:
      publish:   ["forbidden/#"]
      subscribe: ["forbidden/#"]
```

**Identity matching** (`match` block):
- Each field is case-insensitive and must match exactly (no wildcards in the value itself).
- Omitting a field or setting it to `"*"` matches any value.
- For certificates with multiple OU values, a rule matches if **any** OU in the cert equals `match.ou`.

**Topic patterns** support standard MQTT wildcards:

| Pattern | Meaning |
|---|---|
| `+` | Single-level wildcard — matches exactly one topic level |
| `#` | Multi-level wildcard — matches the rest of the topic (must be the last segment) |
| `{o}` | Replaced with the first `O` value from the client certificate |
| `{ou}` | Replaced with the first `OU` value from the client certificate |
| `{cn}` | Replaced with the `CN` value from the client certificate |

**Evaluation order:**

Rules are sorted by **specificity** before evaluation — more specific identity matches are checked first. Within a matched rule, `deny` patterns are checked before `allow` (explicit deny wins). If an identity matches a rule but no topic pattern fires, evaluation continues to the next rule (fall-through).

| Fields set in `match` | Specificity |
|---|---|
| O + OU + CN | 7 |
| O + OU | 6 |
| OU + CN | 5 |
| O + CN | 3 |
| OU only | 4 |
| O only | 2 |
| CN only | 1 |
| none / all wildcards | 0 |

### Example: device namespace isolation

Each device may only access topics under its own `/{o}/{ou}/` prefix:

```yaml
rules:
  - id: device-own-namespace
    allow:
      publish:
        - "/{o}/{ou}/#"
      subscribe:
        - "/{o}/{ou}/#"
```

A device with `O=aabbccdd` and `OU=0001-0001` is allowed on `/aabbccdd/0001-0001/#` and denied everywhere else.

### Example: layered rules

Specific rules are evaluated first, then fall through to a catch-all:

```yaml
rules:
  # Backend service: read all device namespaces, write commands
  - id: internal-backend
    match:
      o: internal
      ou: backend
    allow:
      subscribe: ["/+/+/#"]
      publish:   ["/+/+/cmd/#"]
    deny:
      publish:   ["/internal/#"]

  # Specific device with extra permissions
  - id: gateway-extra
    match:
      o: aabbccdd
      ou: 0001-0001
      cn: gateway-01
    allow:
      publish:
        - "/{o}/{ou}/#"
        - "/gateway/status"
      subscribe:
        - "/{o}/{ou}/#"

  # All other devices: own namespace only
  - id: device-own-namespace
    allow:
      publish:   ["/{o}/{ou}/#"]
      subscribe: ["/{o}/{ou}/#"]
```

## Integrating with EMQX

### 1. Configure the mTLS listener

In `emqx.conf`, ensure the MQTT/TLS listener requires a client certificate:

```hocon
listeners.ssl.default {
  bind = "0.0.0.0:8883"
  ssl_options {
    cacertfile           = "/etc/emqx/certs/ca-chain.pem"
    certfile             = "/etc/emqx/certs/server.crt"
    keyfile              = "/etc/emqx/certs/server.key"
    verify               = verify_peer
    fail_if_no_peer_cert = true
  }
}
```

### 2. Add the HTTP authorization source

Add or include `authorization.conf` in your EMQX configuration. The full reference file is provided at `emqx_config_example/authorization.conf`.

Key section:

```hocon
authorization {
  no_match    = deny
  deny_action = disconnect

  cache {
    enable   = true
    max_size = 32
    ttl      = 1m
  }

  sources = [
    {
      type    = http
      enable  = true
      url     = "https://127.0.0.1:7777/mqtt/authz"
      method  = post
      headers { "Content-Type" = "application/json" }

      body {
        username = "${username}"
        clientid = "${clientid}"
        peerhost = "${peerhost}"
        topic    = "${topic}"
        action   = "${action}"
        cert_dn  = "${cert_subject}"
        cert_cn  = "${cert_common_name}"
      }

      # mTLS: EMQX presents its own certificate to the agent
      ssl {
        enable   = true
        verify   = verify_peer
        cacertfile = "/etc/emqx/certs/ca-chain.pem"
        certfile   = "/etc/emqx/certs/emqx-client.crt"
        keyfile    = "/etc/emqx/certs/emqx-client.key"
      }

      request_timeout = 5s
      pool_size       = 8
    }
  ]
}
```

> **Note:** The `url` must use `https://` because the agent only opens a TLS socket. EMQX must present a client certificate signed by the same CA configured in the agent's `SSL_CA`.

### 3. Apply the configuration

```bash
emqx ctl conf reload
```

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/mqtt/authz` | Authorization endpoint called by EMQX |
| `GET` | `/health` | Returns `204 No Content` |
| `POST` | `/admin/reload` | Reloads `rules.yaml` without restart; requires `Authorization: Bearer <token>` |

## Debugging

Set `LOG_LEVEL=DEBUG` (update the supervisor conf and `supervisorctl reload`) to log every incoming request and rule decision:

```
[DEBUG] POST /mqtt/authz
[DEBUG] request action=publish topic=/aabbccdd/0001-0001/temp client=dev1 peerhost=10.0.0.5 cert_subject=CN=dev1,OU=0001-0001,O=aabbccdd cert_cn=dev1
[DEBUG] payload {"username":"dev1",...}
[ALLOW] rule=device-own-namespace o=aabbccdd ou=0001-0001 cn=dev1 topic=/aabbccdd/0001-0001/temp action=publish matched_allow=/{o}/{ou}/#
```

## Testing

A smoke-test script is included. It connects to the broker using the provided client certificate, extracts `O` and `OU` automatically, and verifies allow/deny for publish and subscribe:

```bash
./test-authz.sh
```

Requires `mosquitto-clients` and `openssl`. Certificate files are expected at `ssl/consumer.pub` and `ssl/consumer.key`.
