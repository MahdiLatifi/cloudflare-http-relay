# Cloudflare HTTP Relay

An authenticated HTTP relay running on [Cloudflare Workers](https://developers.cloudflare.com/workers/). It forwards outbound HTTP requests on behalf of clients that can't (or shouldn't) call external APIs directly — with Bearer-token authentication, SSRF protection, request validation, rate limiting, and configurable size/timeout limits.

Think of it as a hardened single-endpoint proxy: clients `POST` a JSON envelope describing the upstream request, and the relay performs it and returns a sanitized response.

```
Client ──▶ POST /proxy (JSON envelope) ──▶ Relay Worker ──▶ https://target.example.com
   ▲                                                                         │
   └────────────────── sanitized response ◀──────────────────────────────────┘
```

## Features

- **Authentication** — Bearer token checked in constant time against a `SECRET`; no token, no proxying.
- **SSRF protection** — blocks private/loopback/link-local IPv4 & IPv6 (including hex/octal/decimal-obfuscated forms), internal hostnames, URL userinfo, and non-HTTP(S) schemes. Optional target-host allowlist.
- **Request validation** — strict JSON envelope; method allowlist; header and body sanitization; hop-by-hop and proxy-identifying headers stripped.
- **Rate limiting** — fixed-window limit per credential (default 100 requests/minute).
- **Configurable limits** — max body size (default 1 MiB), default and max timeout (hard cap 30 s, respecting Workers' limits).
- **Safe responses** — only an allowlist of response headers is forwarded back; `x-proxy-request-id` and `x-proxy-target-status` added for tracing.
- **Structured JSON logs** — one line per request for observability.
- **Zero dependencies** — a single `worker.js` file, no build step.

## Endpoints

| Method | Path       | Description                          |
| ------ | ---------- | ------------------------------------ |
| `GET`  | `/healthz` | Health check. Returns `200 ok`.      |
| `POST` | `/proxy`   | Relay a request to the target URL.   |

Anything else returns `404 NOT_FOUND`. `/proxy` only accepts `POST`.

## Authentication

All `/proxy` requests must include the relay secret as a Bearer token:

```
Authorization: Bearer <SECRET>
```

The secret is configured via the `SECRET` environment variable (minimum 16 characters — shorter secrets make the relay refuse everything). Comparison is done in constant time to avoid timing attacks.

## Request envelope

`POST /proxy` with a JSON body:

```json
{
  "url": "https://api.example.com/v1/users",
  "method": "POST",
  "params": { "page": 2 },
  "headers": { "accept": "application/json" },
  "json": { "name": "Ada" },
  "timeout_ms": 10000
}
```

| Field        | Type            | Default | Description                                                                                              |
| ------------ | --------------- | ------- | -------------------------------------------------------------------------------------------------------- |
| `url`        | string          | —       | **Required.** Target URL. Only `http:` / `https:`; no embedded userinfo (`user:pass@`).                  |
| `method`     | string          | `GET`   | One of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`.                                        |
| `params`     | object          | —       | Query parameters appended to the target URL. Non-string values are JSON-encoded.                          |
| `headers`    | object          | —       | Outbound headers. Restricted/reserved headers are stripped (see below).                                   |
| `json`       | any             | —       | Serializes as the request body with `content-type: application/json`. Mutually exclusive with the others. |
| `data`       | object          | —       | Serializes as `application/x-www-form-urlencoded`.                                                        |
| `content`    | string          | —       | Raw request body sent as-is.                                                                              |
| `basic_auth` | object          | —       | `{ "username": "...", "password": "..." }` — sends a `Basic` `Authorization` header upstream.             |
| `timeout_ms` | number          | `20000` | Per-request timeout in ms. Clamped to `MAX_TIMEOUT_MS` (hard cap 30 000).                                 |

**Body precedence:** `json` → `data` → `content` (first defined wins).

### Header handling

Outbound headers are sanitized: hop-by-hop headers (`connection`, `transfer-encoding`, `upgrade`, …) and proxy-identifying headers (`authorization`, `host`, `x-forwarded-*`, `cf-*`, `x-real-ip`, …) are always stripped. Headers containing control characters or exceeding 8 KiB are dropped. `basic_auth` re-adds an `Authorization` header after stripping.

Response headers are filtered to a safe allowlist: `content-type`, `content-language`, `content-disposition`, `cache-control`, `etag`, `last-modified`, `expires`, `date`, `vary`, `retry-after`.

### Response

The relay returns the upstream status code and body, plus:

| Header                 | Meaning                              |
| ---------------------- | ------------------------------------ |
| `x-proxy-request-id`   | Unique ID for tracing/log correlation |
| `x-proxy-target-status`| The actual upstream status code       |

> **Note:** redirects (`3xx`) are **not** followed — they're returned to the caller as-is (`redirect: "manual"`). Follow them client-side if needed. Response bodies are buffered in memory (not streamed), so keep `MAX_BODY_SIZE` sane.

### Error format

All errors are JSON:

```json
{
  "error": {
    "code": "TARGET_FORBIDDEN",
    "message": "Target resolves to a private/internal address",
    "request_id": "b1c0…"
  }
}
```

| Status | Code                        | When                                                        |
| ------ | --------------------------- | ----------------------------------------------------------- |
| 400    | `BAD_REQUEST`               | Invalid envelope, method, or field types                     |
| 400    | `BAD_URL`                   | Malformed URL, non-HTTP(S) scheme, or embedded userinfo      |
| 401    | `UNAUTHORIZED`              | Missing/wrong Bearer token                                   |
| 403    | `TARGET_FORBIDDEN`          | SSRF check failed (private IP, internal hostname, or host not in `ALLOWED_TARGET_HOSTS`) |
| 404    | `NOT_FOUND`                 | Unknown path                                                 |
| 405    | `METHOD_NOT_ALLOWED`        | `/proxy` without `POST`                                      |
| 413    | `BODY_TOO_LARGE`            | Envelope or outbound body exceeds `MAX_BODY_SIZE`            |
| 429    | `RATE_LIMITED`              | Rate limit exceeded (`retry-after` header included)          |
| 502    | `UPSTREAM_ERROR`            | Target unreachable or response unreadable                    |
| 504    | `TIMEOUT`                   | Target did not respond within the timeout                    |

## Configuration (environment variables)

| Variable               | Default   | Description                                                                                       |
| ---------------------- | --------- | -------------------------------------------------------------------------------------------------- |
| `SECRET`               | —         | **Required.** Bearer token for `/proxy`. Must be ≥ 16 characters. Treat as a secret (not plain var). |
| `ALLOWED_TARGET_HOSTS` | *(all)*   | Comma-separated hostname allowlist. Unset = any non-private public host. Exact-match (no wildcards). |
| `RATE_LIMIT_ENABLED`   | `true`    | Set `0`/`false` to disable rate limiting.                                                          |
| `RATE_LIMIT_RPM`       | `100`     | Requests per minute per credential (fixed 60 s window).                                            |
| `MAX_BODY_SIZE`        | `1048576` | Max envelope and outbound body size in bytes (1 MiB).                                              |
| `DEFAULT_TIMEOUT_MS`   | `20000`   | Timeout when the envelope has no `timeout_ms`.                                                     |
| `MAX_TIMEOUT_MS`       | `30000`   | Upper bound for `timeout_ms`; hard-capped at 30 s.                                                 |

> The rate limiter is in-memory and **per Worker isolate** — it's approximate under Cloudflare's multi-isolate scaling and resets on deploys. For strict global limits, front it with [Cloudflare WAF rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) or a durable backend.

## Examples

### curl

```bash
RELAY="https://http-relay.<your-subdomain>.workers.dev"
SECRET="your-super-secret-token-here"

# Health check
curl "$RELAY/healthz"

# GET with query params
curl -X POST "$RELAY/proxy" \
  -H "Authorization: Bearer $SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.github.com/repos/cloudflare/workers",
    "method": "GET",
    "params": { "per_page": 1 },
    "headers": { "accept": "application/vnd.github+json" }
  }'

# POST JSON with Basic auth upstream
curl -X POST "$RELAY/proxy" \
  -H "Authorization: Bearer $SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.example.com/v1/login",
    "method": "POST",
    "json": { "grant_type": "client_credentials" },
    "basic_auth": { "username": "id", "password": "secret" },
    "timeout_ms": 8000
  }'
```

### Python

```python
import requests

RELAY = "https://http-relay.<your-subdomain>.workers.dev/proxy"
SECRET = "your-super-secret-token-here"

resp = requests.post(
    RELAY,
    headers={
        "Authorization": f"Bearer {SECRET}",
        "Content-Type": "application/json",
    },
    json={
        "url": "https://api.github.com/repos/cloudflare/workers",
        "method": "GET",
        "headers": {"accept": "application/vnd.github+json"},
        "timeout_ms": 10000,
    },
)
print(resp.status_code, resp.headers.get("x-proxy-target-status"), resp.text)
```

### JavaScript / TypeScript

```ts
const relay = await fetch("https://http-relay.<your-subdomain>.workers.dev/proxy", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${SECRET}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    url: "https://api.example.com/v1/items",
    method: "POST",
    json: { name: "Ada" },
    timeout_ms: 10000,
  }),
});

const upstreamStatus = relay.headers.get("x-proxy-target-status");
const data = await relay.json();
```

---

## Deployment

Two options: **manual** (dashboard, no tooling) or **Wrangler** (CLI, recommended).

### Option 1 — Manual deploy (Cloudflare dashboard)

1. **Create the Worker**
   - Log in to the [Cloudflare dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **Create** → **Create Worker**.
   - Pick a name (e.g. `http-relay`) → **Deploy** the starter, then **Edit code**.

2. **Paste the code**
   - Delete the starter code, paste the full contents of [`worker.js`](./worker.js), and click **Deploy**.

3. **Set the `SECRET` variable**
   - Worker → **Settings** → **Variables and Secrets** → **Add**:
     - Type: **Secret**, Name: `SECRET`, Value: your token (≥ 16 chars).
   - **Deploy** to apply.

4. **(Optional) Add more variables**
   - Same place — e.g. `ALLOWED_TARGET_HOSTS` = `api.github.com,api.openai.com` (type: *Text*), `RATE_LIMIT_RPM` = `60`. Deploy after each change.

5. **Test it**

   ```bash
   curl "https://http-relay.<your-subdomain>.workers.dev/healthz"   # → ok
   ```

   Then run one of the [examples](#examples) against `/proxy`.

6. **(Optional) Custom domain** — Worker → **Settings** → **Domains & Routes** → **Add** → Custom domain.

> ⚠️ Don't put the real `SECRET` in the code or in a plain-text variable — use type **Secret** so it's encrypted and hidden after saving.

### Option 2 — Deploy with Wrangler (recommended)

Requires Node.js ≥ 16 and npm.

1. **Install Wrangler**

   ```bash
   npm install -g wrangler
   # or use npx per-command: npx wrangler <cmd>
   ```

2. **Log in**

   ```bash
   wrangler login
   ```

3. **Create `wrangler.toml`** in the repo root:

   ```toml
   name = "http-relay"
   main = "worker.js"
   compatibility_date = "2024-09-23"

   # Plain-text variables (non-secret) — keep secrets out of this file
   [vars]
   # ALLOWED_TARGET_HOSTS = "api.github.com,api.openai.com"
   # RATE_LIMIT_ENABLED = "true"
   # RATE_LIMIT_RPM = "100"
   # MAX_BODY_SIZE = "1048576"
   # DEFAULT_TIMEOUT_MS = "20000"
   # MAX_TIMEOUT_MS = "30000"
   ```

4. **Set the secret**

   ```bash
   wrangler secret put SECRET
   # paste your token (≥ 16 chars) when prompted
   ```

5. **Deploy**

   ```bash
   wrangler deploy
   ```

   Wrangler prints the `workers.dev` URL, e.g. `https://http-relay.<your-subdomain>.workers.dev`.

6. **Test**

   ```bash
   curl "https://http-relay.<your-subdomain>.workers.dev/healthz"   # → ok

   curl -X POST "https://http-relay.<your-subdomain>.workers.dev/proxy" \
     -H "Authorization: Bearer $SECRET" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://httpbin.org/get", "method": "GET"}'
   ```

7. **(Optional) Custom domain** — add to `wrangler.toml` and redeploy:

   ```toml
   routes = [
     { pattern = "relay.example.com", custom_domain = true }
   ]
   ```

Useful commands:

| Command                      | Purpose                                   |
| ---------------------------- | ----------------------------------------- |
| `wrangler dev`               | Local dev server (note: SSRF checks assume production network semantics) |
| `wrangler deploy`            | Deploy to production                      |
| `wrangler secret list`       | List configured secret names              |
| `wrangler tail`              | Stream live logs (the relay's JSON log lines) |
| `wrangler delete`            | Remove the Worker                         |

---

## Security notes

- **SSRF defenses** — the relay blocks loopback/private/link-local ranges (IPv4: `0.0.0.0/8`, `10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`, `100.64/10`, multicast `224/4`; IPv6: `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`, IPv4-mapped `::ffff:…`), internal-looking hostnames (`localhost`, `*.local`, `*.internal`, `*.corp`, …, and any single-label host), and obfuscated IPv4 forms (`0x7f.1`, `2130706433`, octal, shortened `a.b.c`) so they can't sneak past the checks. Checks are name-based; on Workers there is no internal network to pivot into, but the checks also protect non-Workers deployments of the same code.
- **Lock down targets** — set `ALLOWED_TARGET_HOSTS` in production so the relay can only reach the APIs you intend. This is the single most valuable hardening step.
- **No response streaming** — bodies are buffered; very large responses increase memory pressure. Keep `MAX_BODY_SIZE` and target APIs reasonable.
- **Secrets** — rotate `SECRET` with `wrangler secret put SECRET` (or a new dashboard Secret); every credential change requires redeploying nothing else.

## Logging

Each request emits one structured JSON line (visible in `wrangler tail` or **Logs** in the dashboard):

```json
{"ts":"2026-09-03T12:00:00.000Z","request_id":"…","target_host":"api.example.com","target_method":"GET","status":200,"duration_ms":123,"outcome":"ok"}
```

Failures log `outcome: "error"` with an `error_code` (`UNAUTHORIZED`, `RATE_LIMITED`, `SSRF_PRIVATE`, `SSRF_INTERNAL`, `HOST_NOT_ALLOWED`, `TIMEOUT`, `UPSTREAM_ERROR`, …). No request bodies, secrets, or URLs are logged — only the hostname.

## License

[MIT](./LICENSE) © mahdi latifi
