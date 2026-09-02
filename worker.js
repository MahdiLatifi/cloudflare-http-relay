/**
 * Cloudflare HTTP Relay
 *
 * An authenticated HTTP relay running on Cloudflare Workers to route outbound
 * HTTP requests with SSRF protections, request validation, rate limiting,
 * and configurable limits.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MAX_BODY = 1024 * 1024; // 1 MiB
const DEFAULT_TIMEOUT_MS = 20_000;
const HARD_MAX_TIMEOUT_MS = 30_000;

const ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const STRIPPED_OUTBOUND_HEADERS = new Set([
  "authorization",
  "host",
  "content-length",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-real-ip",
  "true-client-ip",
  "cdn-loop",
  "x-proxy-request-id",
  ...HOP_BY_HOP,
]);

const SAFE_RESPONSE_HEADERS = new Set([
  "content-type",
  "content-language",
  "content-disposition",
  "cache-control",
  "etag",
  "last-modified",
  "expires",
  "date",
  "vary",
  "retry-after",
]);

const INTERNAL_HOSTNAME_PATTERNS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal",
]);

const INTERNAL_HOSTNAME_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".localdomain",
  ".home",
  ".lan",
  ".intranet",
  ".corp",
];

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function genRequestId() {
  try {
    return crypto.randomUUID();
  } catch {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);

    return Array.from(
      bytes,
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
  }
}

function envInt(env, key, fallback) {
  const value = env[key];

  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);

  return Number.isFinite(parsed) && parsed > 0
    ? parsed
    : fallback;
}

function envBool(env, key, fallback) {
  const value = env[key];

  if (value == null) {
    return fallback;
  }

  const normalized = String(value).toLowerCase();

  return (
    normalized === "1" ||
    normalized === "true" ||
    normalized === "yes"
  );
}

function getByteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function errorResponse(
  status,
  code,
  message,
  requestId,
  extraHeaders = {},
) {
  const body = {
    error: {
      code,
      message,
      request_id: requestId,
    },
  };

  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-proxy-request-id": requestId,
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

function isPrivateIpv4(ip) {
  if ((ip >>> 24) === 0) return true;        // 0.0.0.0/8
  if ((ip >>> 24) === 10) return true;       // 10.0.0.0/8
  if ((ip >>> 24) === 127) return true;      // 127.0.0.0/8
  if ((ip >>> 16) === 0xa9fe) return true;   // 169.254.0.0/16
  if ((ip >>> 20) === 0xac1) return true;    // 172.16.0.0/12
  if ((ip >>> 16) === 0xc0a8) return true;  // 192.168.0.0/16
  if ((ip >>> 22) === 0x190) return true;    // 100.64.0.0/10
  if ((ip >>> 28) === 0xe) return true;      // 224.0.0.0/4

  return false;
}

/**
 * Parses an IPv4 address using common inet_aton-style representations.
 *
 * Supports:
 * - a.b.c.d
 * - a.b.c
 * - a.b
 * - a
 * - decimal
 * - hexadecimal
 * - octal
 *
 * Returns the normalized unsigned 32-bit integer or null.
 */
function parseIpv4(value) {
  const parts = value.split(".");

  if (parts.length > 4) {
    return null;
  }

  let result = 0;

  for (let index = 0; index < parts.length; index++) {
    const part = parts[index];

    if (part.length === 0 || part.length > 8) {
      return null;
    }

    let number;

    if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
      number = Number.parseInt(part, 16);
    } else if (/^0[0-7]+$/.test(part)) {
      number = Number.parseInt(part.substring(1), 8);
    } else if (/^[0-9]+$/.test(part)) {
      number = Number.parseInt(part, 10);
    } else {
      return null;
    }

    if (!Number.isFinite(number) || number < 0) {
      return null;
    }

    const remainingParts = 4 - index - 1;
    const maxValue =
      remainingParts > 0
        ? 0xff
        : 0xffffffff;

    if (number > maxValue) {
      return null;
    }

    result += number * Math.pow(256, remainingParts);
  }

  if (result > 0xffffffff) {
    return null;
  }

  return result >>> 0;
}

function parseHexGroup(value) {
  if (
    value.length === 0 ||
    value.length > 4 ||
    !/^[0-9a-fA-F]+$/.test(value)
  ) {
    return null;
  }

  return Number.parseInt(value, 16);
}

/**
 * Parses an IPv6 address into exactly 8 16-bit groups.
 *
 * Supports:
 * - compressed IPv6 (::)
 * - bracketed IPv6
 * - IPv4-embedded IPv6
 *
 * Returns null for invalid input.
 */
function parseIpv6(value) {
  let str = value;

  if (str.startsWith("[") && str.endsWith("]")) {
    str = str.slice(1, -1);
  }

  if (!str) {
    return null;
  }

  // Convert an IPv4 suffix into two IPv6 groups.
  if (str.includes(".")) {
    const lastColon = str.lastIndexOf(":");

    if (lastColon === -1) {
      return null;
    }

    const ipv4Part = str.slice(lastColon + 1);
    const ipv4 = parseIpv4(ipv4Part);

    if (ipv4 === null) {
      return null;
    }

    const high = (ipv4 >>> 16) & 0xffff;
    const low = ipv4 & 0xffff;

    str = `${str.slice(0, lastColon)}:${high.toString(16)}:${low.toString(16)}`;
  }

  const doubleColonIndex = str.indexOf("::");

  let leftParts;
  let rightParts;

  if (doubleColonIndex !== -1) {
    // Only one "::" is valid.
    if (
      str.indexOf("::", doubleColonIndex + 2) !== -1
    ) {
      return null;
    }

    const left = str.slice(0, doubleColonIndex);
    const right = str.slice(doubleColonIndex + 2);

    leftParts = left ? left.split(":") : [];
    rightParts = right ? right.split(":") : [];

    // "::" must represent at least one group.
    if (leftParts.length + rightParts.length >= 8) {
      return null;
    }
  } else {
    const parts = str.split(":");

    if (parts.length !== 8) {
      return null;
    }

    leftParts = parts;
    rightParts = [];
  }

  const groups = new Array(8).fill(0);

  for (let index = 0; index < leftParts.length; index++) {
    const group = parseHexGroup(leftParts[index]);

    if (group === null) {
      return null;
    }

    groups[index] = group;
  }

  const rightStart = 8 - rightParts.length;

  for (let index = 0; index < rightParts.length; index++) {
    const group = parseHexGroup(rightParts[index]);

    if (group === null) {
      return null;
    }

    groups[rightStart + index] = group;
  }

  return groups;
}

function isPrivateIpv6(groups) {
  // Unspecified ::
  if (groups.every((group) => group === 0)) {
    return true;
  }

  // Loopback ::1
  if (
    groups.slice(0, 7).every((group) => group === 0) &&
    groups[7] === 1
  ) {
    return true;
  }

  // Unique local addresses fc00::/7
  if ((groups[0] & 0xfe00) === 0xfc00) {
    return true;
  }

  // Link-local fe80::/10
  if ((groups[0] & 0xffc0) === 0xfe80) {
    return true;
  }

  // Multicast ff00::/8
  if ((groups[0] & 0xff00) === 0xff00) {
    return true;
  }

  // IPv4-mapped IPv6 ::ffff:x.x.x.x
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const ipv4 =
      (((groups[6] << 16) | groups[7]) >>> 0);

    return isPrivateIpv4(ipv4);
  }

  return false;
}

function normalizeHostname(host) {
  let normalized = host
    .toLowerCase()
    .trim();

  if (
    normalized.startsWith("[") &&
    normalized.endsWith("]")
  ) {
    normalized = normalized.slice(1, -1);
  }

  // DNS absolute names may end with a trailing dot.
  normalized = normalized.replace(/\.+$/, "");

  return normalized;
}

function hostnameLooksInternal(host) {
  if (INTERNAL_HOSTNAME_PATTERNS.has(host)) {
    return true;
  }

  for (const suffix of INTERNAL_HOSTNAME_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return true;
    }
  }

  // Reject single-label hostnames.
  if (!host.includes(".")) {
    return true;
  }

  return false;
}

function validateTargetHost(host) {
  const normalizedHost = normalizeHostname(host);

  if (!normalizedHost) {
    return "internal";
  }

  // IPv6
  if (normalizedHost.includes(":")) {
    const ipv6 = parseIpv6(normalizedHost);

    if (!ipv6) {
      return "internal";
    }

    return isPrivateIpv6(ipv6)
      ? "private"
      : "ok";
  }

  // IPv4
  if (
    /^(\d+|0x[0-9a-f]+|0[0-7]+)(\.(\d+|0x[0-9a-f]+|0[0-7]+)){0,3}$/i.test(
      normalizedHost,
    )
  ) {
    const ipv4 = parseIpv4(normalizedHost);

    if (ipv4 !== null) {
      return isPrivateIpv4(ipv4)
        ? "private"
        : "ok";
    }
  }

  return hostnameLooksInternal(normalizedHost)
    ? "internal"
    : "ok";
}

function getAllowedHosts(env) {
  const raw = env.ALLOWED_TARGET_HOSTS?.trim();

  if (!raw) {
    return null;
  }

  return new Set(
    raw
      .split(",")
      .map((value) => normalizeHostname(value))
      .filter(Boolean),
  );
}

// ---------------------------------------------------------------------------
// Authentication & Rate Limiting
// ---------------------------------------------------------------------------

function authenticate(req, env) {
  const expected = env.SECRET;

  if (
    typeof expected !== "string" ||
    expected.length < 16
  ) {
    return false;
  }

  const authorization =
    req.headers.get("authorization") || "";

  const match =
    /^Bearer\s+(.+)$/i.exec(authorization);

  if (!match) {
    return false;
  }

  const token = match[1].trim();

  if (token.length !== expected.length) {
    return false;
  }

  let difference = 0;

  for (let index = 0; index < expected.length; index++) {
    difference |=
      token.charCodeAt(index) ^
      expected.charCodeAt(index);
  }

  return difference === 0;
}

// In-memory fixed-window rate limiter per authorization credential.
const rateMap = new Map();

function rateLimitCheck(clientId, rpm, now) {
  const windowMs = 60_000;
  const bucket = rateMap.get(clientId);

  if (
    !bucket ||
    now - bucket.windowStart >= windowMs
  ) {
    rateMap.set(clientId, {
      count: 1,
      windowStart: now,
    });

    return {
      allowed: true,
      retryAfterMs: 0,
    };
  }

  if (bucket.count >= rpm) {
    return {
      allowed: false,
      retryAfterMs:
        bucket.windowStart +
        windowMs -
        now,
    };
  }

  bucket.count += 1;

  return {
    allowed: true,
    retryAfterMs: 0,
  };
}

function getClientId(req) {
  const authorization =
    req.headers.get("authorization") || "";

  return `relay:${authorization}`;
}

// ---------------------------------------------------------------------------
// Header / Body Processing
// ---------------------------------------------------------------------------

function sanitizeOutboundHeaders(input) {
  const output = {};

  if (!isPlainObject(input)) {
    return output;
  }

  for (const [key, value] of Object.entries(input)) {
    if (
      typeof key !== "string" ||
      typeof value !== "string"
    ) {
      continue;
    }

    const normalizedKey =
      key.toLowerCase().trim();

    if (
      !normalizedKey ||
      normalizedKey.length > 64
    ) {
      continue;
    }

    if (
      STRIPPED_OUTBOUND_HEADERS.has(normalizedKey)
    ) {
      continue;
    }

    if (/[\r\n]/.test(value)) {
      continue;
    }

    if (/[\x00-\x1f\x7f]/.test(value)) {
      continue;
    }

    if (getByteLength(value) > 8192) {
      continue;
    }

    output[normalizedKey] = value;
  }

  return output;
}

function filterResponseHeaders(headers) {
  const output = new Headers();

  for (const [key, value] of headers.entries()) {
    const normalizedKey =
      key.toLowerCase();

    if (SAFE_RESPONSE_HEADERS.has(normalizedKey)) {
      output.set(normalizedKey, value);
    }
  }

  return output;
}

function buildBodyAndHeaders(payload) {
  const headers =
    sanitizeOutboundHeaders(payload.headers);

  let body = null;
  let size = 0;

  // 1. JSON body
  if (
    payload.json !== undefined &&
    payload.json !== null
  ) {
    body = JSON.stringify(payload.json);
    size = getByteLength(body);

    if (!headers["content-type"]) {
      headers["content-type"] =
        "application/json";
    }
  }

  // 2. Form data
  else if (
    payload.data !== undefined &&
    payload.data !== null
  ) {
    if (!isPlainObject(payload.data)) {
      throw new TypeError(
        "data must be an object",
      );
    }

    const form = new URLSearchParams();

    for (const [key, value] of Object.entries(
      payload.data,
    )) {
      form.append(
        key,
        typeof value === "string"
          ? value
          : JSON.stringify(value),
      );
    }

    body = form.toString();
    size = getByteLength(body);

    if (!headers["content-type"]) {
      headers["content-type"] =
        "application/x-www-form-urlencoded";
    }
  }

  // 3. Raw string body
  else if (
    payload.content !== undefined &&
    payload.content !== null
  ) {
    if (typeof payload.content !== "string") {
      throw new TypeError(
        "content must be a string",
      );
    }

    body = payload.content;
    size = getByteLength(body);
  }

  // 4. Basic authentication
  if (payload.basic_auth !== undefined) {
    if (!isPlainObject(payload.basic_auth)) {
      throw new TypeError(
        "basic_auth must be an object",
      );
    }

    const username =
      payload.basic_auth.username;
    const password =
      payload.basic_auth.password;

    if (
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      throw new TypeError(
        "basic_auth.username and basic_auth.password must be strings",
      );
    }

    try {
      const token =
        btoa(`${username}:${password}`);

      headers["authorization"] =
        `Basic ${token}`;
    } catch {
      throw new TypeError(
        "basic_auth contains unsupported characters",
      );
    }
  }

  return {
    body,
    size,
    headers,
  };
}

function safeLog(entry) {
  console.log(JSON.stringify(entry));
}

// ---------------------------------------------------------------------------
// Main Worker Handler
// ---------------------------------------------------------------------------

export default {
  async fetch(req, env, _ctx) {
    const requestId = genRequestId();
    const startedAt = Date.now();

    const requestUrl = new URL(req.url);

    // Health check
    if (requestUrl.pathname === "/healthz") {
      return new Response("ok", {
        status: 200,
        headers: {
          "x-proxy-request-id": requestId,
          "cache-control": "no-store",
        },
      });
    }

    // Proxy endpoint
    if (requestUrl.pathname !== "/proxy") {
      return errorResponse(
        404,
        "NOT_FOUND",
        "Unknown endpoint",
        requestId,
      );
    }

    if (req.method !== "POST") {
      return errorResponse(
        405,
        "METHOD_NOT_ALLOWED",
        "Use POST /proxy",
        requestId,
        { allow: "POST" },
      );
    }

    // Authentication
    if (!authenticate(req, env)) {
      safeLog({
        ts: new Date().toISOString(),
        request_id: requestId,
        status: 401,
        outcome: "error",
        error_code: "UNAUTHORIZED",
      });

      return errorResponse(
        401,
        "UNAUTHORIZED",
        "Invalid proxy credentials",
        requestId,
      );
    }

    // Rate limiting
    if (
      envBool(
        env,
        "RATE_LIMIT_ENABLED",
        true,
      )
    ) {
      const rpm = envInt(
        env,
        "RATE_LIMIT_RPM",
        100,
      );

      const result = rateLimitCheck(
        getClientId(req),
        rpm,
        Date.now(),
      );

      if (!result.allowed) {
        const retryAfterSec =
          Math.max(
            1,
            Math.ceil(
              result.retryAfterMs / 1000,
            ),
          );

        safeLog({
          ts: new Date().toISOString(),
          request_id: requestId,
          status: 429,
          outcome: "error",
          error_code: "RATE_LIMITED",
        });

        return errorResponse(
          429,
          "RATE_LIMITED",
          "Rate limit exceeded",
          requestId,
          {
            "retry-after":
              String(retryAfterSec),
          },
        );
      }
    }

    // Request body limit
    const maxBody = envInt(
      env,
      "MAX_BODY_SIZE",
      DEFAULT_MAX_BODY,
    );

    let rawRequestBody;

    try {
      rawRequestBody =
        await req.arrayBuffer();
    } catch {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "Unable to read request body",
        requestId,
      );
    }

    if (
      rawRequestBody.byteLength >
      maxBody
    ) {
      return errorResponse(
        413,
        "BODY_TOO_LARGE",
        `Request body exceeds ${maxBody} bytes`,
        requestId,
      );
    }

    // Parse JSON envelope
    let payload;

    try {
      payload = JSON.parse(
        new TextDecoder().decode(
          rawRequestBody,
        ),
      );
    } catch {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "Invalid JSON envelope",
        requestId,
      );
    }

    if (
      !isPlainObject(payload)
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "Envelope must be a JSON object",
        requestId,
      );
    }

    // Target URL
    if (
      typeof payload.url !== "string" ||
      !payload.url
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "url is required",
        requestId,
      );
    }

    // HTTP method
    const method = String(
      payload.method || "GET",
    ).toUpperCase();

    if (
      !/^[A-Z]+$/.test(method) ||
      method.length > 16
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "Invalid method",
        requestId,
      );
    }

    if (!ALLOWED_METHODS.has(method)) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "Method not supported",
        requestId,
      );
    }

    // Validate structured fields
    if (
      payload.params !== undefined &&
      !isPlainObject(payload.params)
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "params must be an object",
        requestId,
      );
    }

    if (
      payload.headers !== undefined &&
      !isPlainObject(payload.headers)
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "headers must be an object",
        requestId,
      );
    }

    if (
      payload.json !== undefined &&
      payload.json === null
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "json cannot be null",
        requestId,
      );
    }

    if (
      payload.data !== undefined &&
      payload.data !== null &&
      !isPlainObject(payload.data)
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "data must be an object",
        requestId,
      );
    }

    if (
      payload.content !== undefined &&
      payload.content !== null &&
      typeof payload.content !== "string"
    ) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        "content must be a string",
        requestId,
      );
    }

    // Target URL parsing
    let targetUrl;

    try {
      targetUrl = new URL(payload.url);
    } catch {
      return errorResponse(
        400,
        "BAD_URL",
        "Invalid target URL",
        requestId,
      );
    }

    if (
      targetUrl.protocol !== "http:" &&
      targetUrl.protocol !== "https:"
    ) {
      return errorResponse(
        400,
        "BAD_URL",
        "Only http/https allowed",
        requestId,
      );
    }

    if (
      targetUrl.username ||
      targetUrl.password
    ) {
      return errorResponse(
        400,
        "BAD_URL",
        "URL userinfo not allowed",
        requestId,
      );
    }

    // Query parameters
    if (payload.params) {
      for (
        const [key, value] of Object.entries(
          payload.params,
        )
      ) {
        targetUrl.searchParams.append(
          key,
          typeof value === "string"
            ? value
            : JSON.stringify(value),
        );
      }
    }

    // SSRF protection
    const host =
      normalizeHostname(
        targetUrl.hostname,
      );

    const hostVerdict =
      validateTargetHost(host);

    if (hostVerdict === "private") {
      safeLog({
        ts: new Date().toISOString(),
        request_id: requestId,
        target_host: host,
        status: 403,
        outcome: "error",
        error_code: "SSRF_PRIVATE",
      });

      return errorResponse(
        403,
        "TARGET_FORBIDDEN",
        "Target resolves to a private/internal address",
        requestId,
      );
    }

    if (hostVerdict === "internal") {
      safeLog({
        ts: new Date().toISOString(),
        request_id: requestId,
        target_host: host,
        status: 403,
        outcome: "error",
        error_code: "SSRF_INTERNAL",
      });

      return errorResponse(
        403,
        "TARGET_FORBIDDEN",
        "Internal hostnames are not allowed",
        requestId,
      );
    }

    // Target host allowlist
    const allowed =
      getAllowedHosts(env);

    if (
      allowed &&
      !allowed.has(host)
    ) {
      safeLog({
        ts: new Date().toISOString(),
        request_id: requestId,
        target_host: host,
        status: 403,
        outcome: "error",
        error_code: "HOST_NOT_ALLOWED",
      });

      return errorResponse(
        403,
        "TARGET_FORBIDDEN",
        `Host not in allowlist: ${host}`,
        requestId,
      );
    }

    // Build outbound body and headers
    let outbound;

    try {
      outbound =
        buildBodyAndHeaders(payload);
    } catch (error) {
      return errorResponse(
        400,
        "BAD_REQUEST",
        error instanceof Error
          ? error.message
          : "Invalid request payload",
        requestId,
      );
    }

    const {
      body: outboundBody,
      size: outboundBodySize,
      headers: outboundHeaders,
    } = outbound;

    if (
      outboundBodySize >
      maxBody
    ) {
      return errorResponse(
        413,
        "BODY_TOO_LARGE",
        `Outbound body exceeds ${maxBody} bytes`,
        requestId,
      );
    }

    // Timeout
    const defaultTimeout =
      envInt(
        env,
        "DEFAULT_TIMEOUT_MS",
        DEFAULT_TIMEOUT_MS,
      );

    const hardMax =
      Math.min(
        envInt(
          env,
          "MAX_TIMEOUT_MS",
          HARD_MAX_TIMEOUT_MS,
        ),
        HARD_MAX_TIMEOUT_MS,
      );

    const requestedTimeout =
      typeof payload.timeout_ms === "number" &&
      Number.isFinite(payload.timeout_ms) &&
      payload.timeout_ms > 0
        ? Math.min(
            payload.timeout_ms,
            hardMax,
          )
        : Math.min(
            defaultTimeout,
            hardMax,
          );

    const abortController =
      new AbortController();

    const timer = setTimeout(
      () => abortController.abort(),
      requestedTimeout,
    );

    // Upstream request
    let upstream;

    try {
      const fetchInit = {
        method,
        headers: outboundHeaders,
        redirect: "manual",
        signal: abortController.signal,
      };

      if (
        method !== "GET" &&
        method !== "HEAD" &&
        outboundBody !== null
      ) {
        fetchInit.body = outboundBody;
      }

      upstream = await fetch(
        targetUrl.toString(),
        fetchInit,
      );
    } catch {
      const timedOut =
        abortController.signal.aborted;

      const code = timedOut
        ? "TIMEOUT"
        : "UPSTREAM_ERROR";

      const status = timedOut
        ? 504
        : 502;

      safeLog({
        ts: new Date().toISOString(),
        request_id: requestId,
        target_host: host,
        status,
        outcome: "error",
        error_code: code,
      });

      return errorResponse(
        status,
        code,
        timedOut
          ? "Target timed out"
          : "Failed to reach target",
        requestId,
      );
    } finally {
      clearTimeout(timer);
    }

    // Response body
    //
    // Intentionally buffered for a simple API-relay design.
    // Large responses can increase Worker memory usage.
    let responseBody = null;

    try {
      if (method !== "HEAD") {
        responseBody =
          await upstream.arrayBuffer();
      }
    } catch {
      safeLog({
        ts: new Date().toISOString(),
        request_id: requestId,
        target_host: host,
        status: 502,
        outcome: "error",
        error_code: "UPSTREAM_RESPONSE_READ_ERROR",
      });

      return errorResponse(
        502,
        "UPSTREAM_ERROR",
        "Failed to read target response",
        requestId,
      );
    }

    const filteredHeaders =
      filterResponseHeaders(
        upstream.headers,
      );

    const responseHeaders = {
      "x-proxy-request-id":
        requestId,
      "x-proxy-target-status":
        String(upstream.status),
      "cache-control":
        "no-store",
    };

    for (
      const [key, value]
      of filteredHeaders.entries()
    ) {
      responseHeaders[key] = value;
    }

    safeLog({
      ts: new Date().toISOString(),
      request_id: requestId,
      target_host: host,
      target_method: method,
      status: upstream.status,
      duration_ms:
        Date.now() - startedAt,
      outcome: "ok",
    });

    return new Response(
      responseBody,
      {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders,
      },
    );
  },
};