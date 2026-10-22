"use strict";

// Outbound URL guard.
//
// A server-side fetch of a caller-supplied URL is a Server-Side Request Forgery
// sink: without a guard it reaches loopback services, link-local metadata
// endpoints and the private network, and hands the caller the response body.
//
// This module is the only way this application performs an outbound request.
// It enforces, for the initial URL and for every redirect hop:
//   * https only, no embedded credentials, no non-default port
//   * the hostname must resolve to a public address
//   * loopback, link-local, private, CGNAT, multicast and unspecified addresses
//     are refused, in both IPv4 and IPv6 form (including IPv4-mapped, 6to4 and
//     Teredo encodings, which smuggle an IPv4 address inside an IPv6 literal)
//   * redirects are followed manually and re-validated on every hop

const dns = require("dns").promises;
const net = require("net");

const ALLOWED_PROTOCOL = "https:";
const ALLOWED_PORT = "443";
const MAX_REDIRECTS = 3;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 4096;
const MAX_URL_LENGTH = 2048;

class UrlGuardError extends Error {
  constructor(code) {
    super(code);
    this.name = "UrlGuardError";
    this.code = code;
  }
}

// Ranges that must never be reachable from a caller-supplied URL.
const BLOCKED_V4 = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (cloud metadata lives here)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved
];

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

function ipv4InCidr(ip, cidr, bits) {
  const addr = ipv4ToInt(ip);
  const base = ipv4ToInt(cidr);
  if (addr === null || base === null) return false;
  const size = 2 ** (32 - bits);
  return Math.floor(addr / size) === Math.floor(base / size);
}

/**
 * Expand an IPv6 literal into eight lowercase hextets.
 * @param {string} ip
 * @returns {string[]|null}
 */
function expandIpv6(ip) {
  let head = ip;
  let tailParts = [];
  const doubleColon = ip.indexOf("::");
  if (doubleColon !== -1) {
    head = ip.slice(0, doubleColon);
    tailParts = ip.slice(doubleColon + 2).split(":").filter((part) => part.length > 0);
  }
  const headParts = head.split(":").filter((part) => part.length > 0);
  const missing = 8 - headParts.length - tailParts.length;
  if (missing < 0) return null;
  const parts = [...headParts, ...new Array(missing).fill("0"), ...tailParts];
  if (parts.length !== 8) return null;
  const expanded = [];
  for (const part of parts) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
    expanded.push(part.toLowerCase().padStart(4, "0"));
  }
  return expanded;
}

/**
 * Build an IPv4 address from the two hextets that carry it.
 * @param {string} high
 * @param {string} low
 * @returns {string}
 */
function hextetsToIpv4(high, low) {
  const hi = Number.parseInt(high, 16);
  const lo = Number.parseInt(low, 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/**
 * Detect an IPv4 address embedded in an IPv6 literal and return it.
 *
 * The address may be spelled in several ways, and each spelling has its own
 * prefix:
 *   IPv4-mapped     ::ffff:a.b.c.d    -> 0:0:0:0:0:ffff:v4
 *   IPv4-compatible ::a.b.c.d         -> 0:0:0:0:0:0:v4
 *   IPv4-translated ::ffff:0:a.b.c.d  -> 0:0:0:0:ffff:0:v4
 *   NAT64           64:ff9b::a.b.c.d -> 64:ff9b:0:0:0:0:v4
 *   NAT64 local     64:ff9b:1::a.b.c.d
 * A blocklist that only recognises the dotted spelling misses the others, and
 * the WHATWG URL parser normalises the literal to hex before it is ever seen.
 * @param {string[]} parts eight expanded hextets
 * @returns {string|null} the embedded IPv4 address
 */
function embeddedIpv4(parts) {
  const isZero = (index) => parts[index] === "0000";
  const allZero = (from, to) => {
    for (let i = from; i <= to; i += 1) {
      if (!isZero(i)) return false;
    }
    return true;
  };

  // The IPv4-embedding prefixes all live in the ::/64 and ::ffff:0:0:0/80
  // space, and in each of them the IPv4 address occupies the last two hextets:
  //   0:0:0:0:0:ffff:v4   IPv4-mapped
  //   0:0:0:0:0:0:v4      IPv4-compatible
  //   0:0:0:0:ffff:0:v4   IPv4-translated
  //   0:0:0:ffff:0:0:v4   IPv4-translated with a longer prefix
  // The rule is stated generally rather than per prefix, so a less common
  // spelling of the same idea cannot slip past.
  if (allZero(0, 3) || (allZero(0, 2) && parts[3] === "ffff")) {
    return hextetsToIpv4(parts[6], parts[7]);
  }

  // NAT64: the well-known prefix 64:ff9b::/96 and the local-use 64:ff9b:1::/48.
  if (parts[0] === "0064" && parts[1] === "ff9b") {
    if (allZero(2, 5) || (parts[2] === "0001" && allZero(3, 5))) {
      return hextetsToIpv4(parts[6], parts[7]);
    }
  }
  return null;
}

/**
 * @param {string} address an IP literal
 * @returns {boolean} true when the address is not publicly routable
 */
function isBlockedAddress(address) {
  if (typeof address !== "string" || address.length === 0) return true;
  const ip = address.toLowerCase().split("%")[0];

  if (net.isIPv4(ip)) {
    return BLOCKED_V4.some(([cidr, bits]) => ipv4InCidr(ip, cidr, bits));
  }
  if (!net.isIPv6(ip)) return true;

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) forms carry an
  // embedded IPv4 address. The address may be written in dotted or in hex form,
  // so it is detected on the expanded hextets below and not only on the text.
  const dotted = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip);
  if (dotted) return isBlockedAddress(dotted[1]);

  const parts = expandIpv6(ip);
  if (!parts) return true;
  const hex = parts.join(":");

  if (hex === "0000:0000:0000:0000:0000:0000:0000:0000") return true; // ::
  if (hex === "0000:0000:0000:0000:0000:0000:0000:0001") return true; // ::1

  // Any IPv4 embedded in an IPv6 literal is checked against the IPv4 rules, so
  // a private address cannot be smuggled in through a translation prefix.
  const embedded = embeddedIpv4(parts);
  if (embedded !== null) return isBlockedAddress(embedded);

  const first = Number.parseInt(parts[0], 16);
  if (first >= 0xfe80 && first <= 0xfebf) return true; // link-local fe80::/10
  if (first >= 0xfec0 && first <= 0xfecf) return true; // deprecated site-local
  if (first >= 0xfc00 && first <= 0xfdff) return true; // unique local fc00::/7
  if (first >= 0xff00 && first <= 0xffff) return true; // multicast ff00::/8
  if (hex.startsWith("2001:0db8:")) return true; // documentation
  if (hex.startsWith("2001:0000:")) return true; // Teredo
  if (hex.startsWith("2002:")) {
    // 6to4 embeds the IPv4 address in the second and third hextet.
    return isBlockedAddress(hextetsToIpv4(parts[1], parts[2]));
  }
  return false;
}

/**
 * @param {string} hostname
 * @returns {Promise<string[]>} every address the hostname resolves to
 */
async function resolveAddresses(hostname) {
  if (net.isIP(hostname)) return [hostname];
  let records;
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new UrlGuardError("dns_resolution_failed");
  }
  if (!Array.isArray(records) || records.length === 0) {
    throw new UrlGuardError("dns_resolution_failed");
  }
  return records.map((record) => record.address);
}

/**
 * Validate a URL for outbound use.
 * @param {unknown} rawUrl
 * @returns {Promise<{url: URL, hostname: string, addresses: string[]}>}
 * @throws {UrlGuardError}
 */
async function assertSafeUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > MAX_URL_LENGTH) {
    throw new UrlGuardError("invalid_url");
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch (err) {
    throw new UrlGuardError("invalid_url");
  }

  if (url.protocol !== ALLOWED_PROTOCOL) throw new UrlGuardError("scheme_not_allowed");
  if (url.username || url.password) throw new UrlGuardError("credentials_not_allowed");
  if (url.port && url.port !== ALLOWED_PORT) throw new UrlGuardError("port_not_allowed");

  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!hostname) throw new UrlGuardError("invalid_url");

  const addresses = await resolveAddresses(hostname);
  for (const address of addresses) {
    if (isBlockedAddress(address)) throw new UrlGuardError("address_not_allowed");
  }

  return { url, hostname, addresses };
}

/**
 * Perform a guarded outbound request. Redirects are followed manually so that
 * every hop is re-validated instead of being inherited from the first hop.
 *
 * The body is read here, while the timeout is still armed, so a slow or huge
 * upstream cannot hold the request open or exhaust the process heap.
 * @param {string} rawUrl
 * @param {{method?: string, body?: string, maxHops?: number, timeoutMs?: number}} [options]
 * @returns {Promise<{status: number, body: string}>}
 * @throws {UrlGuardError}
 */
async function fetchGuarded(rawUrl, options = {}) {
  const maxHops = options.maxHops === undefined ? MAX_REDIRECTS : options.maxHops;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  let method = options.method || "GET";
  let body = options.body;
  let current = rawUrl;

  for (let hop = 0; hop <= maxHops; hop += 1) {
    const { url } = await assertSafeUrl(current);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method,
        body,
        redirect: "manual",
        signal: controller.signal,
        headers: { "user-agent": "teamboard-webhook-tester/1.0" },
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) throw new UrlGuardError("redirect_without_location");

        let nextUrl;
        try {
          nextUrl = new URL(location, url).toString();
        } catch (err) {
          throw new UrlGuardError("invalid_redirect");
        }

        // 303 (and 301/302) downgrade the replayed request to a bodyless GET;
        // 307/308 preserve the method. Either way the new target is re-validated.
        if (response.status === 303 || response.status === 301 || response.status === 302) {
          method = "GET";
          body = undefined;
        }
        current = nextUrl;
        continue;
      }

      const text = await readCappedText(response);
      return { status: response.status, body: text };
    } catch (err) {
      if (err instanceof UrlGuardError) throw err;
      // A timeout, a reset connection or a malformed response all surface here.
      throw new UrlGuardError("upstream_request_failed");
    } finally {
      clearTimeout(timer);
    }
  }

  throw new UrlGuardError("too_many_redirects");
}

/**
 * Read at most a bounded prefix of an upstream response body.
 *
 * The body is consumed as a stream with a hard cap and the stream is then
 * cancelled, so an oversized upstream response is never buffered in full. A
 * plain `response.text()` would pull the entire body into memory first and
 * only truncate afterwards.
 * @param {Response} response
 * @param {number} [maxBytes]
 * @returns {Promise<string>}
 */
async function readCappedText(response, maxBytes = MAX_BODY_BYTES) {
  const stream = response.body;
  if (!stream || typeof stream.getReader !== "function") {
    const text = await response.text();
    return text.length <= maxBytes ? text : `${text.slice(0, maxBytes)}...[truncated]`;
  }

  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
      total += value.length;
    }
  } finally {
    // Stop the download instead of letting the rest of the body arrive.
    await reader.cancel().catch(() => {});
  }

  const text = Buffer.concat(chunks).toString("utf8");
  return text.length <= maxBytes ? text : `${text.slice(0, maxBytes)}...[truncated]`;
}

module.exports = {
  UrlGuardError,
  assertSafeUrl,
  fetchGuarded,
  isBlockedAddress,
  readCappedText,
  MAX_BODY_BYTES,
};
