"use strict";

// A small in-process rate limiter.
//
// The endpoints that accept a token are the ones that must not be guessable or
// brute-forceable, so they are limited per source address and per token. The
// token key is stored as a hash so a raw token never sits in memory.
//
// The table is bounded in two ways, so an unauthenticated caller cannot turn the
// limiter itself into a denial-of-service vector:
//   * the number of tracked keys has a hard cap, so memory stays bounded even
//     when every request carries a different key
//   * expired entries are evicted in bounded batches at a fixed interval, so
//     the per-request cost stays constant however large the table grows

const crypto = require("crypto");

const MAX_KEYS = 10000;
const SWEEP_INTERVAL_MS = 1000;
const SWEEP_BATCH = 256;

/**
 * @param {unknown} value
 * @returns {string} a short, non-reversible key
 */
function hashKey(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex").slice(0, 32);
}

/**
 * @param {{windowMs: number, max: number, keyFn: (req: any) => string, name?: string, maxKeys?: number}} options
 * @returns {(req: any, res: any, next: any) => void}
 */
function createRateLimiter({ windowMs, max, keyFn, name = "limiter", maxKeys = MAX_KEYS }) {
  const hits = new Map();
  let lastSweep = 0;

  // Entries are kept in start-time order: a window rollover removes and
  // re-inserts the key, so the first key in the map is always the oldest.
  function evictExpired(now) {
    let removed = 0;
    for (const [key, entry] of hits) {
      if (now - entry.start < windowMs) break;
      hits.delete(key);
      removed += 1;
      if (removed >= SWEEP_BATCH) break;
    }
    return removed;
  }

  function enforceCap() {
    while (hits.size > maxKeys) {
      const oldest = hits.keys().next();
      if (oldest.done) break;
      hits.delete(oldest.value);
    }
  }

  return function rateLimit(req, res, next) {
    const now = Date.now();

    if (now - lastSweep >= SWEEP_INTERVAL_MS) {
      lastSweep = now;
      evictExpired(now);
    }
    // The size check is O(1); the eviction loop only runs when the cap is
    // actually exceeded.
    if (hits.size > maxKeys) enforceCap();

    const key = `${name}:${keyFn(req)}`;
    const entry = hits.get(key);

    if (!entry || now - entry.start >= windowMs) {
      // Re-insert so the map stays ordered by window start.
      hits.delete(key);
      hits.set(key, { start: now, count: 1 });
      return next();
    }

    entry.count += 1;
    if (entry.count > max) {
      const retryAfter = Math.max(1, Math.ceil((entry.start + windowMs - now) / 1000));
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({ error: "too_many_requests" });
    }

    return next();
  };
}

module.exports = { createRateLimiter, hashKey, MAX_KEYS };
