"use strict";

// Token issuing and verification.
//
// The signing key is module-private: this module is the only place that can read
// it, and it exposes sign/verify operations rather than the key itself. Callers
// can obtain a token but can never obtain the key.
//
// Every issued token is backed by a row in `sessions`, so a token can be revoked
// (logout, role change, key rotation) and a revoked token stops working
// immediately instead of staying valid until it expires.

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const db = require("../db");
const { getSecret } = require("../config");

// Fixed in code on both sides. Never inherited from the token's own header.
const ALGORITHM = "HS256";
const DEFAULT_TTL_SECONDS = 30 * 60;

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Create a server-side session and the matching signed token.
 * @param {number} userId
 * @param {object} [claims] additional claims (never a role - roles are read from the database)
 * @param {{ttlSeconds?: number}} [options]
 * @returns {{token: string, jti: string, expiresAt: number}}
 */
function issueSession(userId, claims = {}, options = {}) {
  const ttlSeconds = options.ttlSeconds || DEFAULT_TTL_SECONDS;
  const jti = crypto.randomUUID();
  const issuedAt = nowSeconds();
  const expiresAt = issuedAt + ttlSeconds;

  db.prepare(
    "INSERT INTO sessions (jti, user_id, issued_at, expires_at) VALUES (?, ?, ?, ?)",
  ).run(jti, userId, issuedAt, expiresAt);

  const token = jwt.sign(
    { ...claims, sub: String(userId), jti },
    getSecret(),
    { algorithm: ALGORITHM, expiresIn: ttlSeconds },
  );

  return { token, jti, expiresAt };
}

/**
 * Verify a token's signature, algorithm and expiry.
 * @param {string} token
 * @returns {object} the decoded claims
 */
function verifyToken(token) {
  return jwt.verify(token, getSecret(), { algorithms: [ALGORITHM] });
}

/**
 * Revoke a session. A revoked session is rejected even though its signature
 * is still valid and its `exp` has not passed.
 * @param {string} jti
 * @returns {boolean} true when a live session was actually revoked
 */
function revokeSession(jti) {
  const changes = db
    .prepare("UPDATE sessions SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL")
    .run(nowSeconds(), jti).changes;
  return changes === 1;
}

/**
 * Look up the live session behind a token.
 * @param {string} jti
 * @returns {object|null}
 */
function findLiveSession(jti) {
  if (typeof jti !== "string" || jti.length === 0) return null;
  const session = db
    .prepare("SELECT jti, user_id, issued_at, expires_at, revoked_at FROM sessions WHERE jti = ?")
    .get(jti);
  if (!session) return null;
  if (session.revoked_at !== null && session.revoked_at !== undefined) return null;
  if (session.expires_at <= nowSeconds()) return null;
  return session;
}

module.exports = {
  issueSession,
  verifyToken,
  revokeSession,
  findLiveSession,
  ALGORITHM,
  DEFAULT_TTL_SECONDS,
};
