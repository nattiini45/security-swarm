"use strict";

// Invitation handling.
//
// Only a SHA-256 hash of an invitation token is ever stored, so no database read
// (and no response body) can leak a usable token. Tokens are single use and bound
// to the address they were issued for, which makes them a capability for exactly
// one mailbox instead of a transferable role grant.

const crypto = require("crypto");
const db = require("../db");
const { normalizeEmail } = require("./validate");

const TOKEN_BYTES = 32;
const MAX_TOKEN_LENGTH = 256;

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * @param {unknown} token
 * @returns {string} hex SHA-256 hash of the token
 */
function hashToken(token) {
  return crypto.createHash("sha256").update(String(token), "utf8").digest("hex");
}

/**
 * Create an invitation and return its plaintext token. The plaintext is returned
 * exactly once, at creation time - it cannot be recovered later.
 * @param {string} teamId
 * @param {string} email
 * @returns {{id: number, token: string}}
 */
function issueInvitation(teamId, email) {
  const token = crypto.randomBytes(TOKEN_BYTES).toString("base64url");
  const info = db
    .prepare(
      "INSERT INTO invitations (team_id, email, token_hash, created_at) VALUES (?, ?, ?, ?)",
    )
    .run(teamId, normalizeEmail(email), hashToken(token), nowSeconds());
  return { id: Number(info.lastInsertRowid), token };
}

/**
 * Find the invitation behind a presented token.
 *
 * The lookup is by hash only. A consumed invitation is still returned here, so
 * that the caller can treat "unknown token" and "already redeemed token" with
 * exactly the same code path, the same work and the same response.
 * @param {unknown} token
 * @returns {object|null}
 */
function findInvitation(token) {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    return null;
  }
  return (
    db.prepare("SELECT id, team_id, email, token_hash, created_at, consumed_at FROM invitations WHERE token_hash = ?").get(
      hashToken(token),
    ) || null
  );
}

/**
 * Mark an invitation as redeemed. The conditional update makes a second
 * redemption of the same token impossible even under concurrent requests.
 *
 * The redemption itself is performed inside a transaction in the route, so
 * this helper is the single-statement form of the same claim.
 * @param {number} id
 * @param {number|null} userId
 * @returns {boolean} true when this call performed the redemption
 */
function consumeInvitation(id, userId) {
  const changes = db
    .prepare(
      "UPDATE invitations SET consumed_at = ?, consumed_by = ? WHERE id = ? AND consumed_at IS NULL",
    )
    .run(nowSeconds(), userId, id).changes;
  return changes === 1;
}

module.exports = { issueInvitation, findInvitation, consumeInvitation, hashToken };
