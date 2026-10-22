"use strict";

// Invitation redemption.
//
// Fixes, in order of impact:
//   * The granted role is always 'member'. It is never copied from the
//     invitation row, so redeeming a token can never mint an administrator.
//   * The invitation is single use: it is claimed inside a transaction before
//     the account is created, so a second redemption fails even under
//     concurrency and cannot leave a half-created account behind.
//   * The invitation is bound to the address it was issued for.
//   * Every failure returns the identical status and body. An unknown token, an
//     already-redeemed token, a wrong address and a malformed address are
//     indistinguishable, so the endpoint is not a token-validity oracle.
//   * The email is validated and bounded before it reaches the database, and
//     an address that already has an account never gets a second account.

const router = require("express").Router();
const db = require("../db");
const { findInvitation } = require("../lib/invites");
const { issueSession } = require("../lib/tokens");
const { isValidEmail, normalizeEmail } = require("../lib/validate");

/**
 * The single failure response. Every rejection path uses it, so a caller
 * cannot tell a valid token from an invalid one by the answer.
 */
function reject(res) {
  return res.status(400).json({ error: "invalid_request" });
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

const REDEEM_FAILED = "redeem_failed";

/**
 * Claim the invitation and create the account and membership atomically.
 * @param {number} invitationId
 * @param {string} teamId
 * @param {string} email
 * @returns {number} the new user's id
 */
const redeem = db.transaction((invitationId, teamId, email) => {
  // Claim the invitation first. The conditional update means exactly one
  // request can ever succeed, and the transaction rolls back everything else.
  const claimed = db
    .prepare("UPDATE invitations SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL")
    .run(nowSeconds(), invitationId).changes;
  if (claimed !== 1) throw REDEEM_FAILED;

  const user = db
    .prepare("INSERT INTO users (email, created_at) VALUES (?, ?) RETURNING id")
    .get(email, nowSeconds());

  // The role is fixed. It is never read from the invitation row.
  db.prepare(
    "INSERT INTO memberships (user_id, team_id, role, created_at) VALUES (?, ?, 'member', ?)",
  ).run(user.id, teamId, nowSeconds());

  db.prepare("UPDATE invitations SET consumed_by = ? WHERE id = ?").run(user.id, invitationId);
  return user.id;
});

router.post("/accept", (req, res, next) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const token = typeof body.token === "string" ? body.token : "";
  const email = typeof body.email === "string" ? body.email : "";

  // Unknown token and already-redeemed token take the same path.
  const invitation = findInvitation(token);
  if (!invitation || invitation.consumed_at !== null) return reject(res);

  if (!isValidEmail(email)) return reject(res);
  const normalized = normalizeEmail(email);
  if (normalized !== normalizeEmail(invitation.email)) return reject(res);

  // An address that already has an account never gets a second account, and
  // never receives a session through this path.
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(normalized);
  if (existing) return reject(res);

  let userId;
  try {
    userId = redeem(invitation.id, invitation.team_id, normalized);
  } catch (err) {
    if (err === REDEEM_FAILED) return reject(res);
    // A unique-constraint clash is a client-side condition and is answered with
    // the same generic rejection.
    if (err && err.code === "SQLITE_CONSTRAINT_UNIQUE") return reject(res);
    return next(err);
  }

  const { token: sessionToken } = issueSession(userId, { teamId: invitation.team_id });
  return res.json({ token: sessionToken });
});

module.exports = router;
