"use strict";

// Authentication and authorisation middleware.
//
// requireAuth  - validates the bearer token's signature, algorithm and expiry,
//                and requires it to map to a live server-side session.
// requireTeamAdmin - the admin gate. It reads the caller's CURRENT role from
//                the memberships table, never from the token claim, so a
//                revoked or downgraded role takes effect on the next request.

const db = require("../db");
const { verifyToken, findLiveSession } = require("../lib/tokens");
const { isValidTeamId } = require("../lib/validate");

function unauthorized(res) {
  return res.status(401).json({ error: "unauthorized" });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const raw =
    typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!raw) return unauthorized(res);

  let claims;
  try {
    claims = verifyToken(raw);
  } catch (err) {
    return unauthorized(res);
  }

  // A valid signature is only half the answer. The token must also map to a
  // live server-side session, so a revoked token stops working immediately
  // instead of staying valid until its `exp` passes.
  const session = findLiveSession(claims.jti);
  if (!session) return unauthorized(res);

  // The user id comes from the session row, not from the token payload.
  req.user = { sub: session.user_id, jti: session.jti };
  req.claims = claims;
  return next();
}

/**
 * Require that the caller is a member of the team named in the path.
 */
function requireTeamMember(req, res, next) {
  const teamId = req.params.teamId;
  if (!isValidTeamId(teamId)) return res.status(400).json({ error: "invalid_team" });

  const row = db
    .prepare("SELECT role FROM memberships WHERE user_id = ? AND team_id = ?")
    .get(req.user.sub, teamId);
  if (!row) return res.status(403).json({ error: "forbidden" });

  req.team = { id: teamId, role: row.role };
  return next();
}

/**
 * Require that the caller currently holds the admin role for the team in the path.
 */
function requireTeamAdmin(req, res, next) {
  const teamId = req.params.teamId;
  if (!isValidTeamId(teamId)) return res.status(400).json({ error: "invalid_team" });

  const row = db
    .prepare("SELECT role FROM memberships WHERE user_id = ? AND team_id = ?")
    .get(req.user.sub, teamId);
  if (!row || row.role !== "admin") return res.status(403).json({ error: "forbidden" });

  req.team = { id: teamId, role: row.role };
  return next();
}

module.exports = { requireAuth, requireTeamMember, requireTeamAdmin };
