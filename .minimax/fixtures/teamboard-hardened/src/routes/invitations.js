"use strict";

// Invitation creation (team admin only - enforced by the mount).
//
// The plaintext token is returned exactly once, at creation time. Only its
// SHA-256 hash is stored, so the database can never hand out a usable token.

const router = require("express").Router();
const db = require("../db");
const { issueInvitation } = require("../lib/invites");
const { isValidEmail, normalizeEmail } = require("../lib/validate");

// A rate limit bounds how fast the table can grow; this bounds how large it
// can get. Redeemed invitations are retired on the next creation, so the only
// rows that accumulate are the outstanding ones.
const MAX_LIVE_INVITATIONS_PER_TEAM = 100;

router.post("/", (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const email = typeof body.email === "string" ? body.email : "";
  if (!isValidEmail(email)) return res.status(400).json({ error: "invalid_email" });

  // Retire invitations that have already been redeemed.
  db.prepare("DELETE FROM invitations WHERE team_id = ? AND consumed_at IS NOT NULL").run(
    req.team.id,
  );

  const live = db
    .prepare("SELECT COUNT(*) AS n FROM invitations WHERE team_id = ? AND consumed_at IS NULL")
    .get(req.team.id).n;
  if (live >= MAX_LIVE_INVITATIONS_PER_TEAM) {
    return res.status(429).json({ error: "too_many_invitations" });
  }

  const { token } = issueInvitation(req.team.id, normalizeEmail(email));
  return res.status(201).json({ token, email: normalizeEmail(email), teamId: req.team.id });
});

module.exports = router;
