"use strict";

// Webhook destinations for a team.
//
// Two controls, in this order:
//   1. Allow-list - a URL can only be tested if it is a destination this team
//      registered. Registration is itself validated, so an internal address
//      never gets into the list in the first place.
//   2. Outbound guard - every request re-validates the URL (https only, public
//      address only) and re-validates each redirect hop.
//
// The handler is wrapped so a failed upstream call becomes a 502 instead of an
// unhandled rejection that can terminate the process.

const router = require("express").Router();
const db = require("../db");
const { asyncHandler } = require("../lib/asyncHandler");
const { assertSafeUrl, fetchGuarded, UrlGuardError } = require("../lib/urlGuard");

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// Register a destination for this team.
router.post(
  "/",
  asyncHandler(async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const url = typeof body.url === "string" ? body.url.trim() : "";
    if (!url) return res.status(400).json({ error: "invalid_url" });

    try {
      await assertSafeUrl(url);
    } catch (err) {
      if (err instanceof UrlGuardError) return res.status(400).json({ error: "invalid_url" });
      return next(err);
    }

    const info = db
      .prepare("INSERT INTO team_webhooks (team_id, url, created_at) VALUES (?, ?, ?)")
      .run(req.team.id, url, nowSeconds());
    return res.status(201).json({ id: Number(info.lastInsertRowid), url, teamId: req.team.id });
  }),
);

// Test one of the team's registered destinations.
router.post(
  "/test",
  asyncHandler(async (req, res, next) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const url = typeof body.url === "string" ? body.url.trim() : "";
    if (!url) return res.status(400).json({ error: "invalid_url" });

    // Allow-list, scoped to this team.
    const registered = db
      .prepare("SELECT id FROM team_webhooks WHERE team_id = ? AND url = ?")
      .get(req.team.id, url);
    if (!registered) return res.status(404).json({ error: "not_found" });

    let result;
    try {
      result = await fetchGuarded(url, {
        method: "POST",
        body: JSON.stringify({ ping: true }),
      });
    } catch (err) {
      if (err instanceof UrlGuardError) return res.status(400).json({ error: "invalid_url" });
      // An unreachable or malformed upstream must not take the process down.
      return res.status(502).json({ error: "upstream_unavailable" });
    }

    return res.json({ status: result.status, body: result.body });
  }),
);

module.exports = router;
