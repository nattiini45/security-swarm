"use strict";

// Team roster.
//
// The projection is an explicit allow-list of non-secret columns, and the
// memberships table holds no credential at all - invitation tokens live in
// their own table and only ever as a hash.
//
// The roster requires a session and a membership in the team. The original
// build served it to anonymous callers, which disclosed the internal user ids
// and the admin roles of every member of every team to anyone who guessed a
// team id. A genuinely public roster can be re-enabled by dropping the
// membership check on the mount, but the projection must stay non-secret
// either way.

const router = require("express").Router();
const db = require("../db");

router.get("/", (req, res) => {
  // The row count is capped so one request cannot make the server materialise
  // an unbounded roster, and the team_id index keeps the lookup from scanning
  // the whole table.
  const rows = db
    .prepare(
      "SELECT user_id, team_id, role FROM memberships WHERE team_id = ? ORDER BY user_id LIMIT 200",
    )
    .all(req.team.id);
  return res.json(rows);
});

module.exports = router;
