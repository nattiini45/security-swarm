"use strict";

// Note search.
//
// Every value is a bound parameter. The term is a LIKE pattern whose wildcards
// are escaped, so a search for "100%" matches that literal text instead of
// matching everything. The term is length-capped, control characters are
// rejected, and the statement has a hard row limit.

const router = require("express").Router();
const db = require("../db");
const { isValidSearchTerm, isValidUserId, escapeLikeTerm } = require("../lib/validate");

router.get("/", (req, res) => {
  const q = req.query.q;
  if (typeof q !== "string" || !isValidSearchTerm(q)) {
    return res.status(400).json({ error: "invalid_query" });
  }

  // The owner id comes from the server-side session. It is bound, never
  // concatenated, and it is checked to be an integer before it is used.
  if (!isValidUserId(req.user.sub)) return res.status(401).json({ error: "unauthorized" });

  const pattern = `%${escapeLikeTerm(q)}%`;
  const rows = db
    .prepare(
      "SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ? ESCAPE '\\' LIMIT 100",
    )
    .all(req.user.sub, pattern);
  return res.json(rows);
});

module.exports = router;
