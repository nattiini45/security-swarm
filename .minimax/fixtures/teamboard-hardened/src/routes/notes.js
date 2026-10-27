"use strict";

// A single note, scoped to its owner.
//
// The owner id comes from the server-side session, never from a request
// parameter, and the lookup is fully parameterised.

const router = require("express").Router();
const db = require("../db");
const { isValidUserId } = require("../lib/validate");

router.get("/:id", (req, res) => {
  if (!isValidUserId(req.params.id)) return res.status(400).json({ error: "invalid_id" });

  const row = db
    .prepare("SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?")
    .get(req.params.id, req.user.sub);
  if (!row) return res.status(404).json({ error: "not_found" });
  return res.json(row);
});

module.exports = router;
