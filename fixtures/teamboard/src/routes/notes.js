const router = require("express").Router();
const db = require("../db");
// Safe: parameterized and scoped to the caller.
router.get("/:id", (req, res) => {
  const row = db.prepare("SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?").get(req.params.id, req.user.sub);
  if (!row) return res.status(404).end();
  res.json(row);
});
module.exports = router;
