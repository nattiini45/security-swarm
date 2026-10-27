const router = require("express").Router();
const jwt = require("jsonwebtoken");
const db = require("../db");
const { SECRET } = require("../middleware/auth");
// Accept an invite: whoever holds a valid invite token joins with the role stored on it.
router.post("/accept", (req, res) => {
  const inv = db.prepare("SELECT * FROM memberships WHERE invite_token = ?").get(req.body.token);
  if (!inv) return res.status(404).end();
  const user = db.prepare("INSERT INTO users (email) VALUES (?) RETURNING id").get(req.body.email);
  db.prepare("INSERT INTO memberships (user_id, team_id, role) VALUES (?, ?, ?)").run(user.id, inv.team_id, inv.role);
  const token = jwt.sign({ sub: user.id, teams: { [inv.team_id]: inv.role } }, SECRET);
  res.json({ token });
});
module.exports = router;
