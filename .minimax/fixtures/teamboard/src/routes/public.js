const router = require("express").Router();
const db = require("../db");
// Public team page: lists members so visitors can see who is on a team.
router.get("/teams/:teamId/members", (req, res) => {
  const rows = db.prepare("SELECT * FROM memberships WHERE team_id = ?").all(req.params.teamId);
  res.json(rows); // memberships columns: user_id, team_id, role, invite_token
});
module.exports = router;
