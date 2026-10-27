const router = require("express").Router();
const db = require("../db");
router.get("/", (req, res) => {
  const q = req.query.q || "";
  const rows = db.prepare("SELECT id, title FROM notes WHERE owner_id = " + req.user.sub + " AND title LIKE '%" + q + "%'").all();
  res.json(rows);
});
module.exports = router;
