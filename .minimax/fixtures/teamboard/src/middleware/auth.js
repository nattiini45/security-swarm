const jwt = require("jsonwebtoken");
const SECRET = process.env.JWT_SECRET || "changeme";
function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  try {
    req.user = jwt.verify(h.replace("Bearer ", ""), SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorized" });
  }
}
function requireTeamAdmin(req, res, next) {
  if (req.user && req.user.teams && req.user.teams[req.params.teamId] === "admin") return next();
  res.status(403).end();
}
module.exports = { requireAuth, requireTeamAdmin, SECRET };
