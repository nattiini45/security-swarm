const router = require("express").Router();
// Lets team admins test their webhook endpoint.
router.post("/test", async (req, res) => {
  const r = await fetch(req.body.url, { method: "POST", body: JSON.stringify({ ping: true }) });
  res.json({ status: r.status, body: await r.text() });
});
module.exports = router;
