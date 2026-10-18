const router = require("express").Router();
const path = require("path");
const REPORT_DIR = path.join(__dirname, "..", "..", "reports");
router.get("/download", (req, res) => {
  res.sendFile(path.join(REPORT_DIR, req.query.name));
});
module.exports = router;
