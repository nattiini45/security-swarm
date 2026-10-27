"use strict";

// Report download.
//
// The file name is validated and the candidate path is resolved and checked for
// containment, so no request can escape the team's own reports directory. The
// report must also actually exist there, which makes the directory the
// allow-list rather than a name shape check alone. The route is mounted behind
// the team admin gate, so a caller also has to hold the admin role for the
// team the report belongs to.

const fs = require("fs");
const path = require("path");
const router = require("express").Router();
const { isValidReportName, isValidTeamId } = require("../lib/validate");

const REPORT_DIR = path.resolve(__dirname, "..", "..", "reports");

/**
 * @param {string} parent absolute directory
 * @param {string} child absolute candidate path
 * @returns {boolean} true when child is strictly inside parent
 */
function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

router.get("/download", async (req, res, next) => {
  const name = req.query.name;
  // `name` can arrive as an array or an object; only a single string is accepted.
  if (typeof name !== "string" || !isValidReportName(name)) {
    return res.status(400).json({ error: "invalid_report_name" });
  }

  // The team comes from the authorised team on the request, not from the raw
  // path parameter: a mounted sub-router does not inherit the mount's params.
  const teamId = req.team.id;
  if (!isValidTeamId(teamId)) return res.status(400).json({ error: "invalid_team" });

  // The team id is part of the path, so it is resolved and containment-checked
  // exactly like the file name.
  const teamDir = path.resolve(REPORT_DIR, teamId);
  if (!isInside(REPORT_DIR, teamDir)) return res.status(400).json({ error: "invalid_team" });

  const target = path.resolve(teamDir, name);
  if (!isInside(teamDir, target)) return res.status(400).json({ error: "invalid_report_name" });

  // Resolve symlinks before the containment check. A lexical check alone would
  // accept a symlink inside the team directory that points outside it, so the
  // check is repeated on the real paths.
  let realTeamDir;
  let realTarget;
  try {
    realTeamDir = await fs.promises.realpath(teamDir);
    realTarget = await fs.promises.realpath(target);
  } catch (err) {
    // The report does not exist. The directory contents are the allow-list.
    return res.status(404).json({ error: "not_found" });
  }
  if (!isInside(REPORT_DIR, realTeamDir)) return res.status(400).json({ error: "invalid_team" });
  if (!isInside(realTeamDir, realTarget)) {
    return res.status(400).json({ error: "invalid_report_name" });
  }

  const stat = await fs.promises.stat(realTarget);
  if (!stat.isFile()) return res.status(404).json({ error: "not_found" });

  // The resolved path is served, so the symlink cannot redirect the transfer.
  return res.sendFile(realTarget, (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: "not_found" });
    else if (err) next(err);
  });
});

module.exports = router;
