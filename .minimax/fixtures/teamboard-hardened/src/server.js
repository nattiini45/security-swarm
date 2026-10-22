"use strict";

const express = require("express");
const { loadConfig } = require("./config");
const { securityHeaders } = require("./middleware/security");
const { requireAuth, requireTeamAdmin, requireTeamMember } = require("./middleware/auth");
const { createRateLimiter, hashKey } = require("./middleware/rateLimit");

// Validates the environment and throws on a misconfigured deployment. The
// server does not listen unless this succeeds: no JWT_SECRET, no start.
const config = loadConfig();

const app = express();

app.disable("x-powered-by");
app.set("etag", false);
app.set("env", config.nodeEnv);
// Behind a proxy, the socket address is the only address we trust, so a
// caller cannot spoof its source address through X-Forwarded-For to get
// around the rate limits.
app.set("trust proxy", false);

app.use(securityHeaders);
app.use(express.json({ limit: "16kb" }));
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// Rate limits. The token endpoints are limited per source address and per
// presented token, so a stolen token cannot be brute-forced and no address can
// be used to probe token validity at speed.
const publicLimiter = createRateLimiter({
  windowMs: 60_000,
  max: 120,
  name: "members",
  keyFn: (req) => (req.user ? req.user.sub : req.ip || "unknown"),
});
const inviteIpLimiter = createRateLimiter({
  windowMs: 60_000,
  max: 10,
  name: "invite-ip",
  keyFn: (req) => req.ip || "unknown",
});
const inviteTokenLimiter = createRateLimiter({
  windowMs: 60_000,
  max: 10,
  name: "invite-token",
  keyFn: (req) => hashKey(req.body && req.body.token),
});
// The webhook tester performs an outbound fetch and a DNS lookup per request,
// so it is limited per admin and per team as well.
const webhookLimiter = createRateLimiter({
  windowMs: 60_000,
  max: 30,
  name: "webhook",
  keyFn: (req) => `${req.user ? req.user.sub : "anon"}:${req.params.teamId || ""}`,
});
// Invitation creation writes a row to a shared table, so it is limited too.
const invitationLimiter = createRateLimiter({
  windowMs: 60_000,
  max: 20,
  name: "invitation",
  keyFn: (req) => `${req.user ? req.user.sub : "anon"}:${req.params.teamId || ""}`,
});

app.use(
  "/api/teams/:teamId/members",
  requireAuth,
  requireTeamMember,
  publicLimiter,
  require("./routes/members"),
);
app.use("/api/invite", inviteIpLimiter, inviteTokenLimiter, require("./routes/invite"));
app.use("/api/teams/:teamId/reports", requireAuth, requireTeamAdmin, require("./routes/reports"));
app.use(
  "/api/teams/:teamId/webhooks",
  requireAuth,
  requireTeamAdmin,
  webhookLimiter,
  require("./routes/webhooks"),
);
app.use(
  "/api/teams/:teamId/invitations",
  requireAuth,
  requireTeamAdmin,
  invitationLimiter,
  require("./routes/invitations"),
);
app.use("/api/search", requireAuth, require("./routes/search"));
app.use("/api/notes", requireAuth, require("./routes/notes"));
app.use("/api/session", requireAuth, require("./routes/session"));

// A JSON 404 instead of Express' default HTML page, which fingerprints the stack.
app.use((req, res) => res.status(404).json({ error: "not_found" }));

// Terminal error handler: the detail is logged server-side, the caller gets a
// generic body. No stack trace, no SQL text, no absolute path.
app.use((err, req, res, next) => {
  console.error("[teamboard] unhandled error:", err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  const status =
    Number.isInteger(err && err.status) && err.status >= 400 && err.status < 500 ? err.status : 500;
  return res
    .status(status)
    .json(status === 500 ? { error: "internal_error" } : { error: "bad_request" });
});

// A single bad request must not be able to take the whole service down.
process.on("unhandledRejection", (reason) => {
  console.error("[teamboard] unhandled rejection:", reason);
});

app.listen(config.port, () => {
  console.log(
    `teamboard (hardened reference build) listening on ${config.port} [${config.nodeEnv}]`,
  );
});
