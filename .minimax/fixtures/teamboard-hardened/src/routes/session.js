"use strict";

// Session lifecycle.
//
// Revoking a session makes the token stop working immediately, even though its
// signature is still valid and its expiry has not passed. This is what makes a
// role change, a logout, or a key rotation take effect at once instead of
// waiting for the token to age out.

const router = require("express").Router();
const { revokeSession } = require("../lib/tokens");

router.delete("/", (req, res) => {
  revokeSession(req.user.jti);
  return res.status(204).end();
});

module.exports = router;
