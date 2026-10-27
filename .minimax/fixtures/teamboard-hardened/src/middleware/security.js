"use strict";

// Security response headers.
//
// An explicit header set is used instead of a dependency so the reference build
// runs with no install step. These are the same headers helmet sets by default
// for an API that returns JSON only.
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
  "X-DNS-Prefetch-Control": "off",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

function securityHeaders(req, res, next) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(name, value);
  }
  next();
}

module.exports = { securityHeaders, SECURITY_HEADERS };
