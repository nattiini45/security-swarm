"use strict";

// Startup configuration.
//
// Security posture of this module:
//   * There is NO fallback value for the signing key. A missing or weak key is a
//     hard startup failure, never a default that silently makes every token forgeable.
//   * The key is returned only through getSecret() and is never re-exported anywhere.

const MIN_SECRET_BYTES = 32;
const DEFAULT_PORT = 3000;

function fail(message) {
  throw new Error(`[config] ${message}`);
}

let cachedSecret = null;

/**
 * Resolve the JWT signing secret, failing closed.
 * @returns {string} the signing key
 */
function getSecret() {
  if (cachedSecret !== null) return cachedSecret;

  const secret = process.env.JWT_SECRET;
  if (typeof secret !== "string" || secret.length === 0) {
    fail(
      "JWT_SECRET is not set. Refusing to start with a fallback signing key " +
        "(a default key would make every token in the system forgeable).",
    );
  }
  if (Buffer.byteLength(secret, "utf8") < MIN_SECRET_BYTES) {
    fail(
      `JWT_SECRET must be at least ${MIN_SECRET_BYTES} bytes of entropy; ` +
        `got ${Buffer.byteLength(secret, "utf8")}. Generate one with: openssl rand -base64 48`,
    );
  }

  cachedSecret = secret;
  return cachedSecret;
}

/**
 * Validate the full startup environment. Called once by server.js before listen().
 * @param {NodeJS.ProcessEnv} [env]
 */
function loadConfig(env = process.env) {
  const port = Number.parseInt(env.PORT || String(DEFAULT_PORT), 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    fail(`PORT is not a valid TCP port: ${env.PORT}`);
  }

  // Deployment guard: this build is a reference implementation, not a product.
  // It refuses to listen unless the operator opts in explicitly, so it cannot be
  // started by accident as part of a deploy or a container entrypoint.
  if (env.TEAMBOARD_ALLOW_START !== "1") {
    fail(
      "Refusing to start. This is a reference build and must not be deployed; " +
        "set TEAMBOARD_ALLOW_START=1 to start it explicitly for local review.",
    );
  }

  // Validate the secret eagerly so a misconfigured deployment fails at startup
  // rather than on the first request that needs to sign or verify a token.
  getSecret();

  return {
    port,
    nodeEnv: env.NODE_ENV || "production",
    allowStart: true,
  };
}

module.exports = { loadConfig, getSecret, MIN_SECRET_BYTES, DEFAULT_PORT };
