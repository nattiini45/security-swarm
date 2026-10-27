"use strict";

// Database access.
//
// The schema is created here (idempotently) so the invariants the security fixes
// depend on are enforced by the database itself, not by application code alone:
//
//   * invitations.token_hash stores a SHA-256 hash, never the usable token.
//   * memberships carries no secret column at all, so the public roster endpoint
//     cannot leak a credential even if its projection is widened by mistake.
//   * sessions holds server-side session state, so a token can be revoked and a
//     role change takes effect immediately instead of waiting for token expiry.

const path = require("path");
const Database = require("better-sqlite3");

const dbPath = process.env.DB_PATH || path.join(__dirname, "..", "..", "teamboard.db");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS memberships (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    team_id    TEXT NOT NULL,
    role       TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS memberships_user_team ON memberships (user_id, team_id);
  -- The public roster filters on team_id alone, so it needs its own index.
  CREATE INDEX IF NOT EXISTS memberships_team ON memberships (team_id);

  CREATE TABLE IF NOT EXISTS invitations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id     TEXT NOT NULL,
    email       TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    consumed_at INTEGER,
    consumed_by INTEGER
  );

  CREATE TABLE IF NOT EXISTS sessions (
    jti         TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER
  );

  CREATE TABLE IF NOT EXISTS notes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title    TEXT NOT NULL,
    body     TEXT
  );

  CREATE TABLE IF NOT EXISTS team_webhooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id    TEXT NOT NULL,
    url        TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

module.exports = db;
