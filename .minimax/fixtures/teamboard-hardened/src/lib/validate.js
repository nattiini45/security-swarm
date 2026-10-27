"use strict";

// Shared input validation.
//
// Every value that reaches a SQL statement, a filesystem path, a URL or a role
// decision passes through one of these helpers first.

const EMAIL_PATTERN = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
const MAX_EMAIL_LENGTH = 254;
const TEAM_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const REPORT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * @param {unknown} email
 * @returns {boolean} true when the value is a plausible, bounded email address
 */
function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length > 0 &&
    email.length <= MAX_EMAIL_LENGTH &&
    !/[\u0000-\u001f\u007f]/.test(email) &&
    EMAIL_PATTERN.test(email)
  );
}

/** @param {string} email */
function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

/**
 * @param {unknown} teamId
 * @returns {boolean} true for an opaque, path-safe team identifier
 */
function isValidTeamId(teamId) {
  return typeof teamId === "string" && TEAM_ID_PATTERN.test(teamId);
}

/**
 * @param {unknown} name
 * @returns {boolean} true for a single, path-safe report file name
 */
function isValidReportName(name) {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    name.length <= 128 &&
    name !== "." &&
    name !== ".." &&
    !name.includes("..") &&
    REPORT_NAME_PATTERN.test(name)
  );
}

/**
 * @param {unknown} value
 * @returns {boolean} true for a positive, safe integer id
 */
function isValidUserId(value) {
  const n = typeof value === "number" ? value : Number.parseInt(String(value), 10);
  return Number.isSafeInteger(n) && n > 0;
}

/**
 * @param {unknown} term
 * @returns {boolean} true when the value is a bounded, printable search term
 */
function isValidSearchTerm(term) {
  return (
    typeof term === "string" &&
    term.length > 0 &&
    term.length <= 100 &&
    !/[\u0000-\u001f\u007f]/.test(term)
  );
}

/**
 * Escape the LIKE wildcards so a search term is matched literally.
 * @param {string} term
 * @returns {string}
 */
function escapeLikeTerm(term) {
  return term.replace(/[\\%_]/g, (match) => `\\${match}`);
}

module.exports = {
  isValidEmail,
  normalizeEmail,
  isValidTeamId,
  isValidReportName,
  isValidUserId,
  isValidSearchTerm,
  escapeLikeTerm,
  MAX_EMAIL_LENGTH,
};
