# Logging, alerting and error handling

Companion checklist for OWASP Top 10:2025 **A09 Security Logging and Alerting Failures** and
**A10 Mishandling of Exceptional Conditions** (see also ASVS 5.0 V16 *Security Logging and Error
Handling*). Written for Security Swarm; MIT like the rest of this repository.

These classes are easy to over-report. A missing log line is a finding only when you can name the
attack it lets go unnoticed or the decision it gets wrong. Everything else is a hardening note.

## What to trace

- **Security events that leave no trace**: failed logins, lockouts, password/MFA/e-mail changes,
  permission and role changes, token or API-key creation and revocation, admin actions, exports,
  payment or other high-value operations. Check both outcomes: code that logs only the success path
  (or only the failure path) hides brute force and abuse. (CWE-778, CWE-223)
- **Sensitive data written to logs**: passwords, session/refresh tokens, API keys, OAuth codes,
  full request bodies or headers (`Authorization`, `Cookie`), card data, health/PII fields, signed
  URLs. Follow request/response loggers, error reporters (Sentry and similar breadcrumbs), debug
  dumps and analytics events — a log store usually has wider read access than the database. (CWE-532)
- **Log injection / forging**: user-controlled strings written into line-oriented logs without
  neutralising CR/LF or control characters, or into log viewers that render HTML. Matters when an
  operator or a parser downstream trusts the log. (CWE-117)
- **Logs readable by the wrong principal**: log files or audit tables served by the app, exposed
  through an admin panel without authorisation, world-readable paths, or audit rows a user can
  edit or delete. An audit trail the audited user can rewrite is not an audit trail.
- **Alerting that cannot fire**: security events logged at debug level or dropped by sampling,
  rate-limit and lockout triggers with no signal, catch-all handlers that swallow the error before
  anything is recorded.

## Exceptional conditions (A10)

- **Failing open**: an exception, timeout or missing value inside an authorisation, validation,
  signature, licence or rate-limit check that lets the request continue (`catch { return true }`,
  `?? true`, `except Exception: pass` around a check, default `allow` when a policy lookup fails).
  This is the highest-value item on this list. (CWE-636, CWE-755)
- **Half-finished transactions**: multi-step writes (debit then credit, create then grant,
  upload then record) where an error between steps leaves a state the business rules forbid and no
  rollback runs. (CWE-460)
- **Errors that disclose**: stack traces, SQL text, internal paths, framework versions or secrets in
  responses to an untrusted caller, especially in production error handlers. (CWE-209, CWE-550)
- **Missing-parameter and type confusion paths**: a handler that assumes a field exists or has a
  type and takes a different branch when it does not (`undefined` compared as falsy, `null` owner
  id matching another `null`). (CWE-234, CWE-754)
- **Unchecked results**: ignored return codes or promise rejections from security-relevant calls
  (`verify()`, `chmod`, `revoke`, DB writes that enforce an invariant). (CWE-252, CWE-391)
- **Unbounded retries and handlers**: error paths that retry without limit, recurse, or allocate per
  failure, turning one bad input into resource exhaustion.

## Not findings on their own

- "No centralised logging" or "no SIEM": deployment questions — route to `unvalidated` with the
  missing fact, do not guess.
- Generic `catch (e)` that re-throws or returns a safe error.
- Verbose errors that only the same principal who caused them can see, with nothing sensitive in them.
