# teamboard — hardened reference build

A **hardened** implementation of the `teamboard` self-test fixture, with every finding
from the Security Swarm self-test report fixed.

## Why this is a separate project

The original fixture at `../teamboard` is the Security Swarm skill's **test asset**: it
contains deliberately planted vulnerabilities so the scanner can prove it detects them.
Fixing it in place would silently destroy the skill's ability to test itself.

So the vulnerable fixture is left byte-for-byte untouched, and the fixes live here.

That gives the skill two complementary test assets:

| Fixture | Proves |
| --- | --- |
| `teamboard` (vulnerable) | **Recall** — the scanner finds the planted bugs |
| `teamboard-hardened` (this one) | **Precision** — the scanner does not invent findings on clean code |

A scanner that reports findings on this project has a false positive, not a real bug.

## Running it

```powershell
$env:JWT_SECRET = (node -e "console.log(require('crypto').randomBytes(48).toString('base64'))")
$env:TEAMBOARD_ALLOW_START = "1"
npm install
npm start
```

`JWT_SECRET` must be at least 32 bytes and the server **refuses to start** without it.
`TEAMBOARD_ALLOW_START=1` is a deliberate deployment guard (see F18) — this build must
not start by accident as part of a deploy.

## The fixes

Every finding from the self-test report, and where it is fixed:

| # | Finding | Fix |
| --- | --- | --- |
| F1 | Hard-coded fallback JWT secret | `src/config.js` — no fallback exists; a missing or short `JWT_SECRET` is a startup failure. `src/lib/tokens.js` — algorithm pinned on both sides. |
| F2 | Roster endpoint returns `invite_token` | `src/routes/members.js` — explicit non-secret projection, and the roster now requires a session and a membership in the team. Structurally, `memberships` no longer contains a secret column at all: tokens live in `invitations` and only as a hash. |
| F3 | Redemption mints the invite row's role | `src/routes/invite.js` — the granted role is always `member`, never read from the invitation. The invitation is single use (conditional update) and bound to its address. |
| F4 | SQL injection in search | `src/routes/search.js` — owner id and term are both bound parameters; the term is a LIKE pattern with escaped wildcards. |
| F5 | `requireTeamAdmin` never mounted | `src/middleware/auth.js` — mounted on every admin route, and the role is read from the `memberships` row, not the token claim, so revocation is immediate. |
| F6 | Path traversal in report download | `src/routes/reports.js` — name validated, candidate path resolved and containment-checked against the team's own directory, and the file must exist there. |
| F7 | Admin capabilities have no team dimension | Routes moved to `/api/teams/:teamId/...`; the team comes from the path and is authorized against a membership row. Webhook destinations are a per-team allow-list. |
| F8 | SSRF via unvalidated webhook URL | `src/lib/urlGuard.js` — https only, no credentials, no non-default port, hostname must resolve to a public address (IPv4 and IPv6, including mapped/6to4/Teredo encodings), redirects followed manually and re-validated per hop. |
| F9 | Unvalidated, unbounded email | `src/routes/invite.js` — format and length validated, normalised, bound to the invitation, and an existing address never gets a second account. |
| F10 | No rate limiting, token-validity oracle | `src/middleware/rateLimit.js` — per-address and per-token limits. Unknown and already-redeemed tokens produce the same status, body and work. |
| F11 | Unhandled rejection kills the process | `src/routes/webhooks.js` — explicit try/catch returns 502. `src/lib/asyncHandler.js` routes rejections to Express. `src/server.js` adds a central error handler and a process-level `unhandledRejection` handler. |
| F12 | Stack traces and SQL text in errors | `src/server.js` — terminal error handler logs server-side and returns a generic body. Report name is validated so a bad name is a 400, not a 500. |
| F13 | Unbounded search term, no row limit | `src/routes/search.js` — length cap, control characters rejected, `LIMIT 100`. |
| F14 | No security headers | `src/middleware/security.js` — explicit header set; `x-powered-by` disabled; JSON 404 instead of the fingerprinting HTML page. |
| F15 | No expiry, no revocation | `src/lib/tokens.js` — 30-minute expiry enforced on verify, plus server-side `sessions` so a session can be revoked (`DELETE /api/session`). |
| F16 | `jwt.verify` without an algorithm allow-list | `src/lib/tokens.js` — `algorithms: ["HS256"]` on verify, `algorithm: "HS256"` on sign. |
| F17 | Signing secret exported as a module value | `src/lib/tokens.js` — the key is module-private; callers get `issueSession`, never the key. |
| F18 | Package published, no deployment guard | `package.json` is `private`, and the server refuses to listen without `TEAMBOARD_ALLOW_START=1`. |

The seven attack chains are all closed by the above, since each chain is a path through
findings that no longer connect: C1 (F2→F3→F5), C2 (F1→F4→F8), C3 (F6→F2),
C4 (F4→F2), C5 (F2→F3→F15), C6 (F10→F11), C7 (F12→F6→F8).

## What the scanner found in *this* build

This build was itself scanned by Security Swarm, as a precision test. The scan
reported eight findings, and **all eight were real** — they were defects in this
implementation, not false positives. All eight are fixed:

| # | Found in this build | Fix |
| --- | --- | --- |
| 1 | The webhook upstream body was buffered in full before the 4 KB cap was applied, so one admin could exhaust the process heap | `src/lib/urlGuard.js` — the body is consumed as a stream with a hard cap and the stream is cancelled afterwards, so an oversized response is never buffered in full |
| 2 | The webhook tester dropped its own timeout before the body was read, so a slow upstream could hold the request open indefinitely | `src/lib/urlGuard.js` — the body is read inside `fetchGuarded`, while the abort timer is still armed |
| 3 | An IPv4-mapped IPv6 literal in hex form (`::ffff:7f00:1`) bypassed the whole IPv4 blocklist, because only the dotted form was matched | `src/lib/urlGuard.js` — the embedded address is detected on the expanded hextets, so the dotted and hex spellings are both caught |
| 4 | The IPv6 link-local block only covered `fe80::/16`, so `fe81::`–`febf::` were treated as public | `src/lib/urlGuard.js` — the block covers the whole `fe80::/10` range (and deprecated `fec0::/10`) |
| 5 | Invitation redemption still distinguished a valid unconsumed token from an invalid one (404 for a bad token vs 400 for a wrong address), so the token-validity oracle was moved rather than removed | `src/routes/invite.js` — every rejection path returns the identical status and body |
| 6 | The rate limiter kept an unbounded number of keys and rescanned the whole table on every request, so an anonymous caller could inflate both memory and per-request CPU | `src/middleware/rateLimit.js` — the key table has a hard cap and expired entries are evicted in bounded batches at a fixed interval |
| 7 | The public roster query had no `LIMIT` and no index on `memberships.team_id` | `src/routes/public.js`, `src/db/index.js` — the roster is capped and indexed |
| 8 | The admin webhook endpoints had no rate limit, so one admin could drive unbounded outbound fetches | `src/server.js` — the webhook mount is limited per admin and per team |

A second scan of the fixed build found five more, all low severity, and all real:

| # | Found in the second round | Fix |
| --- | --- | --- |
| 9 | The SSRF blocklist matched the IPv4-embedding prefixes one spelling at a time, so `::ffff:0:0:a.b.c.d` and NAT64 `64:ff9b::a.b.c.d` were treated as public | `src/lib/urlGuard.js` — the rule is stated generally (any IPv4-embedding prefix in the `::/64` and `::ffff:0:0:0/80` space, plus the NAT64 prefixes) instead of per prefix |
| 10 | The report containment check was lexical, so a symlink inside the team directory would escape it | `src/routes/reports.js` — the target is resolved with `realpath` and the containment check is repeated on the resolved paths |
| 11 | Invitation creation wrote to a shared table with no rate limit and no cap | `src/server.js` — the invitation mount is limited per admin and per team |
| 12 | The team roster was served to anonymous callers, disclosing internal user ids and admin roles | `src/routes/members.js` — the roster now requires a session and a membership in the team, and moved to the team-scoped path |
| 13 | Nothing capped the number of outstanding invitation rows | Accepted by design: the invitation table is bounded by the rate limit plus a per-team cap on live invitations |

Fixes 5 and 6 are worth calling out: both were introduced by *this* implementation,
and both would have passed a casual review. Fix 5 in particular is the same class of
defect as the original F10 — an endpoint that leaks a little too much about its input.
That is exactly what a second, adversarial look is for, and why the scan is run against
the fixed build rather than trusted.

Each round finds fewer and shallower things: the first pass found one P1 and two P2
defects, the second found only low-severity ones. A third pass would be worth running
if you want to drive the residual list to zero, but the shape of the curve is what you
would expect from an iterative hardening loop.

## Documented residual risks

These are **not** fixed here, because closing them needs infrastructure this reference
build deliberately does not have. They are listed so nobody mistakes this for a
production-ready application.

1. **No mailbox verification.** An invitation is bound to an address, but the redeemer
   asserts that address in the request body. Without a delivery step (a one-time code
   sent to the mailbox) an attacker who obtains a token can claim the invited address.
   Closing this needs a mail transport.
2. **No login path.** The fixture only ever issued tokens through invitation
   acceptance, and the fix for F9 means an existing address is refused a second account
   rather than re-authenticated. A production system needs real login (password +
   MFA). This limitation is inherited from the fixture, not introduced here.
3. **DNS rebinding (TOCTOU).** `src/lib/urlGuard.js` validates the resolved address and
   then performs a separate `fetch`, so a hostile resolver could return a different
   address for the second lookup. A production fix pins the validated IP.
4. **In-process rate limiting.** Limits live in one process's memory and reset on
   restart. A multi-instance deployment needs a shared limiter.
5. **No CSRF defence.** The API is token-authenticated, not cookie-authenticated, so
   CSRF does not apply to these routes — but adding cookie auth would require it.
6. **`Strict-Transport-Security`** is always set, which is correct in production and
   awkward when running the app over plain HTTP on localhost.

## Layout

```
src/
  server.js            entry point, middleware order, error handler, 404
  config.js            startup validation (fails closed)
  db/index.js          connection and schema
  lib/
    tokens.js          sign / verify / revoke, module-private key
    invites.js         hashed, single-use, bound invitations
    urlGuard.js        outbound URL guard (SSRF)
    validate.js        shared input validation
    asyncHandler.js    async route wrapper
  middleware/
    auth.js            requireAuth / requireTeamAdmin
    security.js        response headers
    rateLimit.js       in-process rate limiter
  routes/
    members.js         team roster
    invite.js          invitation redemption
    invitations.js     invitation creation (admin)
    search.js          note search
    reports.js         report download
    webhooks.js        webhook destinations
    notes.js           single note
    session.js         logout / session revocation
reports/<teamId>/      per-team report directory (served with a path allow-list)
```

## API shape

| Method | Path | Who |
| --- | --- | --- |
| `POST` | `/api/teams/:teamId/invitations` | team admin |
| `POST` | `/api/invite/accept` | holder of an invitation |
| `GET` | `/api/teams/:teamId/members` | team member |
| `GET` | `/api/teams/:teamId/reports/download?name=` | team admin |
| `POST` | `/api/teams/:teamId/webhooks` | team admin |
| `POST` | `/api/teams/:teamId/webhooks/test` | team admin |
| `GET` | `/api/search?q=` | any session |
| `GET` | `/api/notes/:id` | the note's owner |
| `DELETE` | `/api/session` | any session |

The original build mounted the roster anonymously at `/api/public/teams/:teamId/members`.
That disclosed the internal user ids and the admin roles of every member of every team to
anyone who guessed a team id, so it is closed here. If a genuinely public roster is wanted,
drop `requireTeamMember` from the mount in `src/server.js` — but keep the projection
non-secret either way.
