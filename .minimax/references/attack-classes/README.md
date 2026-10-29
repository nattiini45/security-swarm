# Attack-class playbooks

Vendored from **cloudflare/security-audit-skill** (MIT, Copyright (c) 2025-2026 Cloudflare, Inc. —
see `LICENSE-cloudflare`). Used here as curated *hunting checklists* injected into the map prompt;
the harness around them is Security Swarm's own (map → refute → reduce → verify).

Files:

| file | use |
|---|---|
| `ATTACK-CLASSES.md` | Core classes — injected into **every** mapper batch |
| `AI-AND-LLM.md` | Batches touching model calls, prompts, tool/agent code |
| `WEB-PROTOCOL-AND-AUTH.md` | Auth, sessions, JWT, OAuth, CSRF, cookies |
| `CLIENT-SIDE.md` | Browser code, DOM sinks, postMessage, webviews |
| `SUPPLY-CHAIN-AND-RELEASE.md` | Manifests, CI workflows, build/release scripts |
| `CLOUD-AND-DEPLOYMENT.md` | IaC, containers, ingress, runtime config |
| `DATA-ISOLATION-AND-LIFECYCLE.md` | Migrations, tenant scoping, export/backup/delete |
| `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` | Imports/uploads/parsers, queues, quotas, spend |
| `PROTOCOLS-RPC-AND-MESSAGING.md` | RPC, queues/brokers, webhooks, streaming |
| `DESKTOP-MOBILE-AND-LOCAL-IPC.md` | Native apps, deep links, exported components, daemons |
| `MEMORY-SAFETY-AND-BINARY.md` | C/C++/Rust-unsafe, parsers, kernel, FFI |

Selection is deterministic (`attack_playbook()` in `swarm.py`): the core file always, plus up to
`scan.playbook_max_companions` domain files whose path heuristics match the batch.

Do not edit these files to fit a scan — they are upstream text. Harness-specific guidance belongs
in `prompts/map.md`. On a re-vendor, copy the raw files again and keep the MIT notice.
