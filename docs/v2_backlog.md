# V2 Backlog — Deferred from V1

V1 delivers the working prototype: input Stages 1–7, output stages O1–O4, the
`STOP` / `REDACT` / `ESCALATE` / `ALLOW` outcomes, rules **R-01…R-09**, the SQLite
append-only audit log, and the 13-prompt red-team suite (13/13 passing).

The items below were **consciously deferred to V2** — each either needs data that
doesn't exist yet (history/baselines), a component outside V1 scope, or would
introduce a new attack surface. This is honest scope, not missing work.

## Deferred items

| Item | Why deferred | Rule / Ref |
|------|--------------|------------|
| **Multi-turn / session context** | Needs a conversation store (Redis session tier); V1 has no history | R-10 · `pdp/session.py` |
| **ALLOW + CONSTRAIN outcome** | Post-model response constrainer (gate O5) not built in V1 | R-11 · `pdp/constrainer.py` |
| **Automated system behavioural profiling** | Requires a behavioural baseline — data that only accrues over time | R-12 · `monitoring/profiler.py` |
| **Adversary behavioural detection** | Same cold-start baseline dependency as R-12 | R-13 · `monitoring/behaviour.py` |
| **Real EIM identity** | V1 uses a mock with 5 seeded users; real identity integration is a milestone of its own | `identity/eim_client.py` |
| **Reviewer UI** | V1 escalation is a Slack notification only; no reviewer console | — |
| **HA deployment** | V1 is a single server; no clustering / failover | — |
| **SHA-256 hash chain on audit log** | V1 stores a per-record prompt hash, not a tamper-evident chain | `audit/` |
| **Full AI intent classifier** | V1 uses rule-based intent only; AI-judging-AI adds a new attack surface | Stage 9 |
| **Real LLM backend** | V1 ships a stub assistant behind a clean interface; swap-in is a one-line change | `assistant/` |
| **Chat frontend** | V1 is API-only (`POST /v1/chat`); no UI | — |

## Note on the monitoring path

R-12 and R-13 land in the monitoring layer (`app/monitoring/`), extending V1's
signal counters (`signals.py`) into behavioural baselining. This is the natural
V2 growth of the Day-1/2 monitoring work.
