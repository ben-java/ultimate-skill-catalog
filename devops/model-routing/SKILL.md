---
name: model-routing
description: "Use when choosing a model/provider per task; tier routing."
---

# Model Routing (tier-based selection)

> **Manual-only activation:** this skill is NOT active by default. It only applies when the user explicitly invokes it or asks to route models. Otherwise the default model stays `mercury-3` (inceptionlabs) untouched.

Assign a model per task class instead of one model for everything. Goal: enough capability for the work without wasting tokens/quota.

## Collaboration with task-observer
`task-observer` watches real task execution and logs observations (failures, latency, cost, corrections). This skill consumes those observations to keep model selection accurate:
- If `task-observer` logs that a route model keeps failing/busy or is slow/costly, reflect that in the fallback chains below (move the offending model down / add a verified-stable alternative).
- Conversely, when this skill changes a route, log it as an observation (via `task-observer`) so the change is auditable.
- Trigger: when running under `task-observer`, treat `model-routing` choices as observation targets; when running `model-routing`, expect/register reliability signals from observed runs.

## Role-based routing (user-preferred)
Two roles share the work; each has its own primary + fallback chain (primary first, fall on busy/error).

| Role | Primary → fallback chain |
|---|---|
| 🧠 **Plan maker** (main agent turn / orchestrator) | `wz/mimo-v2.6-pro` (×6.5) → `cx/gpt-6.1-sol` (×4) → `cx/claude-sonnet-5.5`-class (×5) |
| ⚡ **Agent/subagent** (`delegate_task` children) | `mercury-3` (inceptionlabs) → `wz/muse-spark-1.3-contributor` (×2.3) → `wz/mimo-v2.6-flash` (×3.5) |

Note: `mercury-3` (fast primary) is the configured **primary model** (`model.default` via `inceptionlabs`). Fallback chain (verified via `hermes fallback list`): `mercury-3` → `wz/muse-spark-1.3-contributor` → `wz/mimo-v2.6-flash` → `wz/deepseek-v4.1-flash`. **Retry-before-failover**: `agent.api_max_retries = 3` — a model is retried 3× before the chain advances, so it does NOT switch on the first error. Global setting → applies to all tiers. `delegation` (subagents) stays single-provider on weizerouter; this cross-provider chain is the routing map the main agent follows. Fast-tier `wz/muse-spark-1.3-contributor` is a data-training tier (gate `security.allow_data_training_tiers_noninteractive` = true) and intermittently busy, hence the fallback chain. Effective cost = multiplier × Rp65/1M; full official table in `references/weizerouter-multipliers.md`.

## Where routing is configured in this Hermes install
- **No external delegation plugin is present** (plugins = `billion-context`, `hindsight`). The capability is native:
  - `config.yaml` → `delegation:` — override `model`/`provider` per subagent, plus `fallback_providers` chain for children.
  - `config.yaml` → `auxiliary:` (commented) — lightweight models for side tasks (image analysis, compression).
- **Verify a capability exists before claiming or building on it.** Grep the config/plugins first; never assume a plugin from a tutorial is installed.

## Pitfalls
- **Avoid busy-prone models as defaults/flagship routes**: on WeizeRouter, `wz/muse-spark-1.3-contributor`, `wz/qwen3.8-flash`, `wz/gemini-3.8-flash(-high)`, `wz/gemini-3.7-flash`, `wz/pria-solo-utara`, `cx/gpt-5.5(-review)` intermittently return `server_load_busy`/`wz_upstream_busy`. Prefer the verified-stable list for anything automatic/long-running.
- **Always keep a fallback chain**: a live provider can be down or busy — set `fallback_providers`/fallback models so the route degrades instead of erroring.
- **Don't burn deep-tier quota on fast-tier work** — that is the whole point of routing; fast tier has the lowest multiplier.
- **Only use models whose credential/availability is verified** before wiring them as a default. `pi-bolt auth check --provider <p> --model <m> --json` → `{"status":"ready",...}` proves credential readiness; do not claim an end-to-end answer until a model response is actually recorded.

## Ally skills (wire-in)
These skills reinforce `model-routing` in well-defined ways:
- `pi-bolt` / `pi-agent` — fast non-interactive subagent execution engine; the natural executor for the agent/subagent role.
- `pstack-verify` / `delivery-gate` — verify (with physical evidence) that a chosen model actually responded before trusting a route change.
- `context-compressor` / `llm-text-compressor` — keep route/reliability telemetry cheap to read.
- `task-observer` — feeds reliability/cost/failure observations into the chains; see Collaboration section.
- `last30days` / `research-lookup` / `parallel-web` — research better/cheaper/newer models and provider status.
- `competitor-news-monitor` / `product-price-monitor` — watch provider availability/pricing changes.
- `ben-mode` — provides the integrity spine (HARD GATE #10) around all of the above.

## References
- `references/weizerouter-multipliers.md` — official multiplier table (cost per 1M tokens) for WeizeRouter models, and which models have unpublished multipliers.
