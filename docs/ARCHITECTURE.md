# Architecture

Status: v1.0

## 1. Design principles

1. **Enforcement, not persuasion.** The agent is never asked to be careful; it is made unable to exceed its authorization.
2. **Deterministic decisions.** No LLM participates in an allow/deny decision.
3. **Default deny, fail closed.** Anything unrecognized, malformed, expired, ambiguous or erroring is not executed.
4. **Bind approvals to facts.** An approval covers one exact action, on one resource version, under one policy and one provenance state, once.
5. **Reject rather than normalize.** Formats are strict enough that normalization is rarely needed; what cannot be proven equivalent is refused.
6. **Same agent, same tools, different routing.** The unprotected baseline differs from the protected setup only by the path between the agent and the tools.

## 2. Components

```
                ┌────────────────────┐
                │      Ollama        │
                └─────────▲──────────┘
                          │ net_llm
┌─────────────────────────┴─────┐
│ Agent container (untrusted)   │
│ tool-calling loop, agent token│
└──────────────┬────────────────┘
               │ net_agent (TB1)
┌──────────────▼────────────────────────────────────┐
│ Gateway (trusted)                                 │
│ validation → canonicalization → policy → approvals│
│ → budget ledger → provenance → audit   SQLite WAL │
└──────▲───────────────────────────────┬────────────┘
       │ net_approval (TB3)            │ net_tools, internal (TB2)
┌──────┴───────────┐        ┌──────────▼─────────────────────┐
│ Approver CLI     │        │ Tools service (protected)      │
│ approver key     │        │ executor API + admin API       │
└──────────────────┘        └──────────▲─────────────────────┘
                                       │ net_control, internal (TB5)
                            ┌──────────┴─────────────────────┐
                            │ Benchmark controller           │
                            └────────────────────────────────┘
```

| Component | Responsibility | Holds |
|---|---|---|
| Agent | Tool-calling loop over Ollama; proposes actions to the Gateway | Agent token only |
| Gateway | Single decision and execution point for every tool call, reads included | Executor token, approver registry, policy |
| Approver CLI | Displays approval requests with provenance; signs decisions | One approver private key |
| Tools service | Simulated stateful backends. Enforces executor token, idempotency keys and version preconditions itself. Labels resources `internal`/`external`. | Simulated data, execution table |
| Benchmark controller | Seeds and resets state, snapshots final state, runs episodes | Admin token |

## 3. Network and hardening

- Networks: `net_agent` (agent ↔ Gateway), `net_llm` (agent ↔ Ollama), `net_approval` (approver ↔ Gateway), `net_tools` (`internal: true`, Gateway ↔ Tools executor API), `net_control` (`internal: true`, controller ↔ Tools admin API).
- No service uses the default network. No Tools port is published on the host.
- All containers: non-root, `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, no Docker socket, secrets mounted only where listed above.
- The Tools service listens on two ports: executor API on `net_tools`, admin API on `net_control`. Each requires its own token.

## 4. Canonicalization (canon v1)

Hashing uses a canonical JSON encoding: UTF-8 (non-ASCII characters are not escaped), keys sorted by Unicode code point, no insignificant whitespace, strings only for decimal values. Parsing rejects duplicate keys, `NaN`/`Infinity`, every float (any number with a fraction or an exponent, and `-0`) and integers outside ±(2^53 − 1).

Per-tool rules:

| Field type | Rule |
|---|---|
| Resource identifiers | Opaque IDs issued by the Tools service, strict pattern (e.g. `^doc_[0-9]{1,8}$`). No path syntax: `./doc_1` is rejected, not normalized. |
| Amounts | JSON string `^(0\|[1-9][0-9]{0,6})\.[0-9]{2}$` (no leading zeros), strictly positive, + currency code from an allow-list. Numbers are rejected. |
| E-mail recipients | Referenced by `contact_id` from the Tools directory, not by raw address. |
| Free text (subject, body, config values) | Must be valid UTF-8 in NFC; characters in Unicode categories Cc, Cf, Cs, Co, Cn, Zl and Zp are rejected (control, invisible format, surrogate, private-use, unassigned, line and paragraph separators). Only exception: U+000A in multi-line fields (e-mail body, document content). Hashed byte-exact. |
| Unknown fields | Rejected (strict Pydantic models, `extra="forbid"`, no coercion). |

The action hash covers the tool, the resource and the validated arguments:

```
action_hash = "sha256:" || hex(SHA-256(canonical_json(
  {"args": {…}, "canon_version": 1, "resource_id": …, "tool": …})))
```

`reason` is not hashed. `agent_id` and `session_id` are bound by the signed decision (§7), not by the hash.

`canon_version` is stored in each approval. A change of rules invalidates outstanding approvals.

## 5. Policy

Declarative YAML, loaded at start-up only (no hot reload). Its SHA-256 is the `policy_hash`, stored with every approval and audit event.

```yaml
tools:
  issue_refund:
    tier: R2
    constraints:
      max_amount: "500.00"
      currency: [EUR]
    budgets:
      - key: [account_id]          # global cap, shared by all agents
        window: 24h
        max_total: "1000.00"
      - key: [agent_id]            # secondary per-agent cap
        window: 24h
        max_total: "600.00"
  delete_document:
    tier: R2
    on_tainted_session: require_approval   # or: deny
default: deny
approval:
  ttl_seconds: 300
  max_pending_per_session: 3
```

## 6. Provenance

- Every read goes through the Gateway, which receives the resource's trust label from the Tools service.
- Each session has a `provenance_version` counter and a list of observed external sources. The counter increments whenever a new external source enters the session.
- A session with at least one external source is **tainted**.
- An approval request shows: action, agent, resource, the agent's stated reason (marked unverified), taint status and observed sources.
- Provenance covers only what the Gateway observed. Agent claims about provenance never change it.

## 7. Approval

### Record

`action_id`, `agent_id`, `session_id`, `tool`, `resource_id`, `resource_version`, `action_hash`, `policy_hash`, `canon_version`, `provenance_version`, provenance snapshot, `nonce` (Gateway-generated, 128 bits), `created_at`, `expires_at`, `status`.

### Signed decision

The approver signs, with Ed25519:

```
"AGENT-GATEWAY/APPROVAL-DECISION/v1\x00" || canonical_json(payload)
```

```json
{
  "decision": "APPROVE",
  "action_id": "act_123",
  "agent_id": "agent_01",
  "session_id": "sess_01",
  "tool": "delete_document",
  "resource_id": "doc_142",
  "resource_version": 12,
  "action_hash": "sha256:…",
  "policy_hash": "sha256:…",
  "canon_version": 1,
  "provenance_version": 4,
  "approver_id": "human_01",
  "nonce": "…",
  "issued_at": "2026-11-11T10:00:00Z",
  "expires_at": "2026-11-11T10:05:00Z"
}
```

The Gateway accepts a decision only if:
- `approver_id` is in the registry and the signature verifies against its key;
- `approver_id` is not an agent principal;
- every field equals the stored record;
- `expires_at` is no later than the record's;
- the record is still `PENDING_APPROVAL`.

The domain-separation prefix prevents the signature from being reused in another context.

## 8. Execution

### State machines

```
Action:  PROPOSED → DENIED
                  → ALLOWED ─────────────────────┐
                  → PENDING_APPROVAL → REJECTED  │
                                     → EXPIRED   │
                                     → INVALIDATED (policy / provenance / canon changed)
                                     → APPROVED ─┤
                                                 ▼
                                            EXECUTING → COMMITTED
                                                      → FAILED
                                                      → UNKNOWN → (reconcile) → COMMITTED | FAILED

Budget reservation:  RESERVED → COMMITTED
                              → RELEASED   (only once the Tools service confirms non-execution)
                              → HELD       (while UNKNOWN)
```

### Sessions

A session is created by a trusted party (the benchmark controller here, an orchestrator in production) through an admin-only Gateway endpoint, on a network and with a credential the agent container never has. The endpoint returns an agent token bound to exactly one `session_id` and one `agent_id`. The agent API offers no way to create a session, switch session, or reset provenance: otherwise an agent could read injected content in one session and propose the resulting action from a clean one.

### Steps

1. **Propose** `POST /v1/actions` with `{tool, resource_id, args, reason}`. `agent_id` and `session_id` come from the token, never from the payload.
2. **Validate and canonicalize** (§4), then compute `action_hash`.
3. **Decide** from the policy (§5): `DENY`, `ALLOW` (R0/R1 within constraints), or `REQUIRE_APPROVAL`. The order is fixed: validate, decide, and only then look up the resource version, for `ALLOW` and `REQUIRE_APPROVAL` only. A `DENY` never contacts the Tools service. If the session's provenance changes between the decision and its recording, nothing is recorded and the agent must propose again.
4. **`ALLOW`**: the Gateway executes within the same request, through the internal execution path (step 6), and returns the result in one round trip. Decision and intent are recorded in one transaction, so a provenance change between two calls cannot invalidate a read.
5. **`REQUIRE_APPROVAL`**: the action is recorded as `PENDING_APPROVAL`. Once a signed decision has approved it, the agent calls `POST /v1/actions/{id}/execute` with the arguments sent **again**. In one `BEGIN IMMEDIATE` transaction, the Gateway:
   - verifies status, expiry, signature, `action_hash`, `policy_hash`, `canon_version` and `provenance_version`;
   - checks and reserves every applicable budget (`RESERVED`);
   - records the intent (step 6a).

   If any step fails, the transaction rolls back and nothing is executed.
6. **Internal execution path**, shared by `ALLOW` and approved actions:
   - a. **Record the intent**: in a Gateway transaction, create an `execution_id` (the idempotency key), set the action to `EXECUTING` and insert the corresponding audit events.
   - b. **Call the Tools service** with the executor token, `Idempotency-Key: execution_id` and `If-Match: resource_version`. The Tools service checks the precondition and records the execution in one transaction; a repeated key returns the stored result without executing again.
   - c. **Record the outcome** in a second Gateway transaction:
     - success ⇒ `COMMITTED`, budget committed;
     - explicit failure with a confirmed non-execution ⇒ `FAILED`, budget released;
     - timeout or lost response ⇒ `UNKNOWN`, budget held.

   There is no atomic transaction across the Gateway database and the Tools service. The guarantee comes from the order (intent recorded before the call, outcome after it), from the idempotency key enforced by the Tools service, and from keeping `UNKNOWN` until reconciliation.
7. **Reconcile** `UNKNOWN` (and any `EXECUTING` found at Gateway start-up) by querying `GET /executions/{execution_id}` on the Tools service.

An approval is never restored after consumption. Any retry requires a new approval.

## 9. Audit

- `audit_events` SQLite table, written in the **same transaction** as the security state transition it records. If the insert fails, the transaction rolls back and the action does not proceed.
- Append-only, enforced by triggers that reject `UPDATE` and `DELETE`.
- Each event stores `seq`, `prev_hash`, `event_hash = SHA-256(prev_hash || canonical event)` and the `policy_hash`.
- `verify-audit` recomputes the chain and detects a modified entry.
- Bypass measurement relies first on cross-checking the Tools service execution table against the Gateway's records, not on the audit log alone.
- Events can be exported as JSONL.
- Deferred: external anchoring of the chain head and truncation detection. A log truncated at its tail still verifies; this is a stated non-guarantee.

## 10. Baseline mode

For the comparative experiment, the agent gets a direct client to the Tools executor API (executor token injected, agent attached to `net_tools`). Agent code, prompts, tools and scenarios are identical; only the routing changes.

## 11. Guarantee map

| Goal | Enforced by |
|---|---|
| G1 | Tiering, signed decision checks (§7), execution transaction (§8.4), network isolation (§3) |
| G2 | `action_hash`, `resource_version`, `policy_hash`, `provenance_version`, single-use consumption |
| G3 | Account- and agent-level budgets reserved inside the execution transaction |
| G4 | Rollback on any failure; `UNKNOWN` keeps budget held until reconciled |
| G5 | Audit events in the same transaction (§9) |
| G6 | Provenance derived from proxied reads only (§6) |
| G7 | Tools-side idempotency keys and preconditions (§8.5) |

## 12. Technology

Python 3.12, FastAPI, Pydantic v2 (strict), SQLite (WAL), `cryptography` (Ed25519), pytest, Docker Compose, Ollama.

Canon v1 relies on the Unicode database of the interpreter (NFC, general categories). It is pinned to Python 3.12 (Unicode 15.0): every Docker image must use Python 3.12. Another Unicode version requires a new `canon_version`.
