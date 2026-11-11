# Architecture

Status: v1.5. Since v1.4: a third agent route, read-only, gives the status of the session's own action (§8); the benchmark support of the Tools service and of the Gateway state view is described (§8, §10); what the model is shown is the same in both routings (§10). The approver channel has a read-only status route (§7). Both status routes were added after L2 run 2 and have not been attacked. Evidence levels: [`EVIDENCE.md`](EVIDENCE.md).

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
| Approver CLI | Displays approval requests with provenance; signs decisions | One approver private key, the approver-channel token |
| Tools service | Simulated stateful backends. Enforces executor token, idempotency keys and version preconditions itself. Labels resources `internal`/`external`. | Simulated data, execution table |
| Benchmark controller | Seeds and resets state, snapshots final state, runs episodes | Admin token |

## 3. Network and hardening

The diagram in §2 shows the logical components. The deployment is configured as nine containers so that reachability is meant to follow from network membership: the configuration gives a container that holds a privileged credential no network in common with the agent, except the agent-facing Gateway API.

This section describes the Compose configuration and the intent behind it. The second L2 run attacked it from inside the agent container and passed, with passing positive controls: one run, on one Docker Desktop version, by TCP connect and DNS from one agent container. What that run attempted, and what it did not, is in [`EVIDENCE.md`](EVIDENCE.md). The description below remains a configuration, not a proof of isolation.

### Topology by authorized clients

| Container | Networks | Authorized clients | Intended enforcement |
|---|---|---|---|
| `agent` (untrusted) | `net_agent`, `net_llm` | none | — |
| `gateway-api` | `net_agent`, `net_tools` | agent | session token; the only Gateway process with Tools access |
| `gateway-admin` (sessions, revocation, read-only state) | `net_admin` | controller | admin token; no network shared with the agent or the Tools service |
| `gateway-approver` | `net_approval` | approver | channel token for listing and for reading a request's status, signature for decisions; no Tools network |
| `tools-executor` | `net_tools` | `gateway-api` | executor token |
| `tools-admin` | `net_control` | controller | Tools admin token |
| `approver` | `net_approval` | none | — |
| `controller` | `net_admin`, `net_control` | none | — |
| `llm-relay` | `net_llm`, `net_egress` | agent | relay contract below |

- Every network is declared `internal: true` except `net_egress`, which only the relay joins. The configuration publishes no port on the host, uses no default network, and mounts the Docker socket nowhere.
- The two agent networks set `com.docker.network.bridge.inhibit_ipv4`, so that the Docker host has no IPv4 address on them. The first L2 run found that, without it, the agent could reach services of the Docker Desktop virtual machine (`rpcbind`, `rpc.statd`) through the bridge address. The five other networks keep a host address; only trusted containers are attached to them.
- Each container runs one application on one port. `gateway-api` contains no client for the admin or approver applications and relays nothing to them.
- The three Gateway containers share one SQLite database on a named volume; the two Tools containers share another. The agent is given neither.
- The agent containers used for multi-agent tests share `net_agent` and `net_llm`, so they are expected to be able to reach each other. A compromised agent could pass content or its session token to another one, outside the Gateway's view (see `THREAT_MODEL.md` §9).
- All containers: Python 3.12 image pinned by digest, fixed non-root user, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, a small tmpfs for `/tmp`.

### Secrets

Secrets are files mounted read-only in the containers of their role, never environment variables. A process that needs a secret it was not given refuses to start.

| Secret | Held by |
|---|---|
| Executor token | `gateway-api`, `tools-executor` |
| Tools admin token | `tools-admin`, `controller` |
| Gateway admin token (session creation and revocation) | `gateway-admin`, `controller` |
| Approver-channel token | `gateway-approver`, `approver` |
| Approver private key | `approver` |
| Agent session token | issued per episode; `controller` → volume → `agent` |

The Gateway receives only the public approver registry.

### Episode token

The controller creates a session and writes its token to a volume that it mounts read-write and the agent mounts read-only. The configuration gives the two no network in common. At the end of the episode the controller revokes the session; the file is then replaced atomically by the next token, so the volume holds one token. Revocation is enforced by the Gateway, not by removing the file (§8).

### LLM relay

The model runs on the host, bound to its loopback interface. The agent reaches it only through the relay:

- method and route: `POST /api/chat`, nothing else;
- model: must be on the configured allow-list (`qwen3:8b`);
- body: bounded size, strict JSON, fields limited to `model`, `messages`, `tools`, `stream`, `options`, `think`; `stream` is always false upstream; unknown fields and unknown options are rejected;
- destination: fixed in the relay's configuration. There is no destination parameter, no generic proxying, no redirect following;
- `/api/pull`, `/api/push`, `/api/create`, `/api/delete`, `/api/copy` and the other model-management routes are refused explicitly; any other route does not exist.

At start-up the relay checks that the upstream answers and serves the allowed model, and logs the model's digest; this check has run in a container. `net_egress` is an additional trust boundary: the relay is configured as the one container with a route out, so a compromised relay is an egress path.

### SQLite

Every connection sets `journal_mode=WAL` and `synchronous=FULL` and verifies both; a service refuses to start on a database that cannot honour them. Databases live on named volumes, not on host bind mounts.

### Baseline

The unprotected comparison is a separate Compose project with its own Tools service, networks, state and credentials. It shares nothing with the protected project.

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

`action_id`, `agent_id`, `session_id`, `tool`, `resource_id`, `resource_version`, `action_hash`, `policy_hash`, `canon_version`, `provenance_version`, `nonce` (Gateway-generated, 128 bits), `created_at`, `expires_at`, `status`.

The record stores the provenance version, not a copy of the sources. The external sources shown to the approver are computed from the session when pending requests are listed. They cannot differ from the state at proposal time without the version having changed, which invalidates the approval.

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
  "issued_at": "2026-11-11T10:00:00.000000Z",
  "expires_at": "2026-11-11T10:05:00.000000Z"
}
```

The Gateway accepts a decision only if:
- `approver_id` is in the registry and the signature verifies against its key;
- `approver_id` is not an agent principal;
- every field equals the stored record;
- `expires_at` is no later than the record's;
- the record is still `PENDING_APPROVAL`.

The domain-separation prefix prevents the signature from being reused in another context.

Timestamps are UTC with microseconds, in the one format shown above. A decision that fails any check changes nothing: it cannot consume or cancel a pending approval. The same checks run again inside the execute transaction, against the registry as it is then.

The approver channel is a separate Gateway application. Listing pending requests requires an approver-channel token, never mounted in the agent container; a decision is authenticated by its signature alone. With the same token, `GET /v1/approvals/{id}` returns the current status of an action that went through approval (`{action_id, status}`), read-only: it tells an approver what became of a request it decided. The approver application has exactly these three routes. A request shows the action and its arguments, the agent, the resource, the taint status and observed sources, and the agent's stated reason under a label that marks it unverified.

A session may hold at most `max_pending_per_session` pending approvals; a further proposal that would need one is denied.

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

An `APPROVED` action can still become `EXPIRED` or `INVALIDATED` before it is consumed.

Budget reservation:  RESERVED → COMMITTED
                              → RELEASED   (only once the Tools service confirms non-execution)
                              → HELD       (while UNKNOWN)
```

### Sessions

A session is created, and later revoked, by a trusted party (the benchmark controller here, an orchestrator in production) through an admin-only Gateway application, on a network and with a credential the agent container never has. A revoked session stays revoked; its pending and approved actions are invalidated. Revocation is checked against the database on every request, and again inside the transaction that would record or consume anything. The guarantee is stated on the commit order of Gateway transactions: no action whose authorization transaction commits after the revocation commits is authorized, consumed or sent to the Tools service. An action whose authorization transaction committed before the revocation may complete: its call to the Tools service, its effect there, and for a read the return of the content, can all happen after the revocation. Such an action was authorized before the revocation; its effect was not necessarily produced before it. One limitation in flight: a mutating request that is revoked between its first check and its transaction can still learn, from the resource lookup, whether a resource exists.

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
7. **Reconcile**, in the Gateway API process only (the admin and approver processes have no access to the Tools service): `UNKNOWN` in a background loop, and any `EXECUTING` found at start-up, when no call can be in flight. Reconciliation asks the Tools service to resolve the `execution_id` (`POST /executions/{execution_id}/resolve`). The answer is `EXECUTED` or `FAILED`. A key the Tools service has never seen is recorded there as failed in the same step, so a request lost in transit cannot execute after its budget has been released.

8. **Status**, read-only: `GET /v1/actions/{id}` with the token of the session that proposed the action returns `{action_id, status, reason}`. `reason` is a fixed word derived from the status (`denied_by_policy`, `rejected_by_approver`, `approval_expired`, `approval_invalidated`, `execution_failed`, or null). It names no approver, policy rule or other session, and it changes no state. An action of another session gets the same 404 as an action that does not exist. Its purpose is to let an agent tell an approver's rejection from the other refusals of the execute route.

The agent API has exactly these three routes: propose, execute, status.

An approval is never restored after consumption. Any retry requires a new approval.

### Benchmark support

These exist for measurement and are reachable only by the trusted controller, on the admin networks.

- **Faults.** A rule on the Tools admin API names a tool, optionally a resource, the nth matching call and a hold point (before or after the effect is committed). A held request waits for the controller to release it. A rule armed with `auto_release: drop` releases itself when it trips: before commit, nothing is executed and the caller gets an error; after commit, the effect is applied and the response is lost. The Gateway treats both as ambiguous (`UNKNOWN`) until reconciliation.
- **Execution log.** Each Tools execution records its canonical arguments next to the idempotency key, tool, resource and status. A key abandoned before any request has no arguments.
- **State view.** `GET /admin/state` on the Gateway admin application returns every action with its arguments, bound fields and stored approval record (nonce, expiry, payload, signature), the budget reservations and the audit chain check. It is read-only. It is what the bypass cross-check compares the Tools execution log with.

Budgets use a rolling window on the Gateway clock. `RESERVED`, `HELD` and `COMMITTED` reservations all count against a cap. If a cap would be exceeded, the execute transaction writes nothing and the approval stays unconsumed.

## 9. Audit

- `audit_events` SQLite table, written in the **same transaction** as the security state transition it records. If the insert fails, the transaction rolls back and the action does not proceed.
- Append-only, enforced by triggers that reject `UPDATE` and `DELETE`.
- Each event stores `seq`, `prev_hash`, `event_hash = SHA-256(prev_hash || canonical event)` and the `policy_hash`.
- `verify-audit` recomputes the chain and detects a modified entry.
- Bypass measurement relies first on cross-checking the Tools service execution table against the Gateway's records, not on the audit log alone.
- Deferred: JSONL export of events, external anchoring of the chain head and truncation detection. A log truncated at its tail still verifies; this is a stated non-guarantee.

## 10. Baseline mode

For the comparative experiment, the agent gets a direct client to the Tools executor API (executor token injected, agent attached to `net_tools`). Agent code, prompts, tools and scenarios are identical; only the routing changes. The baseline project has its own LLM relay, under the same contract.

**What the model sees.** In both routings the client gives the model a normalized reply of one shape: `status` (`executed`, `refused`, `rejected`, `pending_approval` or `unknown`), `result` when executed, `error` and sometimes `reason` otherwise. Trust labels and the provenance source list are removed from everything the model sees; they are inputs of the Gateway, not of the agent. The raw service replies are kept in the transcript only. For the same seeded state and the same tool call the two routings give the model the same reply, except where the outcome itself differs (pending approval, rejection, denial by policy).

**Approval wait.** After a `REQUIRE_APPROVAL`, the client polls the execute route for 20 s. When the wait expires the model is told the action is pending, and the action stays as it is: nothing is cancelled. Every call from the model is a new proposal.

## 11. Guarantee map

| Goal | Mechanisms (what is verified for each: `EVIDENCE.md`) |
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
