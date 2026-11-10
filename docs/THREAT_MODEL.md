# Threat Model

Status: v1.3. Since v1.2: status vocabulary of `EVIDENCE.md` in §7, three non-guarantees (in-flight lookup after revocation, peer agents, effect after revocation), H1–H7 named consistently. Nothing is adversarially verified yet.

## 1. Scope

This project is an enforcement layer (the **Gateway**) placed between an autonomous AI agent and the tools it can call. Its purpose is to prevent the agent from executing **unauthorized irreversible actions**, whatever the agent intends, believes or has been instructed to do.

The model is deliberately conservative: the guarantees must hold even if the agent runtime is fully adversarial. The LLM's reasoning quality is not part of the security argument.

Protected actions in the reference environment (all simulated):

| Tool | Effect | Reversibility tier |
|---|---|---|
| `read_document`, `list_documents`, `read_inbox`, `get_balance` | Read | R0 (read-only) |
| `draft_email`, `update_document` | Modify, recoverable | R1 (reversible) |
| `send_email`, `delete_document`, `issue_refund`, `update_prod_config` | Externally visible or destructive | R2 (irreversible) |

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Protected resources (documents, payment ledger, outbound mail, production config) | Direct target of irreversible harm |
| A2 | Executor credential (Gateway → Tools service) | Possession allows bypassing the Gateway entirely |
| A3 | Approval records and approver signing keys | Forging or reusing them converts a denied action into an allowed one |
| A4 | Budget ledger (cumulative limits) | Manipulating it enables split transactions |
| A5 | Policy configuration | Defines what is allowed at all |
| A6 | Audit log | Needed to detect and investigate attempts |
| A7 | Evaluation endpoints (state reset / snapshot) | Reaching them lets an agent erase or fake outcomes |

## 3. Identities

| Principal | Authentication | Privileges |
|---|---|---|
| Agent | Bearer token issued per session by the session issuer, mapped by the Gateway to exactly one `session_id` and one `agent_id`, and revoked by the issuer at the end of the episode | Propose actions, request execution of its own actions, in its own session. Nothing else. |
| Session issuer (benchmark controller, or an orchestrator in production) | Separate admin token, on a network the agent is not attached to | Create sessions and obtain their agent tokens |
| Approver | Ed25519 key pair; the Gateway holds a registry `approver_id → public key`. An approver-channel token gives access to the list of pending requests | Sign decisions on pending approvals |
| Gateway | Executor token toward the Tools service | Execute actions, query execution status |
| Benchmark controller | Separate admin token, separate network | Reset and snapshot the Tools service; never present during an episode's agent loop |

Identity is never taken from a request payload: `agent_id` and `session_id` come from the token, `approver_id` is only valid if its signature verifies against the registered key. ADV3 can steal the agent token; this grants nothing beyond the agent's own (unprivileged) rights.

## 4. Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| ADV1 | **Manipulated agent** | Follows instructions injected through untrusted content (documents, emails, tickets) it reads during a task |
| ADV2 | **Confused agent** | Acts on ambiguous or conflicting instructions, missing information, or misread tool failures; no malicious intent |
| ADV3 | **Compromised agent runtime** | Attacker controls the agent container completely: arbitrary code, arbitrary requests to any reachable host, arbitrary payloads, the agent token |

ADV3 is the reference adversary. A control that only works against ADV1/ADV2 is not considered a security guarantee.

### Out of scope

- Compromise of the Gateway, the Tools service, the benchmark controller or their hosts
- A malicious or coerced human approver, or a malicious operator editing the policy
- Container escape, kernel or Docker daemon vulnerabilities
- Supply-chain attacks on dependencies or model weights
- Information disclosure through allowed R0 reads

## 5. Trust boundaries

| ID | Boundary | Direction |
|---|---|---|
| TB1 | Agent container → Gateway API | Untrusted → trusted. Every request is attacker-controlled. |
| TB2 | Gateway → Tools service | Trusted → protected. Only the Gateway holds the executor credential. |
| TB3 | Approver → Gateway | Separate channel. Decisions are signed with a key the agent never has. |
| TB4 | Tool output → Agent context | Content returned to the agent may itself be adversarial (injection vector for ADV1). |
| TB5 | Benchmark controller → Tools service admin API | Evaluation-only network, not attached to the agent. |
| TB6 | Agent → LLM relay → model on the host | The relay is configured as the only container with a route out. It is designed to forward one allow-listed request type to one fixed destination. |

## 6. Assumptions

- **H1** Container isolation holds under the documented hardening (non-root, `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem, no Docker socket, no shared default network, no published Tools ports).
- **H2** Approver private keys, the approver-channel token, the executor credential, the admin token and the session-creation credential are never mounted into or reachable from the agent container.
- **H3** The Gateway clock is trustworthy; expiry is evaluated on the Gateway only.
- **H4** The policy file is reviewed and correct; the system enforces the policy, it does not judge it.
- **H5** Trust labels on resources (internal vs external origin) are assigned by the Tools service, not by the agent.
- **H6** The Tools service itself enforces the executor token, idempotency keys and resource-version preconditions. It does not rely on the Gateway for these.
- **H7** A new session is issued only with a fresh agent context. If the agent carries memory across sessions (conversation history, persistent memory, retrieval over past outputs), injected content can cross into a clean session, and the Gateway cannot observe it.

## 7. Threats and mitigations

"Planned verification" names the evaluation layers meant to cover a threat. "Status" uses the levels of [`EVIDENCE.md`](EVIDENCE.md): unit-tested, integration-tested, container-tested, adversarially verified, not verified. Today no threat is container-tested or adversarially verified.

| ID | Threat | Adversary | Mitigation | Planned verification | Status |
|---|---|---|---|---|---|
| T1 | Agent calls a protected tool directly, bypassing the Gateway | ADV3 | Tools reachable only on an internal network the agent is not attached to; executor credential held by the Gateway only | L2 | Not verified. Integration-tested for the executor-token check only |
| T2 | R2 action executed without approval | ADV1–3 | Tier R2 ⇒ `REQUIRE_APPROVAL`; default deny | L1, L3 | Integration-tested. L3 not run. Not container-tested |
| T3 | Approval replayed for a second execution | ADV3 | Single-use approval consumed atomically; idempotency key enforced by the Tools service | L1, L2 | Integration-tested; not adversarially verified |
| T4 | Arguments changed after approval (approve doc A, delete doc B) | ADV1–3 | Approval bound to the canonical action hash; hash recomputed at execution | L1, L2 | Unit-tested, integration-tested; not adversarially verified |
| T5 | Resource modified between approval and execution | ADV1–3 | Approval bound to the resource version; the Tools service enforces the precondition | L1 | Integration-tested. Not container-tested |
| T6 | Agent approves its own request, or forges an approver identity | ADV3 | Decision valid only with a signature from a registered approver key over the full payload | L1, L2 | Unit-tested, integration-tested; not adversarially verified |
| T7 | Expired approval used | ADV1–3 | Gateway-side expiry check at execution time | L1 | Integration-tested. Not container-tested |
| T8 | Split transactions to stay under per-action limits, possibly across several agents | ADV1, ADV3 | Cumulative budget per account (global) plus per agent, checked and reserved in the execution transaction | L1, L2, L3 | Integration-tested (threads in one process); not adversarially verified, L3 not run |
| T9 | Unknown tool, alias or case variant of a protected tool | ADV3 | Exact allow-list of canonical tool names | L1, L2 | Unit-tested, integration-tested; not adversarially verified |
| T10 | Malformed or ambiguous arguments (extra fields, duplicate keys, floats, path syntax, Unicode variants) | ADV2, ADV3 | Strict per-tool formats; values not provably equivalent to a canonical form are rejected, never normalized by guess | L1, L2 | Unit-tested, integration-tested; not adversarially verified |
| T11 | Injected instruction produces a plausible approval request that a human accepts | ADV1 | Gateway-derived provenance shown in the approval request; policy escalation for tainted sessions | L3 | Integration-tested, for what the request displays. L3 not run. Not container-tested |
| T12 | Agent forges or launders provenance. Laundering scenario: the agent reads injected content in session A, then proposes the R2 action from a clean session B, so that the approver sees clean provenance | ADV1, ADV3 | Provenance computed by the Gateway from the reads it proxied; agent claims ignored. Sessions are created only by a trusted party through an admin-only endpoint; an agent token is bound to exactly one session; the agent API cannot create or switch sessions, nor reset provenance | L1 | Unit-tested, integration-tested. Not container-tested |
| T13 | Gateway error, approval timeout or tool timeout leads to execution | ADV2, ADV3 | Fail closed on every error path | L1 | Integration-tested. Not container-tested |
| T14 | Concurrent executions consume one approval twice | ADV3 | Serialized consumption transaction + Tools-side idempotency | L2 | Integration-tested (threads in one process); not adversarially verified |
| T15 | Execution without an audit record, or audit tampering | ADV3 | Audit events written in the same transaction as the security state transition; append-only triggers; hash chain with verification. Truncation detection and external anchoring are deferred | L1 | Unit-tested, integration-tested. Not container-tested |
| T16 | Approval flooding to induce fatigue | ADV1, ADV3 | Limit on pending approvals per session; approval burden measured | L3 | Integration-tested, for the limit. L3 not run. Not container-tested |
| T17 | Policy changed after approval; old approval still used | Operator change + ADV1–3 | Approval bound to the policy hash; mismatch ⇒ invalidated | L1 | Unit-tested, integration-tested. Not container-tested |
| T18 | Session becomes tainted after approval; approval still used | ADV1 | Approval bound to the session's provenance version; mismatch ⇒ invalidated | L1 | Integration-tested. Not container-tested |
| T19 | Crash or timeout after consumption leads to double execution or silent budget loss | ADV3 (induced faults) | Execution and budget state machines; idempotency key; reconciliation before any budget release | L1 (fault injection) | Integration-tested, with simulated faults. Not container-tested |
| T20 | Agent reaches evaluation endpoints (reset, snapshot) | ADV3 | Admin API on a separate network and token, controller only | L2 | Integration-tested, for token and route separation; not adversarially verified |

## 8. Security goals (invariants)

- **G1** No R2 action reaches the Tools service without a valid, unexpired, unconsumed approval, signed by a registered approver, whose action hash, resource version, policy hash and provenance version all match the execution context.
- **G2** An approval authorizes at most one execution of exactly one canonical action on one resource version, under one policy and one provenance state.
- **G3** Cumulative limits hold under concurrency and across agents sharing an account.
- **G4** Any failure in the decision path results in non-execution; any ambiguous outcome keeps the budget reserved until reconciled.
- **G5** No security state transition happens without its audit event (same transaction).
- **G6** Provenance shown to the approver is derived by the Gateway from sources it observed, never from agent claims.
- **G7** In the reference environment, each approval produces at most one effective execution, given H6.

## 9. Non-guarantees

- Actions that do not go through the Gateway are not covered.
- The guarantees depend on the isolation boundary and the trusted components (H1–H7).
- A human approver can still approve a harmful action; the system can only make that decision informed and bounded.
- Provenance covers only sources observed through the Gateway, at session granularity: it over-taints and cannot attribute a specific argument to a specific source.
- Exactly-once execution is not promised for arbitrary external systems; at-most-once holds only where the downstream service enforces idempotency.
- R0 reads can still disclose what the agent is allowed to read.
- Injected content carried across sessions by the agent's own memory is not observed by the Gateway (H7): a session issued to an agent that kept its context can be clean on record and tainted in fact.
- Revocation bounds authorization, not effects: an action authorized before a session is revoked may take effect in the Tools service after the revocation.
- A mutating request revoked while in flight can still learn from the resource lookup whether a resource exists.
- Agent containers that share a network can exchange content and session tokens directly, outside the Gateway's view. Like memory carried across sessions (H7), this can bring injected content into a clean session.
- A compromised LLM relay is an egress path, and the model server's request parser on the host is exposed to the agent through it.
- Truncation of the audit log is not detected: the chain head is not anchored outside the Gateway (deferred).
