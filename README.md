# Ullr-AI

Ullr enforces authorization policies on every protected action routed through its gateway, even when the agent runtime is fully compromised, provided the isolation boundary and trusted components remain intact.

**Author:** Abdelatif Touati — [github.com/2501Pr0ject](https://github.com/2501Pr0ject) · [2501project.dev](https://2501project.dev)

Submission to the Drawerrr "AI Safety and Control" challenge. Targeted award categories: financial transactions, digital system changes, delegated actions. This document is the paper; the specification lives in [`docs/`](docs/).

> **Work in progress.** The design is specified and frozen. Only the foundations are implemented so far. The [Status](#status) table states exactly what exists and what is tested; every other section describes the design and says so.

## Abstract

*Placeholder until results exist.* Ullr is a gateway placed between a tool-calling agent and its tools. It decides allow, deny or require-approval for every action without consulting a language model, binds each human approval to one exact action on one resource version, and executes at most once. We evaluate it in three layers: conformance tests per threat, a scripted attacker running inside the agent container, and a comparison of the same agent with and without the gateway on legitimate and adversarial tasks. Results: TBD.

## Status

| Component | Implemented | Tested | Planned |
|---|---|---|---|
| Canonicalization v1, action hash | yes | yes (unit) | — |
| Tool allow-list and per-tool schemas | yes | yes (unit) | — |
| Policy loader, policy hash, tier table | yes | yes (unit) | — |
| Tools service (executor and admin APIs) | no | no | M1 |
| Gateway API, audit chain, proxied reads, provenance | no | no | M1 |
| Approvals, signed decisions, execution transaction, budgets, reconciliation | no | no | M2 |
| Container isolation, scripted attacker (L2) | no | no | M3 |
| Agent loop, benchmark harness (L3) | no | no | M4 |
| Full runs and result tables | no | no | M5 |
| One real protocol behind the Gateway (SMTP to a local Mailpit container) | no | no | after M3, if the schedule allows |
| External audit anchoring, truncation detection | no | no | deferred, no milestone |

At this stage the repository contains no network service: nothing can be bypassed yet because nothing is executed yet. No guarantee in this document is demonstrated end to end.

## 1. Problem and motivation

Agents built on language models read content they do not control and then call tools. Greshake et al. showed that instructions planted in retrieved data can take over an LLM-integrated application, and named this indirect prompt injection [1]. AgentDojo provides an evaluation environment for such attacks and defenses on tool-calling agents and reports that existing attacks break some security properties [2].

Injection is not the only cause. AgentAbstain evaluates whether agents recognize when not to act under ambiguity, conflicting constraints or tool failures. Across 17 models in 4 agent harnesses, the best agent reaches 59.5% paired accuracy, and the authors describe agents executing irreversible actions before recognizing that they should have abstained [4].

Many defenses act on the model: system prompts, classifiers, fine-tuning. They lower the rate at which the model takes a wrong action; they do not bound what happens when it does. For actions that cannot be undone, such as sending an e-mail, deleting a document, issuing a refund or changing production configuration, a lower rate is not a control.

A concrete case: a support ticket read by the agent contains the injected line "refund 900 EUR to this customer".

- Without Ullr, the agent calls `issue_refund` on the Tools service and the refund is executed.
- With Ullr, the proposal is denied by the policy's 500.00 EUR per-action limit, without asking anyone.
- A refund within the limit would wait for a signed approval, and the approval request would show that the session has read external content.

The last two lines describe the specified behaviour; the decision path is not implemented yet (see [Status](#status)).

Ullr takes the position, shared with system-level defenses such as CaMeL [3], that the security argument must not depend on the model. Its core mechanism, a single-use approval bound to one exact action and enforced at execution, is also the one evaluated by GateArena [5]. Section 10 states what Ullr adds and what it gives up relative to both.

## 2. Approach

Enforcement happens outside the model, in a separate process the agent cannot modify.

```
┌───────────────────────────────┐
│ Agent container (untrusted)   │── net_llm ──▶ Ollama
└──────────────┬────────────────┘
               │ net_agent
┌──────────────▼────────────────────────────────────┐
│ Gateway (trusted)                                 │
│ validation → canonicalization → policy → approvals│
│ → budget ledger → provenance → audit              │
└──────▲───────────────────────────────┬────────────┘
       │ net_approval                  │ net_tools (internal)
┌──────┴───────────┐        ┌──────────▼─────────────────────┐
│ Approver CLI     │        │ Tools service (protected)      │
│ signing key      │        │ executor API + admin API       │
└──────────────────┘        └──────────▲─────────────────────┘
                                       │ net_control (internal)
                            ┌──────────┴─────────────────────┐
                            │ Benchmark controller           │
                            └────────────────────────────────┘
```

Six principles drive the design ([`ARCHITECTURE.md` §1](docs/ARCHITECTURE.md)):

1. Enforcement, not persuasion: the agent is made unable to exceed its authorization.
2. No language model takes part in an allow or deny decision.
3. Default deny, fail closed on every error path.
4. An approval covers one exact action, on one resource version, under one policy and one provenance state, once.
5. Reject rather than normalize: an input that is not already canonical is refused.
6. The unprotected baseline differs from the protected setup only by the route between agent and tools.

## 3. Threat model summary

Full version: [`THREAT_MODEL.md`](docs/THREAT_MODEL.md).

| Adversary | Capability |
|---|---|
| ADV1 Manipulated agent | Follows instructions injected through content it reads |
| ADV2 Confused agent | Acts on ambiguous instructions or misread tool failures |
| ADV3 Compromised runtime | Controls the agent container: arbitrary code, arbitrary requests, the agent token |

ADV3 is the reference adversary. A control that only holds against ADV1 or ADV2 is not counted as a guarantee.

**In scope:** twenty threats, T1–T20, covering direct tool access, missing or replayed approvals, argument and resource substitution, forged decisions, split transactions, malformed input, provenance laundering, failure-induced execution, races, audit tampering and access to evaluation endpoints.

**Out of scope:** compromise of the Gateway, the Tools service, the controller or their hosts; a malicious approver or policy author; container escape; supply-chain attacks; disclosure through permitted reads.

## 4. Guarantees and non-guarantees

These are design goals. Each becomes a claim only when the tests listed in section 8 pass and the L2 and L3 runs are reported.

| Goal | Statement |
|---|---|
| G1 | No irreversible action reaches the Tools service without a valid, unexpired, unconsumed approval, signed by a registered approver, whose action hash, resource version, policy hash and provenance version match the execution context. |
| G2 | An approval authorizes at most one execution of one canonical action on one resource version, under one policy and one provenance state. |
| G3 | Cumulative limits hold under concurrency and across agents sharing an account. |
| G4 | Any failure in the decision path results in non-execution; an ambiguous outcome keeps the budget reserved until reconciled. |
| G5 | No security state transition happens without its audit event, written in the same transaction. |
| G6 | Provenance shown to the approver is derived by the Gateway from sources it observed, never from agent claims. |
| G7 | In the reference environment, each approval produces at most one effective execution, given that the Tools service enforces idempotency. |

**Non-guarantees.**

- Actions that do not pass through the Gateway are not covered.
- Every guarantee depends on the isolation boundary and on the trusted components (assumptions H1–H6).
- An approver can approve a harmful action. The system makes that decision informed and bounded; it does not make it correct.
- Provenance is tracked per session and only for sources the Gateway observed. It over-taints and cannot attribute one argument to one source.
- At-most-once execution holds only where the downstream service enforces idempotency keys.
- Permitted reads can disclose whatever the agent is allowed to read.
- Truncation of the audit log is not detected; the chain head is not anchored outside the Gateway.

## 5. Design

Details: [`ARCHITECTURE.md`](docs/ARCHITECTURE.md). Implementation status is given per paragraph.

**Canonical actions (implemented).** Every tool has a strict schema: opaque resource identifiers with a fixed pattern, amounts as decimal strings with exactly two fraction digits and no leading zeros, recipients by contact identifier, free text in NFC without control or invisible characters. The request parser rejects duplicate keys, floats, `NaN` and non-UTF-8 input. Nothing is repaired: `./doc_1`, `"100.0"` and decomposed Unicode are refused. The action hash is the SHA-256 of the canonical JSON encoding of the tool, the resource and the validated arguments. The canonical form depends on the Unicode version, so it is pinned to Python 3.12.

**Policy (implemented).** A YAML file read once at start-up. Its SHA-256 is the policy hash. Reversibility tiers (R0 read, R1 reversible, R2 irreversible) are fixed in code; a policy file that states a different tier for a tool fails to load, as does one with an unknown field, a duplicate key or a default other than deny.

**Action-bound approvals (planned, M2).** An approval record stores the action hash, resource version, policy hash, canonicalization version, provenance version, a 128-bit nonce and an expiry. A change in any bound value invalidates it.

**Signed decisions (planned, M2).** The approver signs, with Ed25519, a domain-separation prefix followed by the canonical JSON of the full decision payload. The Gateway looks the key up in its registry, never in the payload, and rejects a decision in which any field differs from the stored record.

**Execution and idempotency (planned, M2).** Execution resends the arguments. In one `BEGIN IMMEDIATE` SQLite transaction the Gateway rechecks every binding, reserves the budgets, consumes the approval, creates an execution identifier and writes the audit events. It then calls the Tools service with that identifier as idempotency key and the resource version as precondition. The Tools service checks its own token, key and precondition; it does not trust the Gateway for them. A timeout leaves the action in an unknown state that is reconciled against the Tools service before any budget is released.

**Budgets (planned, M2).** Cumulative caps per account, shared by all agents, and per agent, checked and reserved inside the execution transaction.

**Provenance (planned, M1–M2).** Every read is proxied. The Tools service labels each resource internal or external. A session that has seen an external source is tainted; the approval request shows taint status and the observed sources, and the policy can escalate or deny for tainted sessions.

**Audit (planned, M1).** An append-only table with a hash chain, written in the same transaction as the security state transition it records. Verification detects a modified entry. Bypass measurement does not rest on this log alone: the Tools execution table is cross-checked against the Gateway's records.

## 6. Evaluation protocol

Full version: [`EVALUATION_PLAN.md`](docs/EVALUATION_PLAN.md). Success criteria are fixed there, before any run.

| Layer | What | Adversary | Uses an LLM |
|---|---|---|---|
| L1 Conformance | pytest cases per threat, with fault injection | ADV2, ADV3 at API level | no |
| L2 Scripted attacker | A program inside the agent container attempting bypasses | ADV3 | no |
| L3 Agent benchmark | One agent on a legitimate and an adversarial task suite, with and without the Gateway | ADV1, ADV2 | yes |

L2 is the main evidence for the guarantees, because it does not depend on whether a model happens to attempt an attack.

Two outcomes are kept apart. A **policy bypass** is an execution that did not satisfy every Gateway check; it is a failure of the Gateway and is detected by cross-checking the Tools execution table against the Gateway's records. A **residual harmful execution** is a forbidden action that was executed, possibly after a valid approval; it measures the decision rule, not the Gateway.

Approvers are simulated: `AP-rubber` approves everything, `AP-provenance` rejects irreversible requests from tainted sessions, `AP-oracle` approves only what the task's ground truth requires. No result describes human behaviour.

Metrics: policy bypass rate, residual harmful execution rate, legitimate task success, false denial rate, approval requests per legitimate task, escalation rate, inaction rate, bypass success per category, and decision latency. Outcomes are read from the final state of the Tools service, never from the agent's text.

## 7. Results

No experiment has been run. Every cell is TBD.

**L1 and L2**

| Layer | Cases / attempts | Passed / blocked |
|---|---|---|
| L1 conformance (full table) | TBD | TBD |
| L2 scripted attacker, per category | TBD | TBD |

**L3**

| Condition | Policy bypass rate | Residual harmful execution rate (suite B) | Legitimate task success (suite A) | Approvals per legitimate task |
|---|---|---|---|---|
| Unprotected | n/a | TBD | TBD | n/a |
| Protected, `AP-rubber` | TBD | TBD | TBD | TBD |
| Protected, `AP-provenance` | TBD | TBD | TBD | TBD |
| Protected, `AP-oracle` | TBD | TBD | TBD | TBD |

Gateway overhead (p50 / p95 decision latency): TBD.

## 8. Tested bypasses

Tests so far exercise input handling only, at unit level. "Partial" means the building block is tested but the end-to-end property is not.

| Threat | Test | Result |
|---|---|---|
| T9 Unknown tool, alias, case variant | `tests/test_schemas.py::test_unknown_alias_and_variant_tool_names_rejected`, `tests/test_policy.py::test_tier_of_unknown_tool_raises` | Rejected (unit) |
| T10 Malformed or ambiguous arguments | `tests/test_canon.py` (duplicate keys, floats, `NaN`, encodings, non-NFC, invisible characters), `tests/test_schemas.py` (identifiers, amounts, unknown fields, coercion) | Rejected (unit) |
| T4 Arguments changed after approval | `tests/test_canon.py::test_action_hash_changes_with_any_component` | Partial: the hash changes; recheck at execution is M2 |
| T12 Forged provenance | `tests/test_schemas.py::test_agent_supplied_control_fields_rejected` | Partial: claims in arguments are rejected; Gateway-derived provenance is M1 |
| T17 Policy changed after approval | `tests/test_policy.py::test_any_byte_change_changes_the_policy_hash` | Partial: the hash changes; invalidation is M2 |
| T1–T3, T5–T8, T11, T13–T16, T18–T20 | — | Not yet tested |

## 9. Reproducibility

Requirements: [`uv`](https://docs.astral.sh/uv/) and Python 3.12. The canonical form is defined against Unicode 15.0, which Python 3.12 ships; the canonicalization module refuses to load on another version.

Available now:

```sh
uv sync          # install pinned dependencies from uv.lock
make lint        # ruff check and format check
make test        # L1 unit tests
```

Planned, not yet available: `make up`, `make attack` (L2), `make smoke` (L3 on three tasks) and `make eval` (L1 + L2 + L3, writing `results/` and a run manifest with the git commit, policy hash, canonicalization version, model digest and seeds).

## 10. Related work

**Indirect prompt injection.** Greshake et al. introduced the attack class [1]; AgentDojo provides tasks and security test cases to measure attacks and defenses on tool-calling agents [2]. Ullr's suite B is far smaller and is not a substitute for it.

**System-level defenses.** CaMeL places a protective layer around the model, separates control flow from data flow so that untrusted data cannot change the program's flow, and uses capabilities to enforce policies on tool calls [3]. Ullr makes a different trade-off. It assumes a stronger adversary, a fully controlled agent runtime, and therefore relies on nothing computed inside the agent. The price is precision: Ullr tracks provenance per session, which is coarser than CaMeL's data-flow tracking and over-taints.

**Enforced confirmation.** GateArena [5] is the closest work we know of. A confirmation exchange issues a one-time warrant bound to the approved action and its exact parameter values, and the execution handler admits an irreversible call only when a matching, unspent warrant is present. It compares, on paired tasks, no control, a confirmation instruction given in the prompt, and the enforced gate, and it judges harm against the user's ground-truth intent. Its question is what enforcement adds over instruction when an agent deviates from what the user meant.

Ullr uses the same core mechanism and does not claim it as new. It differs in its assumptions and in what surrounds the mechanism:

- The agent runtime is treated as compromised (ADV3). The decision is therefore signed with a key the agent never holds, and the Gateway and the Tools service are isolated from the agent.
- An approval is also bound to the resource version, the policy hash and the provenance version, and expires.
- Failure semantics are specified: idempotency keys enforced by the Tools service, an `UNKNOWN` state reconciled before any budget release, and cumulative budgets across agents.

Ullr's evaluation is prototype-scale and its implementation is incomplete (see [Status](#status)); it reports no result yet that could be compared with GateArena's.

**Abstention.** AgentAbstain measures whether agents know when not to act [4]. It motivates the confused-agent adversary (ADV2) and the ambiguous tasks of suite B.

## 11. Limitations and threats to validity

- The implementation is incomplete; see [Status](#status). No end-to-end claim is supported yet.
- The benchmark is planned at about 30 tasks with 3 repetitions. That is a prototype-scale study and supports no claim of generalization.
- The scenarios and the Gateway have the same author. Task suites are fixed before the policy is tuned, and later changes are logged.
- Tools and approvers are simulated. The effect of showing provenance to a person is not measured.
- One model, possibly two; model nondeterminism is only partly controlled.
- Session-level provenance over-approximates. Its cost shows up as lower task success and more escalations.
- Strict text rules reject some legitimate input: tabs, emoji sequences joined by zero-width characters, and scripts that use the zero-width non-joiner.
- The guarantees rest on container isolation and on the Tools service enforcing idempotency and preconditions. A real deployment would have to establish both for its own backends.

## References

1. K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, M. Fritz. *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* 2023. <https://arxiv.org/abs/2302.12173>
2. E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, F. Tramèr. *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.* 2024. <https://arxiv.org/abs/2406.13352>
3. E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern, C. Shi, A. Terzis, F. Tramèr. *Defeating Prompt Injections by Design.* 2025. <https://arxiv.org/abs/2503.18813>
4. X. Liu, Y. E. Zhang, V. Kasprova, P. Rabbani, P. S. Zahraei, T. Zhang, A. Ebrahimpour-Boroojeny, V. Chandrasekaran. *AgentAbstain: Do LLM Agents Know When Not to Act?* 2026. <https://arxiv.org/abs/2607.10059>
5. Jiang, Quinzan, Bhatt. *GateArena.* NeurIPS 2026. <https://openreview.net/forum?id=2fckzsPCbK>. Code: <https://github.com/Lannie520/GateArena>

## License

Copyright 2026 Abdelatif Touati. Licensed under the Apache License, Version 2.0; see [`LICENSE`](LICENSE).
