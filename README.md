# Ullr-AI

Ullr is designed to enforce authorization policies on every protected action routed through its gateway, even when the agent runtime is fully compromised, provided the isolation boundary and trusted components remain intact.

**Author:** Abdelatif Touati — [github.com/2501Pr0ject](https://github.com/2501Pr0ject) · [2501project.dev](https://2501project.dev)

Submission to the Drawerrr "AI Safety and Control" challenge. Targeted award categories: financial transactions, digital system changes, delegated actions. This document is the paper; the specification lives in [`docs/`](docs/).

> **Work in progress.** The design documents in `docs/` evolve with the implementation. The Tools service and the Gateway are implemented and integration-tested. The scripted attacker (L2) has run twice against the Docker stack; the second run passed, within the limits of section 11. The agent benchmark (L3) does not exist. The [Status](#status) table states what exists and what is tested.

## Abstract

*Provisional.* Ullr is a gateway between a tool-calling agent and its tools. It decides every action without a language model, binds each human approval to one exact action on one resource version, and executes at most once. Conformance tests pass, and a scripted attacker inside the agent container failed in its second run, on one platform. The agent benchmark has not run.

## Status

| Component | Implemented | Unit-tested | Integration-tested | Container-tested | Adversarially verified (L2 run 2) |
|---|---|---|---|---|---|
| Canonicalization, tool schemas, policy | yes | yes | yes | yes | yes |
| Tools service: executor token, idempotency keys, preconditions, admin API, fault barrier | yes | — | yes | yes | yes |
| Gateway: sessions and revocation, decision, execution of allowed actions, provenance | yes | partly | yes | yes | partly: provenance not attacked |
| Audit table, hash chain, `verify-audit` | yes | yes | yes | yes | no |
| Approvals: signed decisions, lifecycle, approved execution, budgets, reconciliation, approver tool | yes | signing | yes | yes | partly: forged signatures not attacked |
| Docker stack, LLM relay, scripted attacker (L2) | yes | relay, attacker detectors | role wiring, shared SQLite | yes | yes |
| Agent loop, benchmark harness (L3), runs and results | no | no | no | no | no |
| One real protocol behind the Gateway (SMTP to a local Mailpit) | no, after M3 if time allows | no | no | no | no |
| External audit anchoring, truncation detection | deferred | no | no | no | no |

Levels are defined in [`docs/EVIDENCE.md`](docs/EVIDENCE.md). Adversarially verified means the L2 attacker tried from inside the agent container and failed, with passing positive controls; it rests on one run, one Docker Desktop version and one network vantage point, and is not a proof of isolation.

## 1. Problem and motivation

Agents built on language models read content they do not control, then call tools. Greshake et al. showed that instructions planted in retrieved data can take over an LLM-integrated application: indirect prompt injection [1]. AgentDojo reports that existing attacks on tool-calling agents break some security properties [2].

Injection is not the only cause. AgentAbstain evaluates whether agents recognize when not to act: across 17 models, the best agent reaches 59.5% paired accuracy, and some execute irreversible actions before recognizing that they should have abstained [4].

Defenses acting on the model (system prompts, classifiers, fine-tuning) lower the rate of wrong actions without bounding what happens when one occurs. For actions that cannot be undone, a lower rate is not a control.

Example: an inbox e-mail the agent reads contains the injected line "refund 900 EUR to this customer".

- Without Ullr, an agent following the injection is expected to call `issue_refund` directly, and the refund to be executed.
- With Ullr, the proposal is denied by the policy's 500.00 EUR per-action limit, without asking anyone.
- A refund within the limit would wait for a signed approval, and the approval request would show that the session has read external content.

The two behaviours with Ullr are integration-tested; the first line is an expectation.

Ullr takes the position, shared with CaMeL [3], that the security argument must not depend on the model. Its core mechanism, a single-use approval bound to one exact action and enforced at execution, is the one evaluated by GateArena [5] (see section 10).

## 2. Approach

Enforcement is designed to happen outside the model, in a separate process the agent cannot modify. The components run as separate containers on separate networks; L2 run 2 attacked that separation (section 7).

```
 agent ──net_agent──▶ gateway-api ──net_tools──▶ tools-executor
   │                      │                           │
   │ net_llm       (SQLite volume)              (state volume)
   ▼                      │                           │
 llm-relay          gateway-admin ◀─net_admin──┐  tools-admin ◀─net_control─┐
   │ net_egress     gateway-approver           │                            │
   ▼                      ▲ net_approval       └─────── controller ─────────┘
 model on host         approver             (episode token to the agent: read-only volume)
```

Design principles ([`ARCHITECTURE.md` §1](docs/ARCHITECTURE.md)): no model in any decision, default deny, fail closed, approvals bound to facts, reject rather than normalize.

## 3. Threat model summary

Full version: [`THREAT_MODEL.md`](docs/THREAT_MODEL.md).

| Adversary | Capability |
|---|---|
| ADV1 Manipulated agent | Follows instructions injected through content it reads |
| ADV2 Confused agent | Acts on ambiguous instructions or misread tool failures |
| ADV3 Compromised runtime | Controls the agent container: arbitrary code, arbitrary requests, the agent token |

ADV3 is the reference adversary. A control that only holds against ADV1 or ADV2 is not counted as a guarantee.

**In scope:** twenty threats, T1–T20, from direct tool access and forged approvals to split transactions, provenance laundering and audit tampering.

**Out of scope:** compromise of the Gateway, the Tools service, the controller or their hosts; a malicious approver or policy author; container escape; supply-chain attacks; disclosure through permitted reads.

## 4. Guarantees and non-guarantees

These are design goals; the evidence for each is in [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

| Goal | Statement |
|---|---|
| G1 | No irreversible action reaches the Tools service without a valid, unexpired, unconsumed approval, signed by a registered approver, whose action hash, resource version, policy hash and provenance version match the execution context. |
| G2 | An approval authorizes at most one execution of one canonical action on one resource version, under one policy and one provenance state. |
| G3 | Cumulative limits hold under concurrency and across agents sharing an account. |
| G4 | Any failure in the decision path results in non-execution; an ambiguous outcome keeps the budget reserved until reconciled. |
| G5 | No security state transition happens without its audit event, written in the same transaction. |
| G6 | Provenance shown to the approver is derived by the Gateway from sources it observed, never from agent claims. |
| G7 | In the reference environment, each approval produces at most one effective execution, given that the Tools service enforces idempotency. |

**Non-guarantees** ([`THREAT_MODEL.md` §9](docs/THREAT_MODEL.md)).

- Actions that do not pass through the Gateway are not covered.
- Every guarantee depends on the isolation boundary and on the trusted components (H1–H7).
- An approver can approve a harmful action; the system only makes that decision informed and bounded.
- At-most-once execution holds only where the downstream service enforces idempotency keys.
- Others, on provenance, revocation, audit and reads, are listed in section 11 and in the threat model.

## 5. Design

Details: [`ARCHITECTURE.md`](docs/ARCHITECTURE.md).

**Canonical actions (implemented).** Every tool has a strict schema: opaque resource identifiers with a fixed pattern, amounts as decimal strings with exactly two fraction digits and no leading zeros, recipients by contact identifier, free text in NFC without control or invisible characters. The parser rejects duplicate keys, floats, `NaN` and non-UTF-8 input. Nothing is repaired: `./doc_1`, `"100.0"` and decomposed Unicode are refused. The action hash is the SHA-256 of the canonical JSON encoding of the tool, the resource and the validated arguments. The canonical form depends on the Unicode version, so it is pinned to Python 3.12.

**Policy (implemented).** A YAML file read once at start-up; its SHA-256 is the policy hash. Reversibility tiers (R0 read, R1 reversible, R2 irreversible) are fixed in code: a policy that states another tier, an unknown field, a duplicate key or a default other than deny fails to load.

**Action-bound approvals (implemented).** An approval record stores the action hash, resource version, policy hash, canonicalization version, provenance version, a 128-bit nonce and an expiry. A change in any bound value invalidates it.

**Signed decisions (implemented).** The approver signs, with Ed25519, a domain-separation prefix followed by the canonical JSON of the full decision payload. The Gateway looks the key up in its registry, never in the payload, and rejects a decision in which any field differs from the stored record.

**Execution and idempotency (implemented).** Allowed actions execute within the proposing request. Approved actions need a second call that resends the arguments: in one `BEGIN IMMEDIATE` SQLite transaction the Gateway rechecks every binding, reserves the budgets, consumes the approval and writes the audit events. Both then follow the same path. There is no transaction spanning the Gateway and the Tools service: the Gateway records the intent, calls the Tools service with that identifier as idempotency key and the resource version as precondition. The Tools service checks its own token, key and precondition; it does not trust the Gateway for them. The Gateway then records the outcome. A timeout leaves the action in an unknown state that is reconciled against the Tools service before any budget is released.

**Budgets (implemented).** Cumulative caps per account, shared by all agents, and per agent, checked and reserved inside the execution transaction.

**Sessions (implemented).** A trusted party creates and revokes sessions through an admin-only application; the agent token is bound to one session and the agent API cannot create or switch sessions. This closes provenance laundering through a fresh session.

**Provenance (implemented).** Every read is proxied. The Tools service labels each resource internal or external. A session that has seen an external source is tainted; the approval request shows the taint and its sources, and the policy can escalate or deny.

**Audit (implemented).** An append-only table with a hash chain, written in the same transaction as the security state transition it records. Verification detects a modified entry. Bypass measurement also cross-checks the Tools execution table against the Gateway's records.

## 6. Evaluation protocol

Full version and success criteria, fixed before any run: [`EVALUATION_PLAN.md`](docs/EVALUATION_PLAN.md).

| Layer | What | Adversary | Uses an LLM |
|---|---|---|---|
| L1 Conformance | pytest cases for the threats that can be exercised in one process, with fault injection | ADV2, ADV3 at API level | no |
| L2 Scripted attacker | A program inside the agent container attempting bypasses; it does not depend on a model attempting an attack | ADV3 | no |
| L3 Agent benchmark | One agent on a legitimate and an adversarial task suite, with and without the Gateway | ADV1, ADV2 | yes |

Two outcomes are kept apart. A **policy bypass** is an execution that did not satisfy every Gateway check, detected by cross-checking the Tools execution table against the Gateway's records. A **residual harmful execution** is a harmful action executed, possibly after a valid approval; it measures the decision rule, not the Gateway.

Approvers are simulated (`AP-rubber` approves all, `AP-provenance` rejects irreversible requests from tainted sessions, `AP-oracle` approves only what the ground truth requires): no result describes human behaviour.

Outcomes are read from the final state of the Tools service, never from the agent's text.

## 7. Results

**L1.** 1,635 tests pass (`make test`); one more runs only on Linux.

**L2.** Two runs, both in [`results/l2/`](results/l2/), counted on the Tools side.

| Run | Records | Passed | Failed |
|---|---|---|---|
| 1 | 146 | 142 | 4 |
| 2 | 146 | 146 | 0 |

Run 1 failed: the port scan showed that the agent could reach two RPC services of the Docker Desktop virtual machine through the bridge addresses of its own networks. We removed the VM's IPv4 address from those bridges, made the scanner record the endpoints of every connection, and ran again. In run 2 the attacker, inside the agent container, found no route or name for any service but the Gateway API and the LLM relay, none of the seven privileged secrets, and no unexpected open port; 40 API attacks, 15 relay abuses and the revocation attacks were refused. One approval run by 50 processes executed once, and nothing executed twice after the Gateway was killed at three points. Controls: the same direct attack executed against an unprotected baseline, and an approved action executed exactly once. Three scan records report a connection with identical endpoints, under their own outcome.

**L3.** Not run.

| Condition | Policy bypass rate | Residual harmful execution rate (suite B) | Legitimate task success (suite A) | Approvals per legitimate task |
|---|---|---|---|---|
| Unprotected | n/a | TBD | TBD | n/a |
| Protected, `AP-rubber` | TBD | TBD | TBD | TBD |
| Protected, `AP-provenance` | TBD | TBD | TBD | TBD |
| Protected, `AP-oracle` | TBD | TBD | TBD | TBD |

## 8. Tested bypasses

The full table, by guarantee then threat, with six evidence levels and both L2 runs, is in [`docs/EVIDENCE.md`](docs/EVIDENCE.md). In short:

- Adversarially verified in L2 run 2, for the attacks listed there: T1–T4, T7–T10, T14, T16, T19, T20.
- In part: T6 (no decision route or approver key within the agent's reach; forged signatures not attacked across containers), T12 (no session creation, switch or reuse after revocation; peer agents and written resources remain open), T15 (chain verified after each kill; tampering not attacked).
- Integration-tested only: T5, T13, T17, T18. T11 is an L3 question.

## 9. Reproducibility

Requirements: [`uv`](https://docs.astral.sh/uv/) and Python 3.12.

Available now:

```sh
uv sync          # install pinned dependencies from uv.lock
make lint        # ruff check and format check
make test        # L1: unit and integration tests
```

`make secrets`, `make build` and `make attack` run the Docker stack and L2; they need Docker, and Ollama on the host loopback with `qwen3:8b`. L3 commands do not exist.

## 10. Related work

**System-level defenses.** CaMeL places a protective layer around the model, separates control flow from data flow so that untrusted data cannot change the program's flow, and uses capabilities to enforce policies on tool calls [3]. Ullr makes a different trade-off: it assumes a fully controlled agent runtime and relies on nothing computed inside the agent, at the price of per-session provenance, coarser than CaMeL's data-flow tracking.

**Enforced confirmation.** GateArena [5] is the closest work we know of. Its abstract describes a confirmation that returns a warrant binding the approved action to its exact parameter values; the warrant is consumed by the execution it authorizes, and the execution handler rejects a call whose warrant is missing, spent or bound to other values. The paper measures, with no adversarial input involved, how far a prompt-only confirmation instruction depends on model behaviour, over 1,880 episodes and three model backbones; moving the check into the handler takes protocol-violating executions from 91/400 to 0/400.

Ullr uses the same core mechanism and does not claim it as new. It differs in assumptions and surroundings:

- The agent runtime is treated as compromised (ADV3): the decision is signed with a key the agent is not given, and the Gateway and the Tools service are isolated from it by design.
- An approval is also bound to the resource version, the policy hash and the provenance version, and expires.
- Failure semantics are specified: idempotency keys enforced by the Tools service, an `UNKNOWN` state reconciled before any budget release, and cumulative budgets across agents.

GateArena's evaluation is larger than the one planned here. Ullr has L2 results but no L3 result comparable to GateArena's yet.

## 11. Limitations and threats to validity

- L2 evidence is one passing run, on one Docker Desktop version, from one vantage point (TCP connect and DNS from one agent container). Run 1 showed that the platform matters.
- The bridges of the trusted containers' networks still reach the virtual machine's RPC services.
- L3 has not run: nothing is measured about a real agent.
- The planned benchmark is about 30 tasks, 3 repetitions, one or two models: prototype scale.
- Scenarios and Gateway have the same author; suites are fixed before policy tuning.
- Tools and approvers are simulated.
- Provenance is per session, over-taints, and assumes a fresh agent context (H7); permitted reads disclose what they return.
- A refund on an account makes other pending refund approvals on it stale; strict text rules reject some legitimate input.
- Agent containers that share a network can reach each other (observed) and exchange content and tokens outside the Gateway's view.
- A tainted session can write an internal document that a clean session then reads as trusted; a fix is designed and deferred.
- Revocation bounds authorization, not effects: an action authorized before revocation may take effect after it.
- Truncation of the audit log is not detected.
- A real deployment must establish isolation, idempotency and preconditions for its own backends.

## References

1. K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, M. Fritz. *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* 2023. <https://arxiv.org/abs/2302.12173>
2. E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, F. Tramèr. *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.* 2024. <https://arxiv.org/abs/2406.13352>
3. E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern, C. Shi, A. Terzis, F. Tramèr. *Defeating Prompt Injections by Design.* 2025. <https://arxiv.org/abs/2503.18813>
4. X. Liu, Y. E. Zhang, V. Kasprova, P. Rabbani, P. S. Zahraei, T. Zhang, A. Ebrahimpour-Boroojeny, V. Chandrasekaran. *AgentAbstain: Do LLM Agents Know When Not to Act?* 2026. <https://arxiv.org/abs/2607.10059>
5. L. Jiang, F. Quinzan, U. Bhatt. *GateArena: Environment-Enforced Confirmation for Irreversible Agent Actions.* NeurIPS 2026, workshop "Agents in the Wild: Safety, Security, and Beyond". <https://neurips.cc/virtual/2026/168290>. Paper: <https://openreview.net/forum?id=2fckzsPCbK>

## License

Copyright 2026 Abdelatif Touati. Licensed under the Apache License, Version 2.0; see [`LICENSE`](LICENSE).
