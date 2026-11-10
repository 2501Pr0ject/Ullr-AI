# Evidence

What is tested, at which level, for each security goal (G1–G7) and each threat (T1–T20) of [`THREAT_MODEL.md`](THREAT_MODEL.md). Updated at every milestone. Current state: end of M1.

## Evidence levels

| Level | Meaning |
|---|---|
| **Unit** | A function or module tested in isolation. |
| **Integration** | The Gateway and the Tools service exercised through their HTTP interfaces, in one process. No network, no container, no separate credentials store. |
| **End-to-end** | A test that crosses the actual container and network isolation boundary: the scripted attacker (L2) or the agent benchmark (L3). |

**No end-to-end evidence exists yet.** The Docker stack and the scripted attacker are M3. Until L2 has run, this project does not demonstrate that a compromised agent runtime cannot bypass the Gateway. Unit and integration evidence shows that the components refuse what they should refuse when reached through their interfaces; it says nothing about whether those interfaces are the only way in.

**No irreversible action can be executed yet.** Signed approvals are M2. Every R2 proposal stops at `PENDING_APPROVAL`, so the evidence below for approval-related goals covers refusal only, never a correct approved execution.

Test paths are relative to `tests/`. Reproduce with `make test`.

## G1 — No R2 action without a valid, signed, matching approval

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T2 R2 without approval | Each R2 tool is decided `REQUIRE_APPROVAL`; the execute call refuses; the Tools execution table stays empty. A decision is never `ALLOW` for an R2 tool. | `test_gateway_api.py::test_irreversible_action_is_never_executed_without_approval`, `test_policy_decide.py::test_an_irreversible_action_is_never_allowed` | Integration | Approved path (M2); L2, L3 |
| T9 Unknown tool, alias, case variant | Exact allow-list at schema, Gateway and Tools level. | `test_schemas.py::test_unknown_alias_and_variant_tool_names_rejected`, `test_gateway_api.py::test_unknown_alias_and_case_variant_tools_are_denied`, `test_tools_executor.py::test_invalid_requests_are_rejected_with_the_gateway_schemas` | Unit, integration | L2 |
| T10 Malformed or ambiguous arguments | Duplicate keys, floats, `NaN`, encodings, non-NFC and invisible characters, identifier and amount formats, unknown fields, no coercion, request size limit before parsing. | `test_canon.py`, `test_schemas.py`, `test_asgi.py`, `test_gateway_api.py::test_malformed_proposals_are_denied`, `::test_body_above_the_limit_is_rejected_before_parsing` | Unit, integration | L2 fuzzing |
| T1 Direct call to the Tools service | The executor API refuses requests without the executor token. | `test_tools_executor.py::test_execute_requires_the_executor_token` | Integration | Network isolation and credential search (M3, L2). This is the core claim and it is untested. |
| T6 Forged or self-issued approval | — | — | None | Signed decisions (M2); L2 |
| T7 Expired approval | — | — | None | M2 |

## G2 — One approval, one execution, one exact action, one resource version, one policy, one provenance state

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T3 Approval replayed | Tools side only: a repeated idempotency key returns the stored result; a key reused for another request is refused. | `test_tools_executor.py::test_same_key_twice_executes_once_and_replays_the_result`, `::test_same_key_with_a_different_request_is_rejected` | Integration | Single-use approval consumption (M2); L2 |
| T4 Arguments changed after approval | The action hash changes with any component; resent arguments that do not match the recorded hash are refused. | `test_canon.py::test_action_hash_changes_with_any_component`, `test_gateway_api.py::test_changed_arguments_at_execution_are_refused` | Unit, integration | Recheck inside the execute transaction (M2); L2 |
| T5 Resource modified before execution | The Tools service refuses a stale version; a resource changed between observation and execution is not modified (R1). | `test_tools_executor.py::test_stale_precondition_is_not_executed`, `test_gateway_api.py::test_resource_changed_between_observation_and_execution` | Integration | Version bound to an approval (M2) |
| T14 Concurrent executions | Tools side only: 20 concurrent calls with one key execute once. | `test_tools_executor.py::test_concurrent_calls_with_one_key_execute_once` | Integration | Serialized approval consumption (M2); 50-way race (L2) |
| T17 Policy changed after approval | The policy hash changes with any byte of the file and is stored on every action and audit event. | `test_policy.py::test_any_byte_change_changes_the_policy_hash`, `test_gateway_api.py::test_every_state_transition_has_its_audit_event` | Unit, integration | Invalidation of approvals (M2) |
| T18 Session tainted after approval | The provenance version is stored with each proposal. | `test_gateway_sessions.py::test_tainted_session_cannot_be_swapped_for_a_clean_one` | Integration | Invalidation of approvals (M2) |

## G3 — Cumulative limits under concurrency and across agents

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T8 Split transactions | Per-action limit only: a refund above `max_amount` is denied. | `test_policy_decide.py::test_refund_amount_limit`, `test_gateway_api.py::test_refund_outside_the_policy_is_denied` | Unit, integration | Budget ledger (M2); concurrent refunds (L2). The goal itself is untested. |

## G4 — Failures do not execute; ambiguous outcomes stay reserved

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T13 Error or timeout leads to execution | Tools unreachable, unexpected or unlabeled replies: no content returned, nothing assumed executed. A `DENY` makes no call to the Tools service. Audit failure before execution: no call, state rolled back. | `test_gateway_api.py::test_tools_service_unreachable`, `::test_unexpected_tools_reply_to_a_read_returns_no_content`, `::test_deny_makes_no_call_of_any_kind_to_the_tools_service`, `::test_audit_failure_means_nothing_is_executed` | Integration | Approval timeout (M2) |
| T19 Crash or timeout after consumption | A timeout before or after the Tools service acted is recorded as `UNKNOWN`, with the idempotency key that reconciliation will query. | `test_gateway_api.py::test_timeout_before_the_tools_service_acts_is_unknown`, `::test_timeout_after_the_tools_service_executed_is_unknown` | Integration | Reconciliation, budget hold, crash and restart (M2) |

## G5 — No security state transition without its audit event

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T15 Execution without audit, audit tampering | `UPDATE`, `DELETE` and `INSERT OR REPLACE` on `audit_events` are rejected by triggers. The chain verification detects a modified, re-hashed, removed or reordered entry. Every action's last audit event equals its state. An audit insert failure rolls the state change back. | `test_audit.py`, `test_gateway_api.py::test_every_state_transition_has_its_audit_event`, `::test_audit_failure_means_nothing_is_executed`, `::test_audit_failure_while_recording_a_read_returns_no_content` | Unit, integration | Truncation of the tail is not detected, by design (`test_audit.py::test_tail_truncation_is_not_detected`); external anchoring is deferred |

## G6 — Provenance comes from what the Gateway observed

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T12 Forged or laundered provenance | Taint derives only from Tools-assigned labels and is permanent. Claims in the body, the arguments or the reason are rejected or ignored. The agent API has two routes and none creates, switches or resets a session; identity comes from the token. The laundering scenario (tainted session A, clean session B) fails. Session and provenance rows cannot be rewritten in the database. | `test_gateway_sessions.py`, `test_provenance.py`, `test_audit.py::test_session_and_provenance_history_cannot_be_rewritten`, `test_tools_executor.py::test_an_update_cannot_change_the_trust_label` | Unit, integration | Session-creation credential unreachable from the agent container (M3, L2). Cross-session agent memory is out of scope (H7). |
| T11 Plausible injected request accepted by the approver | — | — | None | Approval request display (M2); approver profiles (L3) |

## G7 — At most one effective execution per approval, given H6

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T3, T14, T19 (Tools side) | Idempotency keys and preconditions are enforced by the Tools service itself, in one transaction with the effect; a failed attempt burns its key; every Tools execution is backed by a Gateway action with the same key. | `test_tools_executor.py` (idempotency and precondition sections), `test_gateway_api.py::test_every_tools_execution_is_backed_by_a_gateway_action` | Integration | Approved executions (M2); L2 race |

## Threats not tied to a single goal

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T16 Approval flooding | — | — | None | Pending-approval limit (M2); burden metric (L3) |
| T20 Agent reaches evaluation endpoints | The admin API is a separate application with its own token; its routes do not exist on the executor application. | `test_tools_admin.py` | Integration | Network separation (M3, L2) |

## End-to-end evidence

None. To be filled from the L2 report (`make attack`) and the L3 runs (`make eval`).

| Layer | Status |
|---|---|
| L2 scripted attacker, per category | Not run |
| L3 agent benchmark, policy bypass rate | Not run |
