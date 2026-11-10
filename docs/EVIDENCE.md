# Evidence

What is tested, at which level, for each security goal (G1–G7) and each threat (T1–T20) of [`THREAT_MODEL.md`](THREAT_MODEL.md). Updated at every milestone. Current state: M3 in progress. The stack and the scripted attacker are implemented; the first L2 run has not completed.

## Evidence levels

| Level | Meaning |
|---|---|
| **Unit** | A function or module tested in isolation. |
| **Integration** | The Gateway and the Tools service exercised through their HTTP interfaces, in one process. No network, no container, no separate credential store. Faults (timeouts, crashes, audit failures) are injected through the test transport or the database. |
| **End-to-end** | A test that crosses the actual container and network isolation boundary: the scripted attacker (L2) or the agent benchmark (L3). |

**No end-to-end evidence exists yet**, apart from the start-up check of the LLM relay described at the end. Until L2 has run, this project does not demonstrate that a compromised agent runtime cannot bypass the Gateway. Integration evidence shows that the components refuse what they should refuse when reached through their interfaces; it says nothing about whether those interfaces are the only way in, nor about whether the credentials are out of the agent's reach.

Test paths are relative to `tests/`. Reproduce with `make test`.

## G1 — No R2 action without a valid, signed, matching approval

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T2 R2 without approval | Each R2 tool is decided `REQUIRE_APPROVAL`, never `ALLOW`; the execute call refuses while pending; with a valid approval each R2 tool executes exactly once; every Tools execution of an R2 tool is backed by a stored decision whose signature verifies. | `test_gateway_api.py::test_irreversible_action_is_never_executed_without_approval`, `test_policy_decide.py::test_an_irreversible_action_is_never_allowed`, `test_execute.py::test_approved_irreversible_action_is_executed_once`, `::test_tools_executions_are_backed_by_signed_approvals` | Integration | L2, L3 |
| T6 Forged or self-issued approval | Unsigned, malformed, wrong-key, unregistered-approver, agent-as-approver, wrong-domain and mismatched-payload decisions are refused and change nothing. A correctly signed payload with any one bound field altered is refused. A decision cannot be replayed on another action, even an identical one. The registry refuses an agent identifier. | `test_signing.py`, `test_approvals.py::test_forged_decision_is_refused_and_changes_nothing`, `::test_correctly_signed_payload_with_one_field_altered_is_refused`, `::test_decision_replayed_on_another_action_is_refused`, `::test_decision_for_an_identical_later_action_is_not_reusable`, `::test_gateway_refuses_to_start_with_an_agent_as_approver` | Unit, integration | Approver key and channel token out of the agent's reach (M3, L2) |
| T7 Expired approval | Expiry is checked on the Gateway clock at decision and at execution; a decision cannot extend it and may shorten it. | `test_approvals.py::test_expired_request_cannot_be_approved`, `::test_expired_approval_is_not_executed`, `::test_decision_cannot_extend_the_expiry`, `::test_approver_can_shorten_the_validity` | Integration | — |
| T9 Unknown tool, alias, case variant | Exact allow-list at schema, Gateway and Tools level. | `test_schemas.py::test_unknown_alias_and_variant_tool_names_rejected`, `test_gateway_api.py::test_unknown_alias_and_case_variant_tools_are_denied`, `test_tools_executor.py::test_invalid_requests_are_rejected_with_the_gateway_schemas` | Unit, integration | L2 |
| T10 Malformed or ambiguous arguments | Duplicate keys, floats, `NaN`, encodings, non-NFC and invisible characters, identifier and amount formats, unknown fields, no coercion, request size limit before parsing. | `test_canon.py`, `test_schemas.py`, `test_asgi.py`, `test_gateway_api.py::test_malformed_proposals_are_denied`, `::test_body_above_the_limit_is_rejected_before_parsing` | Unit, integration | L2 fuzzing |
| T1 Direct call to the Tools service | The executor API refuses requests without the executor token. | `test_tools_executor.py::test_execute_requires_the_executor_token` | Integration | Network isolation and credential search (M3, L2). This is the core claim and it is untested. |

## G2 — One approval, one execution, one exact action, one resource version, one policy, one provenance state

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T3 Approval replayed | An approval is consumed by its execution; further execute calls are refused; a failed or unknown execution does not restore it. Tools side: a repeated idempotency key returns the stored result. | `test_execute.py::test_approval_is_single_use`, `::test_failed_execution_does_not_restore_the_approval`, `test_tools_executor.py::test_same_key_twice_executes_once_and_replays_the_result` | Integration | L2 |
| T4 Arguments changed after approval | Resent arguments that do not hash to the approved action are refused without consuming the approval; approving one document does not cover another. | `test_execute.py::test_other_action_cannot_ride_on_an_approval`, `::test_changed_refund_arguments_are_refused`, `::test_changed_email_body_is_refused`, `test_canon.py::test_action_hash_changes_with_any_component` | Unit, integration | L2 fuzzing |
| T5 Resource modified after approval | The Tools service refuses the stale version; the action fails and the approval is not restored. | `test_execute.py::test_resource_changed_after_approval_is_refused_by_the_tools_service`, `test_tools_executor.py::test_stale_precondition_is_not_executed` | Integration | — |
| T14 Concurrent executions | 20 concurrent execute calls on one approval give one execution; Tools side, 20 concurrent calls with one key execute once. | `test_execute.py::test_concurrent_executions_consume_the_approval_once`, `test_tools_executor.py::test_concurrent_calls_with_one_key_execute_once` | Integration (threads, one process) | 50-way race from the agent container (L2) |
| T17 Policy changed after approval | A restart with a different policy hash invalidates pending and approved actions; the same policy keeps them. | `test_approvals.py::test_policy_restart_invalidates_outstanding_approvals`, `::test_restart_with_the_same_policy_keeps_approvals`, `test_policy.py::test_any_byte_change_changes_the_policy_hash` | Integration | — |
| T18 Session tainted after approval | Taint between proposal and decision, or between approval and execution, invalidates the approval; clean reads do not. | `test_approvals.py::test_session_tainted_after_approval_invalidates_it`, `::test_session_tainted_before_the_decision_invalidates_the_request`, `::test_clean_reads_after_approval_do_not_invalidate_it` | Integration | — |

## G3 — Cumulative limits under concurrency and across agents

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T8 Split transactions | Three refunds of 400.00 against the 1000.00 account cap: the third is refused. The account cap is reached through two agents that each stay under their own cap. The per-agent cap is reached across accounts and across sessions. Six concurrent refunds by one agent never exceed its cap. A refused refund reserves nothing and does not consume its approval. | `test_budget.py::test_three_refunds_of_400_against_the_account_cap`, `::test_account_cap_is_reached_through_two_agents`, `::test_agent_cap_is_reached_across_accounts`, `::test_agent_cap_follows_the_agent_across_sessions`, `::test_concurrent_refunds_never_exceed_the_agent_cap`, `::test_three_agents_race_for_one_account_budget` | Integration (threads, one process) | Concurrent refunds from two agent containers (L2) |

## G4 — Failures do not execute; ambiguous outcomes stay reserved

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T13 Error or timeout leads to execution | Tools unreachable, unexpected or unlabeled replies: no content returned, nothing assumed executed. A `DENY` makes no call to the Tools service. An audit failure in the execute transaction executes nothing and consumes nothing. | `test_gateway_api.py::test_tools_service_unreachable`, `::test_unexpected_tools_reply_to_a_read_returns_no_content`, `::test_deny_makes_no_call_of_any_kind_to_the_tools_service`, `::test_audit_failure_means_nothing_is_executed`, `test_execute.py::test_audit_failure_consumes_nothing_and_executes_nothing` | Integration | — |
| T19 Crash or timeout after consumption | Timeout after the Tools service executed: `UNKNOWN`, budget held, reconciled to `COMMITTED` without a second execution. Timeout before: reconciled to `FAILED`, budget released, and the late request does not execute. Simulated crash after consumption, then restart: no second execution. While the Tools service cannot answer, the budget stays held. | `test_reconcile.py::test_timeout_after_execution_is_unknown_then_reconciled_to_committed`, `::test_timeout_before_execution_is_reconciled_to_failed_and_released`, `::test_crash_after_the_tools_service_executed_then_restart`, `::test_crash_before_the_tools_service_acted_then_restart`, `::test_budget_stays_held_while_the_tools_service_cannot_answer`, `test_budget.py::test_unknown_outcome_holds_the_budget` | Integration | The crash is an exception raised in the test transport, not a killed process |

## G5 — No security state transition without its audit event

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T15 Execution without audit, audit tampering | `UPDATE`, `DELETE` and `INSERT OR REPLACE` on `audit_events` are rejected by triggers. The chain verification detects a modified, re-hashed, removed or reordered entry. Every action's last audit event equals its state. An audit insert failure rolls the state change back. | `test_audit.py`, `test_gateway_api.py::test_every_state_transition_has_its_audit_event`, `::test_audit_failure_means_nothing_is_executed`, `::test_audit_failure_while_recording_a_read_returns_no_content` | Unit, integration | Truncation of the tail is not detected, by design (`test_audit.py::test_tail_truncation_is_not_detected`); external anchoring is deferred |

## G6 — Provenance comes from what the Gateway observed

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T12 Forged or laundered provenance | Taint derives only from Tools-assigned labels and is permanent. Claims in the body, the arguments or the reason are rejected or ignored. The agent API has two routes and none creates, switches or resets a session; identity comes from the token. The laundering scenario (tainted session A, clean session B) fails. Session and provenance rows cannot be rewritten in the database. A revoked token is refused on every route, before and after the next token is issued; a revocation committed while a request is in progress wins, and that request records, consumes and executes nothing. | `test_gateway_sessions.py`, `test_provenance.py`, `test_audit.py::test_session_and_provenance_history_cannot_be_rewritten`, `test_tools_executor.py::test_an_update_cannot_change_the_trust_label` | Unit, integration | Session-creation credential unreachable from the agent container (M3, L2). Cross-session agent memory is out of scope (H7). |
| T11 Plausible injected request accepted by the approver | The approval request carries the Gateway-derived taint status and sources, and the agent's reason under an "unverified" label; the approver tool shows taint before the reason, escapes it, and refuses to sign if the displayed action does not hash to the action hash. | `test_approvals.py::test_request_shows_the_action_and_gateway_derived_provenance`, `test_approver_cli.py::test_request_display_states_taint_and_marks_the_reason_unverified`, `::test_tool_refuses_to_sign_when_the_display_does_not_match_the_hash` | Integration | Whether an approver's decisions change is an L3 question (approver profiles); no human is measured |

## G7 — At most one effective execution per approval, given H6

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T3, T14, T19 (Tools side) | Idempotency keys and preconditions are enforced by the Tools service itself, in one transaction with the effect; a failed attempt burns its key; resolving an unknown key burns it, so a late request does not execute; a request held in the Tools service while its key is burned is refused by the Tools service itself when released, and the held request does not block the burn; every Tools execution is backed by a Gateway action with the same key. | `test_tools_executor.py` (idempotency, precondition and resolution sections), `test_tools_faults.py::test_key_burned_while_the_request_is_held_is_enforced_by_the_tools_service`, `test_gateway_api.py::test_every_tools_execution_is_backed_by_a_gateway_action` | Integration | L2 race |

## Threats not tied to a single goal

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T16 Approval flooding | A fourth pending approval in a session is denied without contacting the Tools service; decided or expired requests free a slot; other sessions are unaffected. | `test_approvals.py::test_pending_approvals_are_limited_per_session`, `::test_expired_requests_do_not_count_against_the_limit` | Integration | Approval burden metric (L3) |
| T20 Agent reaches evaluation endpoints | The Tools admin API and the Gateway admin and approver APIs are separate applications with their own tokens; their routes do not exist on the agent-facing or executor applications. | `test_tools_admin.py`, `test_approvals.py::test_agent_api_has_no_approval_or_admin_route`, `test_reconcile.py::test_no_application_exposes_a_reconciliation_route` | Integration | Network separation (M3, L2) |

## Supporting properties of the deployment

| Property | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| One application and one credential set per process | Each role serves exactly its own routes, starts with only its own secrets read from files, and refuses to start without them. The Gateway API process holds neither the admin nor the approver token; the admin and approver processes have no Tools client. | `test_serve.py` | Integration | The same, observed from inside the containers (L2 secrets and network tests) |
| Shared SQLite database | Every connection is WAL with `synchronous=FULL`, verified; six separate OS processes append to one audit chain without loss or gap. | `test_storage.py` | Integration (separate processes, one host) | Three containers on one named volume |
| LLM relay contract | Only `POST /api/chat`, only the allow-listed model, only allow-listed fields; model-management routes refused; the destination cannot be changed by the request; no redirect followed. | `test_llm_relay.py` | Unit | Abuse attempts from the agent container (L2) |
| Controlled faults | A request can be held before or after commit and released or dropped through the Tools admin API, without holding a database lock. | `test_tools_faults.py` | Integration | Used with a real container kill (K1–K3) |
| Attacker self-checks | The secret detector finds a secret in the forms it would leak in, from hashes only; failure causes are classified; a Tools-side count that differs from the expectation fails the record. | `test_attacker.py` | Unit | A positive control run in the baseline project |

## End-to-end evidence

One check has run across a container boundary: the LLM relay container, on an internal network plus the egress network, reached the model server bound to the host's loopback interface and reported the digest of the allow-listed model (`qwen3:8b`, `500a1f067a9f…`). The model server stayed bound to `127.0.0.1`.

Nothing else. The first L2 run did not complete: the Docker virtual machine's disk was full, every service failed to open its database at start-up, and the run was stopped. No L2 or L3 result exists.

| Layer | Status |
|---|---|
| LLM relay reaches the host model server | Done (start-up check) |
| L2 scripted attacker, per category | Implemented (`attacks/`), not run |
| L2 crash cases K1–K3 | Implemented, not run |
| Baseline positive control | Implemented, not run |
| L3 agent benchmark, policy bypass rate | Not implemented |
