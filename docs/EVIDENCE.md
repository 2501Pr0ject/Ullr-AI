# Evidence

What is tested, at which level, for each security goal (G1–G7) and each threat (T1–T20) of [`THREAT_MODEL.md`](THREAT_MODEL.md). Updated at every milestone. Current state: M3. Two L2 runs exist; the second passed. L3 is not built.

## Evidence levels

| Level | Meaning | Reached today |
|---|---|---|
| **Implemented** | The code or configuration exists. | Everything through M3 |
| **Unit-tested** | A function or module tested alone. | Canonicalization, schemas, policy, signing, audit, provenance, relay contract, attacker detectors |
| **Integration-tested** | Services exercised through their HTTP interfaces in one process, or as separate processes on one host. No container, no network isolation, no separate credential store. Faults are injected through the test transport, the database or the Tools fault barrier. | Tools service, Gateway, approvals, budgets, reconciliation, revocation, fault barrier, role wiring, shared SQLite |
| **Container-tested** | The property observed in the running Docker stack. | Start-up of the eleven services on a shared SQLite volume; the LLM relay reaching the model server on the host; audit chain and SQLite integrity after three container kills |
| **Adversarially verified** | The scripted attacker (L2) tried from inside the agent container and failed, with passing positive controls. | The items of L2 run 2 listed in "L2 runs" below, within its limits: one run, one Docker Desktop version, TCP connect from one agent container |
| **Not verified** | No test at that level. | Everything L2 run 2 did not attempt: see "Not verified" below |

**What "adversarially verified" means here.** In run 2, an attacker program inside the agent container attempted each listed attack and failed, while two positive controls passed: the same direct attack succeeded against an unprotected baseline, and a legitimately approved action executed exactly once. It is one run of a finite scripted list on one platform. It is not a proof of isolation, and it does not extend to anything the run did not attempt.

Test paths are relative to `tests/`. Reproduce with `make test`.

## G1 — No R2 action without a valid, signed, matching approval

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T2 R2 without approval | Each R2 tool is decided `REQUIRE_APPROVAL`, never `ALLOW`; the execute call refuses while pending; with a valid approval each R2 tool executes exactly once; every Tools execution of an R2 tool is backed by a stored decision whose signature verifies. | `test_gateway_api.py::test_irreversible_action_is_never_executed_without_approval`, `test_policy_decide.py::test_an_irreversible_action_is_never_allowed`, `test_execute.py::test_approved_irreversible_action_is_executed_once`, `::test_tools_executions_are_backed_by_signed_approvals` | Integration-tested; adversarially verified in L2 run 2: execution without approval attempted from the agent container and refused (A1, A5); F1 control executed once | More than one run; L3 |
| T6 Forged or self-issued approval | Unsigned, malformed, wrong-key, unregistered-approver, agent-as-approver, wrong-domain and mismatched-payload decisions are refused and change nothing. A correctly signed payload with any one bound field altered is refused. A decision cannot be replayed on another action, even an identical one. The registry refuses an agent identifier. | `test_signing.py`, `test_approvals.py::test_forged_decision_is_refused_and_changes_nothing`, `::test_correctly_signed_payload_with_one_field_altered_is_refused`, `::test_decision_replayed_on_another_action_is_refused`, `::test_decision_for_an_identical_later_action_is_not_reusable`, `::test_gateway_refuses_to_start_with_an_agent_as_approver` | Unit-tested, integration-tested; in L2 run 2 the agent could not reach the approver application or any decision route, and the approver key and channel token were not found in the agent container. The signature checks themselves were not attacked across containers | Forged decisions submitted to the approver application across containers |
| T7 Expired approval | Expiry is checked on the Gateway clock at decision and at execution; a decision cannot extend it and may shorten it. | `test_approvals.py::test_expired_request_cannot_be_approved`, `::test_expired_approval_is_not_executed`, `::test_decision_cannot_extend_the_expiry`, `::test_approver_can_shorten_the_validity` | Integration-tested; adversarially verified in L2 run 2: an expired approval was refused (A6) | —  |
| T9 Unknown tool, alias, case variant | Exact allow-list at schema, Gateway and Tools level. | `test_schemas.py::test_unknown_alias_and_variant_tool_names_rejected`, `test_gateway_api.py::test_unknown_alias_and_case_variant_tools_are_denied`, `test_tools_executor.py::test_invalid_requests_are_rejected_with_the_gateway_schemas` | Unit-tested, integration-tested; adversarially verified in L2 run 2: an unknown tool and a case variant were refused (A10) | — |
| T10 Malformed or ambiguous arguments | Duplicate keys, floats, `NaN`, encodings, non-NFC and invisible characters, identifier and amount formats, unknown fields, no coercion, request size limit before parsing. | `test_canon.py`, `test_schemas.py`, `test_asgi.py`, `test_gateway_api.py::test_malformed_proposals_are_denied`, `::test_body_above_the_limit_is_rejected_before_parsing` | Unit-tested, integration-tested; adversarially verified in L2 run 2: the listed malformed, oversized, duplicate-key and non-canonical requests were refused (A4-fuzz, A10); a finite list, not exhaustive fuzzing | Systematic fuzzing |
| T1 Direct call to the Tools service | The executor API refuses requests without the executor token. | `test_tools_executor.py::test_execute_requires_the_executor_token` | Integration-tested; adversarially verified in L2 run 2: the direct attack failed at name resolution, no route existed to the Tools network, no executor credential was found; the same attack executed in the baseline | More than one run and platform; vantage points other than TCP connect from one agent container |

## G2 — One approval, one execution, one exact action, one resource version, one policy, one provenance state

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T3 Approval replayed | An approval is consumed by its execution; further execute calls are refused; a failed or unknown execution does not restore it. Tools side: a repeated idempotency key returns the stored result. | `test_execute.py::test_approval_is_single_use`, `::test_failed_execution_does_not_restore_the_approval`, `test_tools_executor.py::test_same_key_twice_executes_once_and_replays_the_result` | Integration-tested; adversarially verified in L2 run 2: a consumed approval was refused three times (A3) | — |
| T4 Arguments changed after approval | Resent arguments that do not hash to the approved action are refused without consuming the approval; approving one document does not cover another. | `test_execute.py::test_other_action_cannot_ride_on_an_approval`, `::test_changed_refund_arguments_are_refused`, `::test_changed_email_body_is_refused`, `test_canon.py::test_action_hash_changes_with_any_component` | Unit-tested, integration-tested; adversarially verified in L2 run 2: changed tool, resource and arguments and nine non-canonical variants were refused (A4, A5) | Systematic fuzzing |
| T5 Resource modified after approval | The Tools service refuses the stale version; the action fails and the approval is not restored. | `test_execute.py::test_resource_changed_after_approval_is_refused_by_the_tools_service`, `test_tools_executor.py::test_stale_precondition_is_not_executed` | Integration-tested | — |
| T14 Concurrent executions | 20 concurrent execute calls on one approval give one execution; Tools side, 20 concurrent calls with one key execute once. | `test_execute.py::test_concurrent_executions_consume_the_approval_once`, `test_tools_executor.py::test_concurrent_calls_with_one_key_execute_once` | Integration-tested (threads, one process); adversarially verified in L2 run 2: 50 separate processes on one approval produced one execution (C1) | — |
| T17 Policy changed after approval | A restart with a different policy hash invalidates pending and approved actions; the same policy keeps them. | `test_approvals.py::test_policy_restart_invalidates_outstanding_approvals`, `::test_restart_with_the_same_policy_keeps_approvals`, `test_policy.py::test_any_byte_change_changes_the_policy_hash` | Integration-tested | — |
| T18 Session tainted after approval | Taint between proposal and decision, or between approval and execution, invalidates the approval; clean reads do not. | `test_approvals.py::test_session_tainted_after_approval_invalidates_it`, `::test_session_tainted_before_the_decision_invalidates_the_request`, `::test_clean_reads_after_approval_do_not_invalidate_it` | Integration-tested | — |

## G3 — Cumulative limits under concurrency and across agents

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T8 Split transactions | Three refunds of 400.00 against the 1000.00 account cap: the third is refused. The account cap is reached through two agents that each stay under their own cap. The per-agent cap is reached across accounts and across sessions. Six concurrent refunds by one agent never exceed its cap. A refused refund reserves nothing and does not consume its approval. | `test_budget.py::test_three_refunds_of_400_against_the_account_cap`, `::test_account_cap_is_reached_through_two_agents`, `::test_agent_cap_is_reached_across_accounts`, `::test_agent_cap_follows_the_agent_across_sessions`, `::test_concurrent_refunds_never_exceed_the_agent_cap`, `::test_three_agents_race_for_one_account_budget` | Integration-tested (threads, one process); adversarially verified in L2 run 2: six refunds against one agent budget produced two executions (C2); three agent containers against one account budget produced two reservations, one refusal and one execution (C3) | Account budget under contention without the version precondition serializing the refunds |

## G4 — Failures do not execute; ambiguous outcomes stay reserved

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T13 Error or timeout leads to execution | Tools unreachable, unexpected or unlabeled replies: no content returned, nothing assumed executed. A `DENY` makes no call to the Tools service. An audit failure in the execute transaction executes nothing and consumes nothing. | `test_gateway_api.py::test_tools_service_unreachable`, `::test_unexpected_tools_reply_to_a_read_returns_no_content`, `::test_deny_makes_no_call_of_any_kind_to_the_tools_service`, `::test_audit_failure_means_nothing_is_executed`, `test_execute.py::test_audit_failure_consumes_nothing_and_executes_nothing` | Integration-tested | — |
| T19 Crash or timeout after consumption | Timeout after the Tools service executed: `UNKNOWN`, budget held, reconciled to `COMMITTED` without a second execution. Timeout before: reconciled to `FAILED`, budget released, and the late request does not execute. Simulated crash after consumption, then restart: no second execution. While the Tools service cannot answer, the budget stays held. | `test_reconcile.py::test_timeout_after_execution_is_unknown_then_reconciled_to_committed`, `::test_timeout_before_execution_is_reconciled_to_failed_and_released`, `::test_crash_after_the_tools_service_executed_then_restart`, `::test_crash_before_the_tools_service_acted_then_restart`, `::test_budget_stays_held_while_the_tools_service_cannot_answer`, `test_budget.py::test_unknown_outcome_holds_the_budget` | Integration-tested; adversarially verified in L2 run 2: the Gateway API container was killed at three points fixed in the Tools service (K1, K2, K3) and restarted; a process kill, not a power loss | Power loss; a kill at a point not fixed by the Tools barrier |

## G5 — No security state transition without its audit event

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T15 Execution without audit, audit tampering | `UPDATE`, `DELETE` and `INSERT OR REPLACE` on `audit_events` are rejected by triggers. The chain verification detects a modified, re-hashed, removed or reordered entry. Every action's last audit event equals its state. An audit insert failure rolls the state change back. | `test_audit.py`, `test_gateway_api.py::test_every_state_transition_has_its_audit_event`, `::test_audit_failure_means_nothing_is_executed`, `::test_audit_failure_while_recording_a_read_returns_no_content` | Unit-tested, integration-tested; container-tested: the audit chain verified after each of the three container kills. The agent has no access to the database; tampering was not attempted in L2 | Truncation of the tail is not detected, by design (`test_audit.py::test_tail_truncation_is_not_detected`); external anchoring is deferred  |

## G6 — Provenance comes from what the Gateway observed

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T12 Forged or laundered provenance | Taint derives only from Tools-assigned labels and is permanent. Claims in the body, the arguments or the reason are rejected or ignored. The agent API has two routes and none creates, switches or resets a session; identity comes from the token. The laundering scenario (tainted session A, clean session B) fails. Session and provenance rows cannot be rewritten in the database. A revoked token is refused on every route, before and after the next token is issued. No action whose authorization transaction commits after the revocation is authorized, consumed or sent to the Tools service; an action authorized before it may take effect afterwards, which is tested as such. The order is checked on the audit sequence, including under concurrent requests. Stress test history: a defect was confirmed in a reconstructed earlier version of the test (a comparison across rounds); the cause of the first historical failure is not verifiable for lack of a trace; the current version is stable over 300 runs, in a single process with threads. | `test_gateway_sessions.py` (including `::test_action_authorized_before_revocation_may_take_effect_after_it` and `::test_revocation_racing_concurrent_requests`), `test_provenance.py`, `test_audit.py::test_session_and_provenance_history_cannot_be_rewritten`, `test_tools_executor.py::test_an_update_cannot_change_the_trust_label` | Unit-tested, integration-tested; in L2 run 2 the agent could not create or switch a session (routes absent, admin application unreachable, credential not found) and a revoked token was refused before and after the next one was issued. Peer agents and written resources remain open channels | Peer-agent channel; written resources (deferred design); cross-session agent memory is out of scope (H7) |
| T11 Plausible injected request accepted by the approver | The approval request carries the Gateway-derived taint status and sources, and the agent's reason under an "unverified" label; the approver tool shows taint before the reason, escapes it, and refuses to sign if the displayed action does not hash to the action hash. | `test_approvals.py::test_request_shows_the_action_and_gateway_derived_provenance`, `test_approver_cli.py::test_request_display_states_taint_and_marks_the_reason_unverified`, `::test_tool_refuses_to_sign_when_the_display_does_not_match_the_hash` | Integration-tested | Whether an approver's decisions change is an L3 question (approver profiles); no human is measured |

## G7 — At most one effective execution per approval, given H6

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T3, T14, T19 (Tools side) | Idempotency keys and preconditions are enforced by the Tools service itself, in one transaction with the effect; a failed attempt burns its key; resolving an unknown key burns it, so a late request does not execute; a request held in the Tools service while its key is burned is refused by the Tools service itself when released, the refusal is recorded on the fault row even when no caller is left, and the held request does not block the burn; every Tools execution is backed by a Gateway action with the same key. | `test_tools_executor.py` (idempotency, precondition and resolution sections), `test_tools_faults.py::test_key_burned_while_the_request_is_held_is_enforced_by_the_tools_service`, `test_gateway_api.py::test_every_tools_execution_is_backed_by_a_gateway_action` | Integration-tested | — |

## Threats not tied to a single goal

| Threat | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| T16 Approval flooding | A fourth pending approval in a session is denied without contacting the Tools service; decided or expired requests free a slot; other sessions are unaffected. | `test_approvals.py::test_pending_approvals_are_limited_per_session`, `::test_expired_requests_do_not_count_against_the_limit` | Integration-tested; adversarially verified in L2 run 2: a fourth pending approval was denied (A9) | Approval burden metric (L3)  |
| T20 Agent reaches evaluation endpoints | The Tools admin API and the Gateway admin and approver APIs are separate applications with their own tokens; their routes do not exist on the agent-facing or executor applications. | `test_tools_admin.py`, `test_approvals.py::test_agent_api_has_no_approval_or_admin_route`, `test_reconcile.py::test_no_application_exposes_a_reconciliation_route` | Integration-tested; adversarially verified in L2 run 2: the admin applications, the controller and their networks were unreachable from the agent, and their routes absent from the agent API (N2, A8) | Vantage points other than TCP connect from one agent container |

## Supporting properties of the deployment

| Property | What is tested | Tests | Level | Missing |
|---|---|---|---|---|
| One application and one credential set per process | Each role serves exactly its own routes, starts with only its own secrets read from files, and refuses to start without them. The Gateway API process holds neither the admin nor the approver token; the admin and approver processes have no Tools client. | `test_serve.py` | Integration-tested | —. Observed from the agent container in L2 run 2 for the secrets and the routes |
| Shared SQLite database | Every connection is WAL with `synchronous=FULL`, verified; six separate OS processes append to one audit chain without loss or gap. | `test_storage.py` | Integration-tested (separate processes, one host) | —. Three containers shared one named volume throughout L2 run 2; integrity check passed after each kill |
| LLM relay contract | Only `POST /api/chat`, only the allow-listed model, only allow-listed fields; model-management routes refused; the destination cannot be changed by the request; no redirect followed. | `test_llm_relay.py` | Unit-tested | —. 15 abuse attempts from the agent container were refused in L2 run 2 |
| Controlled faults | A request can be held before or after commit and released or dropped through the Tools admin API, without holding a database lock. | `test_tools_faults.py` | Integration-tested | —. Used with real container kills in L2 run 2 (K1–K3) |
| Attacker self-checks | The secret detector finds a secret in the forms it would leak in, from hashes only; failure causes are classified; a Tools-side count that differs from the expectation fails the record. | `test_attacker.py` | Unit-tested | —. Positive controls passed in L2 run 2 |

## L2 runs

Results are in [`results/l2/`](../results/l2/). Each run has its report; run 2 also has the attacker's raw output and the Tools-side counters.

| Run | Executed on | Results committed in | Records | Passed | Failed |
|---|---|---|---|---|---|
| 1 | `b842701` | `3f79a4b` (report unchanged) | 146 | 142 | 4 |
| 2 | `769eecc` | `f014737` | 146 | 146 | 0 |

**Run 1** found that the agent could reach two services of the Docker Desktop virtual machine. The VM's bridge devices for the two agent networks had an address in those networks, and the VM's `rpcbind` (port 111) and `rpc.statd` (a dynamic port) listen on all interfaces. From the agent container both accepted connections, and `rpcbind` answered a program listing. Two other failed records were open ports on the agent's own addresses. Details, with evidence and hypotheses kept apart: [`results/l2/run-1/INVESTIGATION.md`](../results/l2/run-1/INVESTIGATION.md).

**Between the runs**, two changes:
- `com.docker.network.bridge.inhibit_ipv4` on the two agent networks, so that the VM has no IPv4 address there (`8771b1e`). Checked before run 2: the former bridge addresses no longer answer; the agent's interfaces have IPv6 disabled and cannot reach the bridges' link-local addresses.
- The scanner records both endpoints of every successful connection and reports a connection whose endpoints are identical as `self_connect` (`d3b11f9`). An unexpected open port still fails the record.

**Run 2**, from inside the agent container:

| Area | What was attempted | Result |
|---|---|---|
| Network | Name resolution of every other service, external and Docker host names, by the system resolver and by direct queries; connection to the other five networks; egress; full TCP connect scan of 30 addresses on ports 1–65535 | Only `gateway-api` and `llm-relay` resolve and answer, on port 8000; no route elsewhere; no unexpected open port; nothing on the former bridge addresses |
| Scan observations | — | Three connections with identical local and peer endpoints (`self_connect`), on `127.0.0.1` and on the agent's two addresses. Reported with their endpoints; an observation about those sockets, nothing more |
| Secrets | The seven privileged secrets, searched by hash in the environment of the visible processes and in 5,222 readable files | None found. 14 files unreadable, 4 read to 4 MB only |
| Privileges and mounts | Mount table, write attempts, uid, capabilities | No unexpected mount, no write outside `/tmp`, uid 10001, no capability, no Docker socket |
| Direct path | Call the Tools executor with every credential found | Blocked at name resolution |
| API | 40 attempts: no approval, other applications' routes, replay, changed and non-canonical arguments, another action's approval, expiry, foreign action, pending limit, malformed and oversized bodies, bad tokens | All refused |
| Revocation | Old token after revocation, on both routes, before and after the next token | Refused; new token accepted |
| Relay | 15 requests outside the contract | All refused; one allowed chat succeeded |
| Concurrency | One approval in 50 processes; six refunds against an agent budget; three agents against an account budget | 1, 2 and 1 effective executions |
| Crash | Gateway API container killed at K1, K2, K3, then restarted | 0, 1 and 0 effective executions; in K3 the Tools service refused the released request with the abandoned-key error |

**Positive controls, both passed.** In the baseline project the same direct attack reached the Tools executor and produced 2 effective executions. In the protected stack the approved action F1 produced exactly 1.

**Tools-side reconciliation.** The Tools service recorded 7 effective executions in the protected stack, each backed by a committed Gateway action: the first use of the approval later replayed (A3), F1, C1, two for C2, one for C3 and K2. Its 3 failed entries are the second reserved refund of C3 (refused on the version precondition) and the abandoned keys of K1 and K3. Record counts: `report.json` holds 146 records, of which 142 come from the attacker and 4 are built by the driver (the account-budget summary and the three K records). `raw_records.jsonl` holds 148 attacker records. The six extra are the execute and retry attempts of K1, K2 and K3, which the report folds into the three K records. The 142 attacker records of the report are identical, field for field, to their raw lines.

**Observed, not blocked.** Peer agent containers resolve by DNS and accept connections from the agent.

## Not verified

- **One run, one platform.** Docker Desktop 27.4.0 on macOS. The run-1 finding shows that the platform matters.
- **One vantage point.** TCP connect and DNS from one agent container. No UDP other than DNS, nothing requiring raw sockets, no scan from the other containers.
- **Trusted containers and the VM.** The bridges of the five other networks keep a VM address, so the Gateway, Tools, controller, approver and relay containers can still reach the VM's RPC services.
- **Peer agents.** Agent containers that share a network can exchange content and tokens outside the Gateway's view.
- **Cross-session provenance through written resources** (a tainted session writes an internal document that a clean session reads). Not tested; a design for it is deferred.
- **Forged decisions** against the approver application, and the **audit-order invariant** for revocation, inside the stack. Both are integration-tested only.
- **Power loss**, as opposed to a process kill.
- **Status route.** `GET /v1/actions/{id}` was added to the agent API after L2 run 2. It is integration-tested (owner only, 404 for another session's action, no state change); it has not been attacked from the agent container and must be part of the next L2 run.
- **L3.** The harness is built and tested in process; no full run exists.
