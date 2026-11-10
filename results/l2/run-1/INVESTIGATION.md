# Run 1: investigation of its findings

`report.json` in this directory is the first full L2 run, unchanged: 146 records, 142 passed, 4 failed. This note records what was investigated afterwards. Evidence and hypotheses are kept apart. The raw outputs of the investigation are not in the repository.

Environment: Docker Desktop 27.4.0 on macOS, Linux VM kernel 6.10.14-linuxkit. Everything below is specific to it.

## A. Two listeners on the Docker VM, reachable from the agent

Failed records: `N3-scan-172.30.0.8`, `N3-scan-172.30.0.24` (ports 111 and 57483 open).

**Evidence**

- `172.30.0.8` and `172.30.0.24` were not containers. They were the addresses of the VM's bridge devices for `net_agent` and `net_llm`.
- In the VM, `rpcbind` listens on TCP and UDP port 111 and `rpc.statd` on a dynamic TCP port, both bound to all interfaces, IPv4 and IPv6. Both are started by the VM's init; neither belongs to this project.
- From the agent container, connections to port 111 and to the `rpc.statd` port succeeded on both bridge addresses, with distinct local and peer endpoints.
- A portmapper listing request sent from the agent to port 111 was answered: portmapper versions 2 to 4, and the status program (`rpc.statd`) version 1. No NFS, mount or lock-manager program was registered. Nothing beyond the listing was attempted.
- The `rpc.statd` port changes: 57483 in the run, 64109 and then 61991 during the investigation.

**Hypothesis**

- That port 57483 in the run was `rpc.statd`. It is consistent with the above; it was not observed at the time of the run.

**Change tested and kept**

`com.docker.network.bridge.inhibit_ipv4: "true"` on `net_agent` and `net_llm`. With it, observed:

- the two bridges have no IPv4 address in the VM; the five other bridges of the stack still have one;
- from the agent, the former bridge addresses no longer answer on port 111 or on the `rpc.statd` port, the latter discovered through `rpcbind` at the time of the test;
- both bridges carry an IPv6 link-local address in the VM, but the agent's interfaces have IPv6 disabled and connections to those addresses fail with "network unreachable";
- `gateway-api` and `llm-relay` still resolve and accept connections; name resolution is otherwise unchanged;
- an approved action produced exactly one effective execution, counted on the Tools side before and after; one chat request through the relay succeeded;
- a full port scan found no open port on the former bridge addresses.

**Not covered**

- The containers on the five other networks (Gateway, Tools, controller, approver, relay) can still reach the VM's RPC services. They are trusted in the threat model.
- A configuration with IPv6 enabled on the agent networks.

## B. Open ports on the agent's own addresses

Failed records: `N3-scan-172.30.0.11` (port 42362), `N3-scan-172.30.0.25` (port 60818).

**Evidence**

- Both ports are inside the container's local port range (32768–60999).
- The agent's network namespace had one listening socket, Docker's resolver on `127.0.0.11`.
- A controlled test from the agent, connecting to its own addresses across the local port range, produced 7 successful connections out of about 141,000 attempts. For each, the local endpoint and the peer endpoint were identical and the socket was in state ESTABLISHED.
- A full rescan of the agent's two addresses from another agent container found every port refused.
- After the `inhibit_ipv4` change, a scan with the unchanged scanner again reported open ports on the agent's own addresses only (six ports, all in the local port range).

**Hypothesis**

- That the two ports in the run, and the six in the later scan, were TCP self-connections. The scanner did not record the endpoints of successful connections, so this cannot be confirmed for those connections.

**Change made to the measurement**

The scanner now records the local and peer endpoints of every successful connection. A connection is classified as a self-connection only when the two endpoints are identical, and is reported under that name with its endpoints. Any other open port that is not expected still fails the record. A self-connection is an observation about a socket during the scan; it is not a statement about the port.

## C. A failure of the revocation stress test during development

**Evidence**

- An early version of `test_revocation_racing_concurrent_requests` failed once in six runs. No trace of that failure was kept.
- That version was never committed. It was reconstructed from the session log and run 300 times in an isolated copy: 52 failures, 49 on `assert all(seq < revoked_seq for seq in executing.values())` and 3 on the assertion that some request was rejected.
- In all 52, every `EXECUTING` event that followed the compared revocation belonged to another session, in a later round, and preceded its own session's revocation. The test compared against the first revocation in a database shared by all rounds.
- No `EXECUTING` event of a revoked session followed that session's revocation in any of the 300 runs of the reconstructed version, nor in 300 runs of the current version, which all passed.

**Conclusion and limit**

- Defect confirmed in the reconstructed version: a comparison across rounds, in the test.
- The cause of the first historical failure cannot be verified, for lack of a trace.
- The current version is stable over 300 runs. This is one process with threads; it says nothing about several containers sharing the database.
