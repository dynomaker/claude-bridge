# Security

## Threat model

| Threat | Mitigation |
| --- | --- |
| Sender key theft: someone with a teammate's private key sends tasks as them | Only sessions explicitly shared with that person are reachable. Every task is risk-classified on the receiver; risky ones are held. During a remote thread the PreToolUse hook enforces the deny-list. Revoke the identity with the relay admin CLI (`revoke <name>`); this also purges its queued envelopes and shares. |
| Malicious or compromised relay | Envelopes are signed (Ed25519) and sealed (X25519 sealed box), so the relay cannot read or forge content. Receivers pin each peer's keys on first use and refuse a changed key (`bridge pin --reset <id>` after verifying out-of-band). The relay still sees metadata: who talks to whom, when, and message sizes. It can drop or delay messages. |
| Prompt injection inside a task or message | Inbound text is treated as untrusted data. The classifier gates it before injection, and the hook enforces the deny-list on tool calls regardless of what the model was convinced of. Permission prompts are never relayed to remote parties. |
| Share narrowed or removed | The relay drops the removed people's threads and queued envelopes at once; the plugin drops their messages and ends their active task. |
| Owner absent | The receiver runs unattended only within policy. Anything at or above the risk threshold, any classifier error or timeout, and any blocked tool call is held until the owner runs `bridge approve` or `bridge reject`. The relay queues for 24 hours. |

## Residual risk

A remote task's text stays in the receiving session's context after it ends and can influence
later turns; tool-level enforcement applies only while a remote thread is active. The deny-list is
best-effort text matching, the classifier is an LLM and can be wrong, and shared sessions run
without permission prompts by design. Share dedicated per-track sessions, not your main one.

Results are gated like messages; an injected result keeps the sender's session under a sender
marker for 10 minutes (or until the owner approves/rejects it or the session sends a new task),
so tool calls right after a result are checked against it. Later turns are not. A marker the
hook has held never expires; only the owner lifts it.

Markers record the pid of the Claude Code process that holds the peer text (the bridge server's
parent), not of the server, so a crashed or restarted server does not lift them. A restarted
server keeps them and re-stamps one whose Claude Code has exited with its own parent (a resumed
session still holds the peer text). If that Claude Code process is gone and no server took the
marker over, or a result marker expired without being held, the hook treats the session as having
no active task. A server whose parent is pid 1 or has changed since it started (orphaned) refuses
to inject peer content and says so in its log, the audit log and `bridge status`. `bridge clear
--session <name>` removes a stuck marker by hand.

This assumes Claude Code starts the bridge server directly (`plugin/.mcp.json` runs `node` with
no wrapper). A long-lived wrapper process between them would be recorded instead of Claude Code,
and a server crash would then no longer leave the session gated.

When the hook itself cannot start (for example an unbuilt plugin), the `hooks.json` fallback
denies tool calls only while the session has an active marker. Without one it allows them, and
the always-on rule that keeps reads away from held peer content (`sessions/*/held/`) is not
enforced in that state. Build the plugin before loading it.

## Known relay limits (public deployments)

The relay is built for a small team behind TLS. Before exposing it to the internet, know that
v0.1 does not defend against:

- unauthenticated connections: pre-auth WebSocket connections are not capped;
- invalid frames: malformed or unauthenticated frames are not rate-limited (only authenticated
  sends are, at 30 per minute per identity);
- queue growth: the per-recipient queue has no size cap (entries expire after 24 hours);
- identity enumeration: `GET /v1/identities/:id` answers for any name without authentication.

Put it behind a reverse proxy with connection and request limits, or keep it on a private
network.

## Reporting a vulnerability

Please report privately through the repository's GitHub Security Advisories ("Report a
vulnerability" on the Security tab). Do not open a public issue for security problems. Include
steps to reproduce and the affected version. We aim to acknowledge reports within a few days.
