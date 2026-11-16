# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-15

### Added
- Relay: HTTP + WebSocket mailbox server storing only ciphertext and routing metadata in SQLite;
  Docker image and `docker-compose.yml`; `/healthz`; admin CLI (`invite`, `revoke`);
  24h envelope TTL, 64 KiB ciphertext limit, 30 sends/min per identity.
- Core: Ed25519 signing and X25519 sealed-box envelopes (libsodium), key fingerprints.
- Plugin for Claude Code: MCP channel server (`experimental['claude/channel']`, no remote
  permission relay) with tools `bridge_send`, `bridge_message`, `bridge_reply`, `bridge_status`;
  `bridge` skill; PreToolUse hook.
- Two-way threads: a receiver can ask clarifying questions and the sender can answer, until
  the receiver replies with the result.
- Owner CLI `bridge`: `init`, `share`, `unshare`, `list`, `approve`, `reject`, `pause`, `resume`,
  `pin --reset`, `show`, `status`, `clear`. Owner commands are deliberately a CLI rather than
  `/bridge:*` skills, so that the model cannot invoke them.
- Unsharing or narrowing a share takes effect at once: the relay drops the threads opened into
  the session by the removed people and their queued envelopes (threads the session opened to
  others, and their queued replies, are kept; a queued envelope whose thread is unknown is judged
  by its sender), the plugin drops their messages and ends their
  active task.
- Injected results set a 10-minute sender marker (a marker the hook has held never expires);
  a new peer turn resets an owner approval.
- Markers carry the pid of the Claude Code process (the server's parent): a crash or restart of
  the server does not lift them, and a restarted server keeps them (one whose Claude Code exited
  is re-stamped with the new parent, covering `claude --resume`). An orphaned server (parent pid 1
  or changed) injects nothing and reports it in its log, the audit log and `bridge status`.
- The hook always denies reads and searches of held peer content (`sessions/*/held/`); when the
  hook itself cannot start (e.g. an unbuilt plugin) it denies only while the session has an
  active marker.
- Receiver-side safety: per-session opt-in shares, trust-on-first-use key pinning, LLM risk
  classifier (`claude -p --model haiku`, then `ANTHROPIC_API_KEY`) with fail-closed holds,
  deterministic deny-list in the hook, held-work approval flow, local audit log.
- `README.md`, `AGENTS.md`, `SECURITY.md`, `policy.example.yaml`, MIT `LICENSE`.
