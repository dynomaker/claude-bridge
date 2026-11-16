# claude-bridge — design

Date: 2026-11-15. Status: draft for approval.

## Intent

A small team (three people, each running Claude Code on their **own machine**)
splits projects into tracks. Today, when person A needs something done in a
track owned by person B, A writes to B in a messenger, B copy-pastes it into
their Claude, waits, and pastes the answer back. B is a human relay.

claude-bridge removes the human relay: A's Claude sends a task straight into a
**specific, explicitly shared** Claude Code session of B, B's Claude does it
without B being present, and the result comes back to A's session. Dangerous
work is never done unattended — it waits for B.

The project will be published on GitHub under MIT, so it must be generic (no
company names, hosts, people) and deployable by an agent from `AGENTS.md`.

## Goals

- Send a task from my session to a named shared session on someone else's
  machine; get the final result back into my session.
- Sharing is **per session**, opt-in by the session owner, revocable at any time.
- Receiving side runs tasks **without the owner online**, as long as they pass
  the owner's policy.
- Anything outside policy (destructive, deploy, secrets, out-of-track) is held
  until the owner approves it locally.
- Privacy both ways: a sender sees only their own task and its result, never the
  session's history; the owner never needs to see the sender's other sessions.
- Self-hosted relay; first deployment on the author's own server in Docker.

## Non-goals

- No shared chat/history view, no "remote terminal", no live streaming of the
  other session's transcript.
- No file transfer beyond text in v1 (attachments can come later).
- No multi-tenant SaaS, no web UI in v1.
- Not a replacement for the owner's own Claude Code permission settings — it
  adds restrictions, never removes them.

## Anti-goals (failure even if it "works")

- A sender (or anyone who steals a sender's key) can make the receiving Claude
  delete data, push to protected branches, deploy, read/exfiltrate secrets, or
  change claude-bridge's own config/access list.
- A remote sender can **approve permission prompts** on the receiver's machine.
- The relay operator can read task contents.
- Access to one shared session implies access to any other session of that person.

## Architecture

```
 A's machine                     relay (Docker, self-hosted)            B's machine
 ┌──────────────┐  HTTPS/WSS   ┌──────────────────────────┐  WSS   ┌──────────────────┐
 │ Claude Code  │─────────────▶│ mailbox router            │◀──────│ Claude Code      │
 │ + bridge MCP │◀─────────────│ (stores only ciphertext,  │──────▶│ + bridge channel │
 │  (send tool) │              │  routing ids, timestamps) │       │ + policy gate    │
 └──────────────┘              └──────────────────────────┘       │ + PreToolUse hook│
                                                                    └──────────────────┘
```

Three components, one TypeScript/Node codebase (my call; matches the existing
Claude Code channel-plugin ecosystem):

1. **Relay** — a tiny HTTP + WebSocket server. Knows identities (public keys),
   share records (`session_id → allowed sender ids`) and queues encrypted
   envelopes. Never sees plaintext. Persists to SQLite. Ships as a Docker image
   plus `docker-compose.yml`.
2. **Bridge plugin** (Claude Code plugin) — one MCP server that is both:
   - a **channel** (`experimental['claude/channel']`) that pushes incoming tasks
     into the live session as `<channel source="bridge" ...>` events — the same
     mechanism the official Telegram plugin uses;
   - tools: `bridge_send(to, task)`, `bridge_reply(task_id, text)`,
     `bridge_status(task_id)`, and inbound results delivered back as channel
     events in the sender's session.
   - It must **not** declare `claude/channel/permission`: permission prompts are
     never relayed to remote senders.
3. **Policy gate** on the receiving side (part of the plugin):
   - **Pre-classifier**: before an inbound task is injected, it is checked
     against the session's policy (deterministic rules first, then an LLM
     classifier call — Haiku-class model — with the track description). Verdict
     `allow` → inject; `hold` → queue for owner; `deny` → reject to sender with
     reason.
   - **PreToolUse hook**: while a remote task is active in the session (marker
     file written by the plugin, cleared on `bridge_reply`), every tool call is
     checked against the hard deny-list and path scope. Violations are blocked
     and the task flips to `held` — the owner sees it next time they look, and
     the sender is told "waiting for owner".

## Identities, sharing, and the user flow

- Each person runs `bridge init` once: generates an Ed25519 signing key and an
  X25519 encryption key locally (`~/.claude/channels/bridge/`), registers the
  public keys on the relay with a one-time **invite code** issued by the relay
  admin. Private keys never leave the machine.
- Session owner shares a session from inside it: `/bridge:share <name> <person…>`
  (e.g. `front alice bob`) plus a one-line track description and an
  optional path scope. `/bridge:unshare <name>` revokes instantly. `/bridge:list`
  shows what is shared. These commands only work from the owner's terminal;
  the plugin refuses any share/ACL change that arrives via a channel message.
- Sender: tells their Claude "send to bob/front: fix the pricing page
  header". Claude calls `bridge_send`; result arrives later as a channel event.
- Session names are only addresses; the receiver's plugin maps name → live
  session. If the session is not running, tasks queue on the relay (TTL, my call:
  24h) and are delivered when it reconnects.

## Security layers (also the outline for README "Why it's safe")

1. **Opt-in per session** — nothing is reachable until the owner shares that
   exact session with named people. Default is closed.
2. **Strong identity** — every envelope is signed by the sender's Ed25519 key;
   the receiver verifies against the key registered for that person, so the
   relay cannot forge senders. Invites are single-use; keys revocable.
3. **End-to-end encryption** — envelopes are sealed to the receiver's X25519 key
   (libsodium sealed box + signature). The relay stores only ciphertext and
   routing metadata.
4. **Receiver-side policy, not sender-side** — the owner's machine decides what
   runs; a compromised sender or relay cannot loosen it.
5. **Pre-classification** — deterministic deny rules (rm -rf, force push,
   deploy/infra commands, secret files, DB drops, editing bridge/Claude config)
   then an LLM classifier for "does this fit the track". Unsure ⇒ hold.
6. **Runtime enforcement** — PreToolUse hook blocks violating tool calls during
   remote tasks regardless of what the model was convinced of (defends against
   prompt injection in the task text).
7. **No remote permission approval** — permission prompts stay local to the owner.
8. **Privacy by construction** — the only thing returned to the sender is what
   Claude explicitly passes to `bridge_reply`; the plugin instructions tell
   Claude not to include unrelated session context, and transcript is never sent.
9. **Audit log** — every inbound task, verdict, blocked tool call and reply is
   appended locally (`~/.claude/channels/bridge/audit.log`).
10. **Rate limits & size limits** on the relay and the receiver.

Known residual risk (to state honestly in README): a remote task's text stays
in the receiving session's context after it ends and could influence later
turns; tool-level enforcement only applies while the remote task is marked
active. Mitigation advice: share dedicated sessions per track.

## Deliverables

- `relay/` (server + Dockerfile + docker-compose.yml), `plugin/` (Claude Code
  plugin: MCP channel server, skills `/bridge:share|unshare|list|init`, hook),
  default `policy.example.yaml`.
- `README.md` — what it is, quickstart, **"Why it's safe"** section with the
  layers above in short form.
- `AGENTS.md` — step-by-step instructions an agent can follow to deploy the relay
  (Docker, TLS/reverse proxy or Cloudflare Tunnel, admin invite creation) and to
  install the plugin on a teammate machine.
- `SECURITY.md` — threat model summary and how to report issues.
- `LICENSE` — MIT.
- Tests: crypto/envelope roundtrip, ACL enforcement on relay, policy rules,
  hook blocking.

## Deployment constraint (first install)

The author's server currently answers on IPv6 only from the outside. If
teammates lack IPv6, put the relay behind Cloudflare Tunnel or an IPv4 reverse
proxy. `AGENTS.md` covers both.

## Calls made by the designer (check these)

- TypeScript/Node for everything; SQLite on the relay.
- Repository and docs in English (public GitHub), despite internal notes being Russian.
- Classifier uses the receiver's own Anthropic API access (Haiku-class model).
- Queued task TTL 24h; unsure classifier verdict ⇒ hold, never allow.

- **Session identity:** a share is bound to a *name* claimed by a running plugin
  process (name + owner identity + working directory). Restart / `--resume`
  re-claims the same name; a second live process claiming an already-claimed
  name is rejected. Shares persist across restarts until unshared.
- **Key trust:** trust-on-first-use with pinning. Fingerprints are printed at
  `init` and at `share`; the receiver pins sender keys locally and refuses
  envelopes if the relay later serves a different key. Person names are assigned
  by the relay admin at invite time.
- **Held work:** a blocked tool call ends the remote task's turn; the task becomes
  `held`, the sender is told "waiting for owner". Owner runs
  `/bridge:approve <task_id>` (re-injects the task with the restriction lifted
  for that task only) or `/bridge:reject <task_id>`.
- **Concurrency:** one remote task at a time per session, injected only when the
  session is idle; others queue. While the marker is active, the hook restrictions
  apply to the whole session (owner included) — owner can `/bridge:pause`.
- **Classifier access:** prefer `claude -p --model haiku` (works on subscriptions),
  fall back to `ANTHROPIC_API_KEY`; if neither works, every task is `hold`.
- **Setup:** teammates start shared sessions with `claude --channels` (and the
  development-channels flag while the plugin is not in an official marketplace);
  documented in `AGENTS.md`/README.

## Decided by the owner: unattended mode = bypass + risk classifier

Shared sessions run without permission prompts (bypass). No allow-list. Safety
comes from an LLM risk classifier, not from enumerating allowed actions:

- **Task level:** each inbound task gets `risk` ∈ [0,1] plus a short reason
  (malicious/destructive/out-of-track). `risk < threshold` (default 0.3,
  configurable per session) ⇒ run; otherwise ⇒ held for owner. Sender sees the
  verdict reason.
- **Tool level (designer's call):** during a remote task, the PreToolUse hook
  scores risky tool calls (Bash, writes outside the project dir, network/MCP
  tools) with the same classifier, given the original task as context. This
  catches a harmless-looking task that turns harmful mid-way.
- **Backstop (designer's call):** a small deterministic deny-list (rm -rf on
  non-temp paths, force push, deploy/infra CLIs, secret files, DB drops, editing
  bridge/Claude config) is checked before the classifier and cannot be
  overridden by it. Classifier error/timeout ⇒ block (fail-closed).

## Decided by the owner: two-way conversation, not just task → result

The point is that Claudes can talk to each other: the receiving Claude can ask
the sender a clarifying question mid-task, the sender's Claude answers, and
either side can follow up. Model:

- Every task opens a **thread** (`threadId` = `taskId`). Inside a thread both
  sides exchange `message` envelopes; the thread ends with `done` (receiver,
  carries the result) or `rejected`/`held` statuses.
- Only **opening** a thread requires a share. Messages inside an existing thread
  are allowed in both directions for its two participants (relay tracks
  threads, 24h idle TTL).
- **Symmetric gating:** every inbound message is untrusted on whichever machine
  receives it. A clarifying question arriving at the sender's session goes through
  the sender's own gate and puts that session into "remote thread active" mode,
  so the hook protects the sender too (e.g. a question like "paste your .env"
  or "run X and tell me the output" is blocked like any other risky request).
- The receiving session's task stays `running` while waiting for an answer;
  answers are injected into the session as channel events tagged with the thread.

## Left to the builder

Exact wire format, library choices (libsodium vs tweetnacl), WS reconnect
strategy, CLI ergonomics, exact default deny-list contents.

## Implementation notes (v0.1)

- Owner commands (`init`, `share`, `unshare`, `list`, `approve`, `reject`, `pause`,
  `resume`, `pin --reset`, `show`, `status`, `clear`) are a standalone `bridge` CLI run in
  the owner's own terminal, not `/bridge:*` skills. This is deliberate: a skill is something
  the model can invoke, and these commands must stay out of the model's reach. The plugin
  ships one `bridge` skill that only explains the MCP tools.
- Inbound results are gated like messages and, once injected, set a sender-side marker for
  10 minutes (cleared earlier by owner approve/reject or the session's next successful
  `bridge_send`). A marker the hook has held never expires.
- Markers carry the pid of the Claude Code process (the server's parent); a marker whose
  process is gone, or that expired without being held, counts as absent. A restarted server keeps
  markers whose Claude Code is alive and re-stamps the others with its own parent (resumed
  sessions); an orphaned server (parent pid 1 or changed) injects nothing and reports it.
- Relay share changes end only threads opened into the shared session by people who lost
  access; threads the session opened to others, and their queued replies, are kept. `bridge status` / `bridge clear --session <name>` let the owner inspect
  and remove a stuck one.
