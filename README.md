# claude-bridge

claude-bridge lets Claude Code sessions on different machines work together. You share specific
sessions with named teammates. A teammate's Claude opens a thread with a task, both Claudes can
exchange clarifying messages, and the receiver replies with a result. No human has to copy and
paste between chats. Messages are end-to-end encrypted through a self-hosted relay. The receiving
side runs unattended and gates every inbound message with a risk classifier, a PreToolUse hook and
a hard deny-list; anything risky waits for the session owner.

## Requirements

- Claude Code with channels support (`--channels` / `--dangerously-load-development-channels`)
- Node 22
- A relay you host (Docker), reachable over HTTPS/WSS by every teammate

## 60-second flow

```bash
# once per machine, in a terminal (invite code comes from the relay admin)
npm ci && npm run build
npx bridge init https://relay.example.com <invite>

# bob shares a session with alice (name it, describe its track)
npx bridge share front alice --track "Frontend of the shop"

# bob starts that session from the checkout (details in AGENTS.md)
BRIDGE_SESSION=front claude --plugin-dir "$PWD/plugin" \
  --dangerously-load-development-channels plugin:bridge@inline --dangerously-skip-permissions
# alice tells her Claude: "send to bob/front: fix the pricing page header"
```

v0.1 runs from a built checkout only. Installing through a plugin marketplace is **not
supported** yet: the plugin's `dist/` and `node_modules/` are not bundled.

Alice's Claude calls `bridge_send`. Bob's Claude gets the task as a channel event, may ask
alice's Claude a clarifying question (`bridge_message`), and finishes with `bridge_reply`. The
result arrives in alice's session. See [AGENTS.md](AGENTS.md) for full setup.

## Two-way threads

Every task opens a thread. Inside it both sides exchange messages until the receiver sends the
result with `bridge_reply`. Only opening a thread needs a share; follow-ups work in both
directions. Every inbound message is untrusted on whichever machine receives it, so the
classifier and hook protect the sender's session too.

## Held work and approval

If the classifier scores a task at or above the threshold (`--threshold` per session, else `threshold` in `policy.yaml`, else 0.3), is unsure, or fails, or
if the hook blocks a tool call, the task is held and the sender is told it is waiting for the
owner. The owner decides in their own terminal:

```bash
npx bridge approve <taskId> --session front   # release it
npx bridge reject  <taskId> --session front
npx bridge pause front                        # block remote work; `bridge resume front` to lift
```

Held text is never printed into the session. The hook denies Read/Grep/Glob calls on the
held-content directory (`sessions/*/held/`, including searches rooted above it) and Bash
commands that name a path inside it; a Bash command that reaches it some other way (for example
`grep -r x ~`) is not caught by this rule. To read it, run `bridge show <taskId> --session front`
in a **separate terminal**; it refuses to run inside Claude Code or without a TTY.

Results are gated on the sender's side like messages. When a result is injected, the sender's
session runs under a sender marker for 10 minutes, so the hook checks its tool calls against
the result; the owner's `bridge approve|reject <taskId>` or the session's next successful
`bridge_send` ends it earlier. If the hook blocks a call under that marker, the marker no longer
expires: only the owner's approve/reject (or `bridge clear`) lifts it. A new message from the peer also cancels an earlier owner approval of that
task, so the classifier gates tool calls again.

`npx bridge status` shows every local session (send-only `tmp-*` ones included), its active
marker, and how many items are held or queued. A marker records the Claude Code process whose
context holds the peer text (the bridge server's parent), so it survives a crash or restart of
the bridge server. A restarted server re-stamps a marker whose Claude Code has exited with its
own parent, because `claude --resume`/`--continue` brings the same peer text back; such a marker
keeps its expiry, and a held one still waits for the owner. A mid-thread sender marker (a peer
message, not a result) has no expiry, so it is lifted only by the owner's approve/reject,
`bridge clear`, or the session's next successful `bridge_send`. A bridge server whose Claude Code is
gone (orphaned) injects nothing, logs it, and `bridge status` shows the session as orphaned.

If a marker is still stuck, `npx bridge clear --session <name>` prints and removes it (separate
terminal only, like `show`). This is the only way out for a send-only session after its bridge
server crashed: the new server claims a new `tmp-*` name, so nothing watches the old session's
approvals, yet its marker keeps gating that working directory while the Claude Code lives. Find
the name with `npx bridge status` and run `npx bridge clear --session tmp-<id>`. If the plugin is
not built, `npx bridge` does not run either: run `npm run build` in the checkout, or delete
`${BRIDGE_HOME:-~/.claude/channels/bridge}/sessions/<name>/active.json` from another terminal.

## Commands

`bridge init <relayUrl> <invite>`, `share <session> <people...> --track "<text>" [--scope <dir>]
[--threshold <0-1>]`, `unshare <session>`, `list`, `approve|reject <taskId> --session <name>`,
`show <taskId> --session <name>`, `status`, `clear --session <name>`, `pause|resume <session>`,
`pin --reset <id>`. Run them in your own terminal: `npx bridge ...` from the checkout, or put
`plugin/dist/cli.js` on your `PATH` as `bridge`.
State lives in `${BRIDGE_HOME:-~/.claude/channels/bridge}`; optional policy in `policy.yaml`
there (see `policy.example.yaml`); audit trail in `audit.log`.

## Why it's safe

1. Opt-in per session: nothing is reachable until the owner shares that exact session with named people.
2. Strong identity: every envelope is signed with the sender's Ed25519 key and keys are pinned on first use.
3. End-to-end encryption: envelopes are sealed to the receiver's X25519 key; the relay stores ciphertext only.
4. Receiver-side policy: the owner's machine decides what runs; a compromised sender or relay cannot loosen it.
5. Pre-classification: deterministic rules plus an LLM risk classifier; unsure, error or timeout means hold.
6. Runtime enforcement: the PreToolUse hook blocks violating tool calls during remote threads.
7. No remote permission approval: permission prompts stay local; the plugin does not relay them.
8. Privacy by construction: the sender gets only what Claude passes to `bridge_reply`/`bridge_message`, never the transcript.
9. Audit log: inbound messages, verdicts, blocked calls and replies are appended locally to `audit.log`.
10. Limits: the relay caps ciphertext at 64 KiB and 30 sends per minute per identity; queued messages expire after 24 hours.

### Limits

- Residual risk: a remote task's text stays in the receiving session's context after it ends and
  could influence later turns; tool-level enforcement applies only while a remote thread is active.
- The deny-list is best-effort text matching. For Bash it catches a few command patterns
  (recursive `rm` outside temp dirs, force pushes or pushes to main, `git reset --hard` on a
  remote ref, deploy tooling, destructive SQL, the `bridge` CLI) and paths it can read from the
  command line (sensitive files such as `~/.ssh` or `~/.aws`, `~/.claude` and Claude settings,
  bridge state). It does not confine Bash to the session's scope and cannot see through
  variables, scripts or indirection; everything else in a Bash command is judged by the
  classifier, which is the main line of defence for Bash. After the owner approves a task, only
  these rules apply to its tool calls (until the peer's next message).
- The classifier is an LLM and can be wrong in both directions.
- Shared sessions run without permission prompts by design. Share dedicated per-track sessions,
  not the session you use for everything else.
- Run `bridge show` only in a separate terminal.
- The relay sees metadata (who talks to whom, when, message sizes), not content.
- The relay has only basic abuse limits; see [SECURITY.md](SECURITY.md) before exposing one publicly.

See [SECURITY.md](SECURITY.md) for the threat model and how to report issues.

## License

MIT, see [LICENSE](LICENSE).
