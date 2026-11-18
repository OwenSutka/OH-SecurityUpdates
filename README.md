# security-baseline

A hardened-by-default guard that runs on every tool call: it blocks destructive
and exfiltrating commands, blocks writes outside the workspace, blocks reads of
credential stores, warns on judgement calls, and logs everything else to a
redacted trail you can inspect.

Rules are plain-text ERE files that ship with the version. You can add your own
in `PLUGIN_DATA` without touching installed code, and you can pull a newer ruleset
with one explicit, verified, diff-reviewed command.

Repo `OH-SecurityUpdates` maps to plugin name **`security-baseline`**. The name
differs because renaming the public repo would churn URLs.

## What this can and cannot do

The original design promised that a `PostToolUse` hook would scan tool output and
redact secrets before they were persisted. **Hooks cannot modify tool output.**
They can block before execution (`PreToolUse`, exit 2) and emit
`additionalContext` after. So this plugin:

- **prevents** (`cat .env`, `printenv`, `echo $TOKEN`, credential-store reads)
- **detects and logs** after the fact, redacted, and tells the agent to rotate

It never claims to have scrubbed a value from a response. Anything else would be a
lie in a security tool.

There is no `Stop` hook on purpose: a security hook that can block the agent from
finishing is a deadlock generator. Isolation belongs at `PreToolUse`.

## Status

**Not installable yet.** Scaffolded and functional: the hooks run, the rule
routing works, and the behaviour suite passes. The updater (`update.sh`,
`revert.sh`, `allow.sh`), `status.sh`, and the full 200-command false-positive
corpus land in Wave 7.

## Layout

```
plugin.json                              manifest (Agent Plugins 1.0.0)
dev.openhands/hooks/hooks.json           PreToolUse + PostToolUse registration
dev.openhands/hooks/pre_tool.sh          blocking gate, fail-closed
dev.openhands/hooks/post_tool.sh         detector, never blocks
dev.openhands/hooks/rules/               the ruleset (ERE, plain text)
  HEADER.md                              what each file means
  VERSION                                ruleset version
  manifest.sha256                        integrity of every rule file
  allow_silent.txt  allow.txt
  deny_commands.txt  deny_paths.txt
  warn_commands.txt  warn_paths.txt
  log_commands.txt   log_paths.txt
  detect_secrets.txt
tests/unit/test_hooks.py                 behaviour suite, runs the real hooks
```

No `mcp.json`: this plugin ships hooks only.

## Precedence

`deny` → `allow_silent` → `allow` → `warn` → `log` → unmatched (logged as
`unknown_tool`).

Deny is checked **before** the silent list on purpose. `git push --force origin
main` matches both the git silent rule and the force-push deny rule, and deny must
win: a convenience list for quieting routine commands must never be able to mask a
destructive one.

## Trust model and limits

- An attacker who can edit `allow.txt` already owns the session. The ruleset is
  not a sandbox; it is a guardrail against the agent's own mistakes and against
  prompt-injected instructions.
- `detect_secrets.txt` is a detection net, not a redaction guarantee.
- Ruleset updates verify a SHA-256 and show a diff before applying.
- Windows-native hooks are untested in v1.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check .
```

## Licence

MIT.
