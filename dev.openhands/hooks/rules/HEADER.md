# Rule files

Plain-text extended regular expressions, one per line. `#` starts a comment; a
blank line is ignored. `pre_tool.sh` matches each line against the extracted
command or path text, so keep expressions anchored where a partial match would be
too broad.

| File | Severity | Effect |
|---|---|---|
| `allow_silent.txt` | silent | never warned, never logged |
| `deny_commands.txt` | deny | exit 2, operation blocked |
| `deny_paths.txt` | deny | exit 2, operation blocked |
| `allow.txt` | allow | exit 0, bypasses warn, surfaced to the agent |
| `warn_commands.txt` | warn | exit 0 plus `additionalContext` |
| `warn_paths.txt` | warn | exit 0 plus `additionalContext` |
| `log_commands.txt` | log | exit 0, event entry only |
| `log_paths.txt` | log | exit 0, event entry only |
| `detect_secrets.txt` | detect | `PostToolUse` only, warning, never blocks |

**Precedence**, first match wins: `allow_silent` → `deny` → `allow` → `warn` →
`log` → unmatched (logged as `unknown_tool`).

Every `deny` line is a command or path with no legitimate use inside an agent
session. Anything debatable belongs in `warn_commands.txt`: a false positive on a
deny rule stops real work, which is how users learn to bypass guardrails.

`detect_secrets.txt` exists because hooks cannot modify tool output. Prevention
happens in `pre_tool.sh`; this file is the after-the-fact net, and it never
persists the matched value.
