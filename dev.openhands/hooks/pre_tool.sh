#!/bin/sh
# =============================================================================
# security-baseline PreToolUse gate.
#
# Reads the hook envelope on stdin, extracts the payload text with sed only (no
# jq, no python: this runs on every tool call and must stay dependency-free),
# then routes it through the rule files by severity:
#
#   deny_*   -> exit 2 (blocked, reason on stdout)
#   warn_*   -> exit 0 + additionalContext
#   log_*    -> exit 0, event only
#   allow_*  -> exit 0, allow wins over warn (but is surfaced)
#
# FAIL-CLOSED: if the ruleset itself cannot be read, this exits 2. A guardrail
# that silently degrades to "allow everything" is worse than no guardrail.
# =============================================================================
set -u

PLUGIN_ROOT=${PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
PLUGIN_DATA=${PLUGIN_DATA:-}
RULES_LOCAL="$PLUGIN_ROOT/dev.openhands/hooks/rules"

# Authority order: the user's active ruleset wins over the shipped one.
if [ -n "$PLUGIN_DATA" ] && [ -d "$PLUGIN_DATA/rules" ]; then
    RULES="$PLUGIN_DATA/rules"
else
    RULES="$RULES_LOCAL"
fi

if [ ! -d "$RULES" ]; then
    printf '%s\n' '{"decision":"deny","reason":"security-baseline: ruleset directory missing - refusing to run unguarded"}'
    exit 2
fi

# stdin can only be read once: buffer it, then parse the copy. Reading it twice
# silently produced an empty PAYLOAD, which made every command look harmless.
STDIN_PAYLOAD=$(cat)

PAYLOAD=$(printf '%s' "$STDIN_PAYLOAD" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' 2>/dev/null || true)
TOOL_NAME=$(printf '%s' "$STDIN_PAYLOAD" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' 2>/dev/null || true)
[ -n "$TOOL_NAME" ] || TOOL_NAME=${OPENHANDS_TOOL_NAME:-unknown}

EVENT=${OPENHANDS_EVENT_TYPE:-PreToolUse}
SESSION=${OPENHANDS_SESSION_ID:-unknown}
PROJECT=${OPENHANDS_PROJECT_DIR:-}

# Escape a value for embedding inside a JSON string literal.
# Rule patterns contain backslashes (\. \* \/), and JSON rejects most of those
# escape sequences, so pattern text must be escaped rather than interpolated raw.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r' | sed -e 's/	/\\t/g'
}

# --- logging (redacted, rotated elsewhere; best-effort) ----------------------
log_event() {
    [ -n "$PLUGIN_DATA" ] || return 0
    _dir="$PLUGIN_DATA/logs"
    _file="$_dir/events.jsonl"
    [ -d "$_dir" ] || mkdir -p "$_dir" 2>/dev/null || return 0
    printf '{"ts":"%s","event":"%s","tool":"%s","severity":"%s","rule":"%s","session":"%s"}\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$EVENT" "$TOOL_NAME" "$1" "$2" "$SESSION" \
        >> "$_file" 2>/dev/null || true
}

# --- rule matching -----------------------------------------------------------
# match FILE -> 0 when PAYLOAD matches any non-comment ERE line in FILE.
match() {
    [ -f "$1" ] || return 1
    _line=''
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            ''|\#*) continue ;;
        esac
        if printf '%s' "$PAYLOAD" | grep -qE -- "$_line" 2>/dev/null; then
            printf '%s' "$_line"
            return 0
        fi
    done < "$1"
    return 1
}

# 1. deny: hard block. This is the only path that exits 2, and it is checked
#    BEFORE allow_silent on purpose: `git push --force origin main` matches the
#    git silent rule and the force-push deny rule, and deny must win. A quiet
#    convenience list must never be able to mask a destructive command.
if hit=$(match "$RULES/deny_paths.txt"); then
    log_event deny "$hit"
    printf '%s\n' "{\"decision\":\"deny\",\"reason\":\"security-baseline: path rule '$(json_escape "$hit")' blocked this operation\"}"
    exit 2
fi
if hit=$(match "$RULES/deny_commands.txt"); then
    log_event deny "$hit"
    printf '%s\n' "{\"decision\":\"deny\",\"reason\":\"security-baseline: command rule '$(json_escape "$hit")' blocked this operation\"}"
    exit 2
fi

# 2. allow_silent: never warned, never logged (git and routine dev operations).
if hit=$(match "$RULES/allow_silent.txt"); then
    exit 0
fi

# 3. allow: explicit user bypass. Allow wins over warn, but is still surfaced.
if hit=$(match "$RULES/allow.txt"); then
    log_event allow "$hit"
    printf '%s\n' "{\"additionalContext\":\"security-baseline: allowed by explicit bypass rule '$(json_escape "$hit")'\"}"
    exit 0
fi

# 4. warn: proceed, but tell the agent.
if hit=$(match "$RULES/warn_paths.txt") || hit=$(match "$RULES/warn_commands.txt"); then
    log_event warn "$hit"
    printf '%s\n' "{\"additionalContext\":\"security-baseline: '$(json_escape "$hit")' matched a warn rule - proceeding\"}"
    exit 0
fi

# 5. log: event only.
if hit=$(match "$RULES/log_paths.txt") || hit=$(match "$RULES/log_commands.txt"); then
    log_event log "$hit"
    exit 0
fi

# Nothing matched. Unknown tools are logged so a tool rename surfaces as a trail
# entry instead of silent non-coverage.
log_event unknown_tool '-'
exit 0
