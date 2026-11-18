#!/bin/sh
# =============================================================================
# security-baseline PostToolUse detector.
#
# Hooks cannot modify tool output, so this does not redact. It DETECTS credentials
# in what came back, writes a redacted event, and tells the agent via
# additionalContext so the agent can stop and rotate. Prevention happens in
# pre_tool.sh; this is the after-the-fact net.
#
# Always exits 0: PostToolUse cannot block, and a detector that errors must never
# break the session.
# =============================================================================
set -u

PLUGIN_ROOT=${PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
PLUGIN_DATA=${PLUGIN_DATA:-}
RULES_LOCAL="$PLUGIN_ROOT/dev.openhands/hooks/rules"

if [ -n "$PLUGIN_DATA" ] && [ -d "$PLUGIN_DATA/rules" ]; then
    RULES="$PLUGIN_DATA/rules"
else
    RULES="$RULES_LOCAL"
fi

# stdin can only be read once: buffer it, then parse the copy.
STDIN_PAYLOAD=$(cat)

TOOL_NAME=$(printf '%s' "$STDIN_PAYLOAD" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' 2>/dev/null || true)
[ -n "$TOOL_NAME" ] || TOOL_NAME=${OPENHANDS_TOOL_NAME:-unknown}
SESSION=${OPENHANDS_SESSION_ID:-unknown}

DETECTED=''
if [ -f "$RULES/detect_secrets.txt" ]; then
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            ''|\#*) continue ;;
        esac
        if printf '%s' "$STDIN_PAYLOAD" | grep -qE -- "$_line" 2>/dev/null; then
            DETECTED="$_line"
            break
        fi
    done < "$RULES/detect_secrets.txt"
fi

# Log the event WITHOUT the matched value - the whole point is not to persist it.
if [ -n "$PLUGIN_DATA" ] && [ -n "$DETECTED" ]; then
    _dir="$PLUGIN_DATA/logs"
    mkdir -p "$_dir" 2>/dev/null || true
    printf '{"ts":"%s","event":"PostToolUse","tool":"%s","severity":"detect","rule":"redacted","session":"%s"}\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$TOOL_NAME" "$SESSION" \
        >> "$_dir/events.jsonl" 2>/dev/null || true
fi

if [ -n "$DETECTED" ]; then
    printf '%s\n' '{"additionalContext":"security-baseline: tool output contained something matching a credential signature. Treat it as exposed: rotate the credential before continuing, and do not repeat the value."}'
fi

exit 0
