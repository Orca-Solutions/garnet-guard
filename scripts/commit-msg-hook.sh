#!/bin/sh
# Strips AI attribution lines from commit messages. Install per repo:
#   cp scripts/commit-msg-hook.sh .git/hooks/commit-msg && chmod +x .git/hooks/commit-msg
f="$1"
awk '{
    line = tolower($0)
    if (line ~ /^[[:space:]]*(co-authored-by:|claude-session:|codex-session:)/) next
    if (line ~ /^[[:space:]]*(🤖[[:space:]]*)?generated[ -](with|by):?[[:space:]]+\[?(claude|codex|anthropic|openai)([[:space:][:punct:]]|$)/) next
    print
}' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
