#!/usr/bin/env bash
set -euo pipefail

BASE_BRANCH="main"
SYNC_BRANCH="automation/deploy-repo-sync"
REPO="nwarila-platform/talos-cluster"
BOT_NAME="nwarila-repo-sync[bot]"
BOT_EMAIL="294612239+nwarila-repo-sync[bot]@users.noreply.github.com"
BOT_IDENTITY="${BOT_NAME} <${BOT_EMAIL}>"
COMMIT_SUBJECT="chore(deploy-repos): sync deploy repository wiring"
COMMIT_BODY="Regenerate tenant-scoped Flux wiring for deploy-* repositories that expose kubernetes/overlays/talos-cluster/kustomization.yaml."
PR_TITLE="chore(deploy-repos): sync deploy repository wiring"
PUSH_URL="https://github.com/${REPO}.git"

ADD_PATHS=(
  ".gitignore"
  "clusters/talos-cluster/apps"
  "clusters/talos-cluster/tenants"
)

PR_BODY=$(cat <<'PR_BODY_EOF'
## Summary

Regenerates tenant-scoped Flux wiring for deploy repositories matching
the `deploy-*` contract. Opened by the cluster's dedicated
`nwarila-repo-sync[bot]` identity from an on-cluster SOPS-mounted key.

## Contract

- repository is under `nwarila-platform`
- repository name matches `deploy-*`
- repository exposes `kubernetes/overlays/talos-cluster/kustomization.yaml`

After merge, Flux reconciles the generated GitRepository and
Kustomization resources. Future workload/image changes happen in each
`deploy-*` repository.
PR_BODY_EOF
)

askpass_dir=""

cleanup() {
  if [ -n "$askpass_dir" ]; then
    rm -rf "$askpass_dir"
  fi
}

trap cleanup EXIT

install_askpass() {
  : "${GH_TOKEN:?GH_TOKEN must be set}"
  : "${RUNNER_TEMP:?RUNNER_TEMP must be set}"

  askpass_dir=$(mktemp -d "${RUNNER_TEMP%/}/git-askpass.XXXXXX")
  chmod 700 "$askpass_dir"

  local askpass_file="${askpass_dir}/askpass.sh"
  cat >"$askpass_file" <<'ASKPASS_EOF'
#!/usr/bin/env sh
case "$1" in
  *Username*) printf '%s\n' "x-access-token" ;;
  *Password*) printf '%s\n' "$GH_TOKEN" ;;
  *) printf '%s\n' "$GH_TOKEN" ;;
esac
ASKPASS_EOF
  chmod 700 "$askpass_file"

  export GIT_ASKPASS="$askpass_file"
  export GIT_TERMINAL_PROMPT=0
}

open_pr_number() {
  gh pr list \
    --repo "$REPO" \
    --state open \
    --base "$BASE_BRANCH" \
    --head "$SYNC_BRANCH" \
    --json number \
    --jq '.[0].number // empty'
}

delete_remote_branch_if_present() {
  install_askpass

  local ls_remote_status=0
  git ls-remote --exit-code --heads "$PUSH_URL" "$SYNC_BRANCH" >/dev/null || ls_remote_status=$?

  if [ "$ls_remote_status" -eq 0 ]; then
    git push "$PUSH_URL" ":refs/heads/${SYNC_BRANCH}"
  elif [ "$ls_remote_status" -eq 2 ]; then
    echo "No stale remote branch found for ${SYNC_BRANCH}."
  else
    return "$ls_remote_status"
  fi
}

git checkout -B "$SYNC_BRANCH"
git reset --quiet
git add -- "${ADD_PATHS[@]}"

if git diff --cached --quiet --exit-code; then
  pr_number=$(open_pr_number)
  if [ -n "$pr_number" ]; then
    gh pr close "$pr_number" --repo "$REPO" --delete-branch
  else
    delete_remote_branch_if_present
  fi
  exit 0
fi

GIT_COMMITTER_NAME="$BOT_NAME" \
GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
  git -c commit.gpgsign=false commit \
    --author="$BOT_IDENTITY" \
    -m "$COMMIT_SUBJECT" \
    -m "$COMMIT_BODY"

install_askpass
git push --force "$PUSH_URL" "HEAD:refs/heads/${SYNC_BRANCH}"

pr_number=$(open_pr_number)
if [ -n "$pr_number" ]; then
  gh pr edit "$pr_number" --repo "$REPO" --title "$PR_TITLE" --body "$PR_BODY"
else
  gh pr create \
    --repo "$REPO" \
    --base "$BASE_BRANCH" \
    --head "$SYNC_BRANCH" \
    --title "$PR_TITLE" \
    --body "$PR_BODY"
fi
