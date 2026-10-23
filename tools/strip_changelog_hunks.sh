#!/usr/bin/env bash
# strip-changelog-hunks.sh: make every listed pull request mergeable at once by taking the
# CHANGELOG.md entry out of each branch and saving it for the maintainer to write on main at merge.
#
# Keeping both sides of the conflict cannot be done once: every merge adds a bullet under
# [Unreleased], so each merge re-conflicts the rest. Dropping the bullet from each branch can:
# with no branch touching CHANGELOG.md, they merge in any order, and the saved bullets go on
# main in one commit afterwards (the rule in CONTRIBUTING step 5, as amended).
#
# Usage:  strip-changelog-hunks.sh [--dry-run] PR_NUMBER...
#   e.g.  strip-changelog-hunks.sh 608 610 537 618 619
# Needs: push access to the fork branches (GitHub's "allow edits from maintainers", on by
# default for fork pull requests) and a git identity whose email matches the DCO sign-off.
# Run from any clone of the upstream repository. Writes the saved entries to ./changelog-entries/.
set -euo pipefail

UPSTREAM="${UPSTREAM:-https://github.com/agentrust-io/trace-spec.git}"
FORK="${FORK:-https://github.com/drk-ram/trace-spec.git}"
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi
[ $# -gt 0 ] || { echo "usage: $0 [--dry-run] PR_NUMBER..." >&2; exit 2; }

mkdir -p changelog-entries
git fetch -q "$UPSTREAM" "+refs/heads/main:refs/remotes/strip/main"
main_sha="$(git rev-parse refs/remotes/strip/main)"
echo "main is ${main_sha:0:7}"

for n in "$@"; do
  head="$(git ls-remote "$UPSTREAM" "refs/pull/$n/head" | cut -f1)"
  [ -n "$head" ] || { echo "PR $n: no refs/pull/$n/head on upstream" >&2; exit 1; }
  branch="$(git ls-remote --heads "$FORK" | awk -v h="$head" '$1==h {sub("refs/heads/","",$2); print $2}' | head -1)"
  [ -n "$branch" ] || { echo "PR $n: no branch on $FORK has tip ${head:0:7}; is the fork right?" >&2; exit 1; }
  echo "== PR $n: head ${head:0:7}, fork branch $branch"

  git fetch -q "$UPSTREAM" "refs/pull/$n/head:refs/remotes/strip/pr-$n"
  git checkout -q -B "strip-pr-$n" "refs/remotes/strip/pr-$n"
  mb="$(git merge-base HEAD "$main_sha")"

  # 1. Save the entry this pull request added, for the maintainer to write on main at merge.
  git diff "$mb" HEAD -- CHANGELOG.md | grep '^+' | grep -v '^+++' | sed 's/^+//' > "changelog-entries/$n.md" || true
  if [ -s "changelog-entries/$n.md" ]; then
    echo "   saved $(wc -l < "changelog-entries/$n.md") lines of CHANGELOG.md entry to changelog-entries/$n.md"
  else
    echo "   this pull request adds nothing to CHANGELOG.md"
  fi

  # 2. Merge main; whatever the merge did to CHANGELOG.md, take main's copy, so the branch no longer touches it.
  if ! git merge -q --no-commit --no-ff "$main_sha" >/dev/null 2>&1; then :; fi
  git checkout -q "$main_sha" -- CHANGELOG.md
  git add CHANGELOG.md
  if git diff --name-only --diff-filter=U | grep -q .; then
    echo "   PR $n has conflicts outside CHANGELOG.md:"; git diff --name-only --diff-filter=U | sed 's/^/     /'
    echo "   stopping; resolve this one by hand" >&2; exit 1
  fi
  if git diff --cached --quiet && git diff --quiet "$main_sha" -- CHANGELOG.md; then
    echo "   nothing to commit"
  else
    git commit -q -s -m "Merge main into #$n; the CHANGELOG.md entry moves to main at merge

The entry this pull request proposed is written on main at merge by the merging
maintainer, as CONTRIBUTING step 5 now asks, so open pull requests stop
conflicting on the one file they would all touch."
    echo "   merge commit $(git rev-parse --short HEAD); CHANGELOG.md now equals main's: $(git diff --quiet "$main_sha" -- CHANGELOG.md && echo yes || echo NO)"
  fi

  # 3. Push to the fork branch (the pull request's head moves; approvals on the old head are dismissed).
  if [ "$DRY_RUN" = 1 ]; then
    echo "   dry run: would push strip-pr-$n to $FORK $branch"
  else
    git push -q "$FORK" "strip-pr-$n:$branch" && echo "   pushed to $FORK $branch"
  fi
done

echo
: > changelog-entries/unreleased-additions.md
for n in "$@"; do [ -s "changelog-entries/$n.md" ] && cat "changelog-entries/$n.md" >> changelog-entries/unreleased-additions.md; done
echo "Saved entries in changelog-entries/<PR>.md, and all of them in changelog-entries/unreleased-additions.md ($(grep -c . changelog-entries/unreleased-additions.md) lines) to paste under [Unreleased] on main in one commit after the merges."
