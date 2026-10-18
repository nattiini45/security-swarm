#!/usr/bin/env sh
# Make the self-test fixture a git repo with one commit.
# The scanner snapshots COMMITTED HEAD via `git archive`, so the fixture must have a commit
# before you can plan a scan against it.
set -e
cd "$(dirname "$0")/teamboard"
if [ ! -d .git ]; then
  git init -q
fi
git add -A
git -c user.email=swarm@example.com -c user.name="Security Swarm" \
    commit -qm "self-test fixture" >/dev/null 2>&1 || true
echo "fixture ready at $(pwd) @ $(git rev-parse --short HEAD)"
