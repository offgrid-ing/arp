#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: ./release.sh <version>  (e.g. 0.3.0)}"

# Validate semver (loose)
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'; then
  echo "Error: version must be semver (e.g. 0.3.0)" >&2
  exit 1
fi

echo "Bumping to v$VERSION"

# 1. Cargo workspace version (single source of truth)
sed -i.bak -E "s/^(version = \").*(\")/\1$VERSION\2/" Cargo.toml
rm -f Cargo.toml.bak

# 2. SKILL.md frontmatter version
if [ -f SKILL.md ]; then
  sed -i.bak -E "s/^(version: ).*/\1$VERSION/" SKILL.md
  rm -f SKILL.md.bak
fi

# 3. Update Cargo.lock
cargo check --quiet 2>/dev/null || cargo check

echo ""
echo "Updated:"
echo "  Cargo.toml          → $VERSION"
echo "  SKILL.md            → $VERSION"
echo "  Cargo.lock          → synced"
echo ""

git add -A
git commit -S -m "ARP v$VERSION"
git tag -s "v$VERSION" -m "ARP v$VERSION"
git push && git push --tags

echo ""
echo "✔ v$VERSION released and pushed."
