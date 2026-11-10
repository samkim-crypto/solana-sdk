#!/usr/bin/env bash
#
# Replays the solfuzz-agave test vectors with a crate taken from a pull request
# and from the commit the pull request branched from, and fails if the result
# of any fixture differs.

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

usage() {
  cat <<EOF >&2
USAGE:
    $0 <PR_NUMBER> <CRATE_PATH>

ARGS:
    <PR_NUMBER>     Pull request number in anza-xyz/solana-sdk
    <CRATE_PATH>    Relative path to the crate to test, ie. "address"

ENV:
    SOLFUZZ_AGAVE_BRANCH    Branch of solfuzz-agave to use. By default, its default branch.
EOF
}

pr="$1"
crate_dir="$2"
if [ -z "$pr" ] || [ -z "$crate_dir" ]; then
  usage
  exit 1
fi

if [ "$(uname -sm)" != "Linux x86_64" ]; then
  echo "solfuzz-agave only supports x86_64 Linux" >&2
  exit 1
fi

work_dir="$src_root/target/solfuzz-agave"
solfuzz="$work_dir/solfuzz-agave"
sdk="$work_dir/solana-sdk"
vectors="$work_dir/test-vectors"
results="$work_dir/results"
package="solana-$crate_dir"

rm -rf "$work_dir"
mkdir -p "$results"

git clone -q --depth 1 ${SOLFUZZ_AGAVE_BRANCH:+--branch "$SOLFUZZ_AGAVE_BRANCH"} \
  https://github.com/firedancer-io/solfuzz-agave.git "$solfuzz"
branch="$(git -C "$solfuzz" rev-parse --abbrev-ref HEAD)"
echo "Using solfuzz-agave branch $branch"

git clone -q https://github.com/anza-xyz/solana-sdk.git "$sdk"
git -C "$sdk" fetch -q origin "pull/$pr/head"
head_sha="$(git -C "$sdk" rev-parse FETCH_HEAD)"
base_sha="$(git -C "$sdk" merge-base origin/master "$head_sha")"

vectors_sha="$(cat "$solfuzz/scripts/test-vectors-commit-sha.txt")"
git init -q "$vectors"
git -C "$vectors" fetch -q --depth 1 https://github.com/firedancer-io/test-vectors.git "$vectors_sha"
git -C "$vectors" checkout -q FETCH_HEAD

# The crate's dependencies in this repo have to be patched along with it.
# Otherwise cargo builds them as second copies whose types don't match the
# crates.io ones that the rest of Agave uses.
crates_to_patch() {
  cargo metadata --manifest-path "$sdk/Cargo.toml" --format-version 1 --no-deps | python3 -c '
import json
import os
import sys

metadata = json.load(sys.stdin)
root = metadata["workspace_root"]
packages = {package["name"]: package for package in metadata["packages"]}
todo = [sys.argv[1]]
seen = set()
while todo:
    name = todo.pop()
    if name not in seen:
        seen.add(name)
        todo += [
            dependency["name"]
            for dependency in packages[name]["dependencies"]
            if dependency.get("path") and dependency["kind"] != "dev"
        ]
for name in sorted(seen):
    print(os.path.relpath(os.path.dirname(packages[name]["manifest_path"]), root))
' "$package"
}

run_vectors() {
  declare name="$1"
  declare sha="$2"

  echo "Building solfuzz-agave with $package at $name ($sha)"
  git -C "$sdk" checkout -q "$sha"
  git -C "$solfuzz" checkout -q -- .
  (
    # Selects the toolchain from solfuzz-agave's rust-toolchain.toml.
    cd "$solfuzz"
    # run_test_vectors.sh expects the binaries in ./target.
    unset CARGO_TARGET_DIR

    crate_dirs="$(crates_to_patch)"
    for dir in $crate_dirs; do
      "$sdk/scripts/patch-crates-no-header.sh" "$solfuzz" "$sdk" "$dir" >> "$results/$name.patch.log" 2>&1
    done

    # Cargo ignores a patch whose version doesn't satisfy what Agave requires,
    # which would silently test the crates.io crate instead.
    cargo metadata --format-version 1 > /dev/null
    if grep -A1 '^\[\[patch.unused\]\]$' Cargo.lock | grep "^name = \"$package\"$" > /dev/null; then
      echo "$package at $name is not compatible with the version $branch uses" >&2
      exit 1
    fi

    cargo build --release --bins

    # A failing fixture shows up in the results below, so don't stop here.
    LOG_PATH="$results/$name.logs" WORK_DIR="$vectors" ./scripts/run_test_vectors.sh || true

    # The runner's own .passed and .failures files are written by parallel
    # workers and can be garbled. The per-chunk logs are not.
    grep -rhoE '(OK|FAIL): .*' "$results/$name.logs/per_fixture" | sed 's/"//g' | sort > "$results/$name"
  )
  echo "$name: $(grep -c '^OK: ' "$results/$name") OK, $(grep -c '^FAIL: ' "$results/$name") FAIL"
}

run_vectors base "$base_sha"
run_vectors pr "$head_sha"

if diff -u "$results/base" "$results/pr" > "$results/diff"; then
  echo "All fixture results match between $base_sha and $head_sha"
else
  echo "Fixture results differ, see $results/diff" >&2
  exit 1
fi
