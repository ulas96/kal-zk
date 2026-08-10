#!/usr/bin/env bash
set -euo pipefail

# Hold the system awake for the whole run, on any machine that can.
#
# This is not a convenience. Go measures test duration on the monotonic clock, which does not
# advance while macOS is asleep; PostgreSQL's now() is wall clock, which does. A laptop that sleeps
# mid-suite therefore resumes with every live auth_zk_challenges row expired — its 60-second TTL was
# issued before a sleep that lasted fifteen minutes — while Go still believes the test took two
# seconds. What that looks like is a handful of unrelated DB tests failing with
# `INVALID_PROOF: ... pg: no rows in result set`, a different handful each run, none of them
# reproducible, and no data race. It cost a day to identify once. `-timeout` does not save you
# either: the testing package's watchdog is monotonic too, so a 45-minute limit does not fire on a
# run that occupied two and a half hours of wall clock.
#
# caffeinate is macOS-only and absent on the Linux runners, where the problem does not exist; the
# command -v guard makes this a no-op there. Set KAL_ZK_NO_CAFFEINATE=1 to opt out.
# Re-exec through "${BASH}", not through "$0": the Makefile invokes this as `bash scripts/...`, so
# the file carries no execute bit and `exec caffeinate -i "$0"` dies with "Permission denied".
# "${BASH}" is also what preserves the interpreter the shebang already resolved.
if [[ -z "${KAL_ZK_NO_CAFFEINATE:-}" ]] && command -v caffeinate >/dev/null 2>&1; then
  export KAL_ZK_NO_CAFFEINATE=1
  exec caffeinate -i "${BASH:-bash}" "$0" "$@"
fi

# macOS still ships bash 3.2 as /bin/bash, and `make test-db` runs whatever `bash` resolves to.
# Two things here would otherwise die there with a message that names neither bash nor a version:
# `mapfile` does not exist at all, and under `set -u` an empty array expands to "unbound variable"
# rather than to nothing. Hence the read loop below and the `${a[@]+"${a[@]}"}` guards on the only
# two arrays that are legitimately empty — the no-tags run, which is the common one.
tags="${1:-}"
list_args=()
test_args=()
if [[ -n "$tags" ]]; then
  list_args+=("-tags=$tags")
  test_args+=("-tags=$tags")
fi

expected=()
while IFS= read -r line; do
  expected+=("$line")
done < <(go test ${list_args[@]+"${list_args[@]}"} -list '^TestDBZK' ./tests | grep '^TestDBZK' | sort)
if [[ ${#expected[@]} -eq 0 ]]; then
  echo "no TestDBZK* tests discovered" >&2
  exit 1
fi

result_file="$(mktemp "${TMPDIR:-/tmp}/kal-zk-db-tests.XXXXXX.json")"
trap 'rm -f "$result_file"' EXIT
go test ${test_args[@]+"${test_args[@]}"} -json -race -count=1 -timeout 45m ./tests | tee "$result_file"

for test_name in "${expected[@]}"; do
  pass_count=$(jq -r --arg test "$test_name" 'select(.Test == $test and .Action == "pass") | .Test' "$result_file" | wc -l | tr -d ' ')
  skip_count=$(jq -r --arg test "$test_name" 'select(.Test == $test and .Action == "skip") | .Test' "$result_file" | wc -l | tr -d ' ')
  if [[ "$pass_count" != "1" || "$skip_count" != "0" ]]; then
    echo "$test_name: pass_count=$pass_count skip_count=$skip_count" >&2
    exit 1
  fi
done

observed=$(jq -r 'select(.Action == "pass" and (.Test // "" | startswith("TestDBZK")) and (.Test | contains("/") | not)) | .Test' "$result_file" | sort -u)
if ! diff -u <(printf '%s\n' "${expected[@]}") <(printf '%s\n' "$observed"); then
  echo "discovered and passed top-level DB test sets differ" >&2
  exit 1
fi

echo "all ${#expected[@]} discovered TestDBZK* tests passed exactly once with no skips"
