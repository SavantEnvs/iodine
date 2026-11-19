#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's libcheck unit suites (tests/*.c), built by mayhem/build.sh into mayhem/build-test.
# Each suite binary prints "<pct>%: Checks: <n>, Failures: <f>, Errors: <e>"; a suite that is
# missing, crashes or prints no summary counts as one failed test.
SUITES=(base32 base64 base64u base128 common compat dns encoding fw_query login process random read ui user)
# Some tests resolve address literals through get_addr(), which passes AI_ADDRCONFIG to
# getaddrinfo(): a host without a configured non-loopback address of that family (docker build,
# --network none, the grader) refuses them. Probe getaddrinfo the same way and, only for a form
# the host refuses, count that test's assertion failure (F:, not a crash) as skipped.
probe() {  # probe <family 4|6> <literal> -> exit 0 if getaddrinfo(AI_ADDRCONFIG) resolves it
  python3 -I -c 'import socket,sys
f = socket.AF_INET if sys.argv[1] == "4" else socket.AF_INET6
socket.getaddrinfo(sys.argv[2], 53, f, socket.SOCK_DGRAM, socket.IPPROTO_UDP, socket.AI_ADDRCONFIG)' "$@" 2>/dev/null
}
env_tests=()
probe 4 1.2.3.4 || env_tests+=(test_parse_format_ipv4 test_parse_format_ipv4_listen_all)
probe 6 2001:db8::1 || env_tests+=(test_parse_format_ipv6 test_check_user_and_ip)
probe 6 ::ffff:1.2.3.4 || env_tests+=(test_parse_format_ipv4_mapped_ipv6)
ENV_TESTS=$(IFS='|'; echo "${env_tests[*]:-}")
[ -n "$ENV_TESTS" ] && echo "host refuses some address literals; may skip: $ENV_TESTS"
passed=0 failed=0 skipped=0
for s in "${SUITES[@]}"; do
  bin="$SRC/mayhem/build-test/tests/test_$s"
  if [ ! -x "$bin" ]; then
    echo "FAIL $s: $bin missing (build.sh should have built it)"; failed=$((failed + 1)); continue
  fi
  out=$(cd "$SRC/mayhem/build-test" && "$bin" 2>&1); rc=$?
  line=$(printf '%s\n' "$out" | grep -E '^[0-9]+%: Checks: [0-9]+, Failures: [0-9]+, Errors: [0-9]+' | tail -1)
  if [ -z "$line" ]; then
    printf '%s\n' "$out" | tail -20
    echo "FAIL $s: no check summary (exit $rc)"; failed=$((failed + 1)); continue
  fi
  n=$(sed -E 's/.*Checks: ([0-9]+).*/\1/' <<<"$line")
  f=$(sed -E 's/.*Failures: ([0-9]+).*/\1/' <<<"$line")
  e=$(sed -E 's/.*Errors: ([0-9]+).*/\1/' <<<"$line")
  sk=0
  if [ -n "$ENV_TESTS" ]; then
    sk=$(printf '%s\n' "$out" | grep -cE ":F:[A-Za-z_]+:($ENV_TESTS):[0-9]+: Assertion '[^']*get_addr\(") || true
    f=$((f - sk))
  fi
  bad=$((f + e))
  if [ "$n" -eq 0 ]; then bad=1; n=1; fi
  if [ "$rc" -ne 0 ] && [ "$bad" -eq 0 ] && [ "$sk" -eq 0 ]; then bad=1; fi
  [ "$bad" -gt 0 ] && printf '%s\n' "$out" | grep -E 'F:|E:' | head -20
  echo "$s: $line (exit $rc)"
  [ "$sk" -gt 0 ] && echo "  ($sk address-literal test(s) skipped: refused by this host)"
  passed=$((passed + n - bad - sk)); failed=$((failed + bad)); skipped=$((skipped + sk))
done
emit_ctrf "libcheck" "$passed" "$failed" "$skipped"
