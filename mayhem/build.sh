#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# meson.build runs `git rev-parse` at configure time; a rebuild under another uid than the tree's
# owner must not trip git's safe.directory check (env-only config, no file written).
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'

MESON_OPTS=(-Dselinux=disabled -Dsystemd=disabled -Dlibcapng=disabled)

# meson_setup <builddir> <args...>: configure, or reconfigure an existing tree (re-runnable build).
meson_setup() {
  local dir="$1"; shift
  if [ -f "$dir/meson-private/coredata.dat" ]; then
    meson setup --reconfigure "$dir" "$@"
  else
    meson setup "$dir" "$@"
  fi
}

# 1) The project itself, sanitized + SanCov-instrumented (libcommon.a / libserver.a).
#    -fsanitize=fuzzer-no-link gives the library coverage edges even when SANITIZER_FLAGS is empty.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
meson_setup mayhem/build-fuzz "${MESON_OPTS[@]}" -Dbuildtype=plain -Db_lundef=false \
  -Dc_args="$FUZZ_CFLAGS" -Dc_link_args="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
ninja -C mayhem/build-fuzz -j"$MAYHEM_JOBS" libcommon.a libserver.a

INC=(-D_GNU_SOURCE -std=gnu99 -Imayhem/build-fuzz -Isrc -I.)
LIBS=(mayhem/build-fuzz/libserver.a mayhem/build-fuzz/libcommon.a -lz)
mkdir -p mayhem/obj
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o mayhem/obj/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/obj/standalone_main.o

# 2) libFuzzer harnesses: fuzzer binary + run-once standalone reproducer each.
for t in dns_answer dns_query encoding server; do
  $CC $FUZZ_CFLAGS "${INC[@]}" -c "mayhem/fuzz_$t.c" -o "mayhem/obj/fuzz_$t.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "mayhem/obj/fuzz_$t.o" \
    mayhem/obj/lsan_off.o "${LIBS[@]}" -o "/mayhem/fuzz_$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link mayhem/obj/standalone_main.o \
    "mayhem/obj/fuzz_$t.o" mayhem/obj/lsan_off.o "${LIBS[@]}" -o "/mayhem/fuzz_$t-standalone"
done

# 2b) The client target is a file-input AFL target (the client exit()s on hostile replies), so
#     the project is built a second time with afl-clang-fast. client.c is in no upstream library
#     (meson links it straight into the iodine binary next to iodine.c, which holds main).
AFL_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
CC=afl-clang-fast meson_setup mayhem/build-afl "${MESON_OPTS[@]}" -Dbuildtype=plain -Db_lundef=false \
  -Dc_args="$AFL_CFLAGS" -Dc_link_args="$SANITIZER_FLAGS"
ninja -C mayhem/build-afl -j"$MAYHEM_JOBS" libcommon.a
AINC=(-D_GNU_SOURCE -std=gnu99 -Imayhem/build-afl -Isrc -I.)
afl-clang-fast $AFL_CFLAGS "${AINC[@]}" -c src/client.c -o mayhem/obj/afl_client.o
afl-clang-fast $AFL_CFLAGS "${AINC[@]}" -c mayhem/fuzz_client.c -o mayhem/obj/afl_fuzz_client.o
afl-clang-fast $AFL_CFLAGS mayhem/obj/afl_fuzz_client.o mayhem/obj/afl_client.o \
  mayhem/obj/lsan_off.o mayhem/build-afl/libcommon.a -lz -o /mayhem/fuzz_client

# 3) Upstream's libcheck unit suites, with the project's normal (release) flags.
SUITES=(base32 base64 base64u base128 common compat dns encoding fw_query login process random read ui user)
( unset CFLAGS LDFLAGS
  meson_setup mayhem/build-test "${MESON_OPTS[@]}" \
    ${COVERAGE_FLAGS:+-Dc_args="$COVERAGE_FLAGS" -Dc_link_args="$COVERAGE_FLAGS"}
  ninja -C mayhem/build-test -j"$MAYHEM_JOBS" $(printf 'tests/test_%s ' "${SUITES[@]}") )
echo "build.sh: done"
