#!/usr/bin/env bash
# Mutation suite for H0 (Argon2.H0 and Argon2.H0_Model): shows that
# the proof and the tests each catch the mistakes they are supposed to
# catch. Adapted from the blake2b crate's scripts/mutants.sh.
#
# First the unmutated crate (the baseline) must build, prove and pass its
# tests under the same settings, or the run stops: otherwise a broken
# toolchain or a missing prover would look like a caught mutant. The
# baseline also proves both H0 units once with each prover alone, and
# every check must cost at most STEP_MARGIN steps (5000, half the units'
# 10000-step budget in argon2.gpr; not configurable) with its cheapest
# prover (scripts/spark-proof.py margin), so a check a mutant fails proved
# in the baseline with at least half its budget to spare; and every check
# must be proved by at least two of the provers each on its own
# (scripts/spark-proof.py coverage), so that none rests on one prover.
#
# Then each mutant changes one or more places in a TEMPORARY COPY of the
# crate (under .mutants/, never the sources):
#   * GNATprove re-runs on the unit named in the mutant's entry (P), under
#     the guard below;
#   * for mutants of executable code, the tests are rebuilt and re-run (T).
#     Mutants of static ghost code (the model, the client's lemma calls)
#     change nothing any build compiles, so for them tests are n/a.
# The proof is judged strictly, from GNATprove's results file
# (scripts/spark-proof.py judge): caught only when an unproved check lies
# at one of the places the mutant's entry expects (file, line and rule, in
# the mutated copy) and one of its VCs was attempted by every prover in
# PROVERS and failed within the step budget for each. A clean unproved
# check elsewhere is not a catch (a mutant can make a true goal dearer
# without the proof seeing the mistake): MISSED. A proof the guard
# killed, or whose unproved checks failed only through a timeout, memory
# exhaustion, a prover crash or a prover that never ran, is TAINTED: not a
# catch, and it fails the run. The tests catch a mutant only with H0
# evidence: the harness reports failed tests (" N passed, M failed" with
# M > 0) and at least one of them is an H0 test ("FAIL: H0: ...") that
# did not fail through Storage_Error. An exception that escapes the
# harness, or failures outside H0, are an ERROR, not a catch. The
# classifier has its own check: scripts/h0-mutants.sh --selftest.
#
# The mutants:
#   * field-order: T and m swapped among the hashed fields (code);
#   * field-byte-order: the fields stored big-endian, the local contract
#     changed to match (code);
#   * len-p-omitted: the length field of P never absorbed (code);
#   * dropped-final-chunk: each input's last chunk never absorbed (code);
#   * rounded-m: m replaced by the rounded m' = 4p floor (m / 4p) (code);
#   * copy-input-swap: Copy_Input copies S where P belongs and P where S
#     belongs (code);
#   * client-no-bridge: the input-chunk lemma applied to an empty slice
#     instead of the chunk, so the chunk's place is never established
#     (ghost; removing the call outright leaves the lemma unreferenced,
#     which the warning-free build refuses);
#   * model-m-prime: the model hashing m' instead of m, its field lemma
#     changed to match (ghost; the client's proof must fail);
#   * model-le-byte-order: the model's LE_Byte big-endian (ghost; the
#     client's proof must fail);
#   * model-schedule-swap: P's and S's pieces exchanged in the schedule
#     (ghost; the byte-position lemma must fail);
#   * model-formula-field: the formula reading length (S) where length (P)
#     belongs (ghost; the byte-position lemma must fail);
#   * model-length: the message one byte longer than its pieces (ghost).
#
# The guard. Every mutant proof runs under a guard that polls the proof's
# process tree every MUTANT_POLL seconds and kills the whole tree when one
# process, or the tree in total, exceeds MUTANT_RSS_KB of resident memory,
# or the proof exceeds MUTANT_WALL seconds. MUTANT_TIMEOUT bounds each
# prover attempt (mutant proofs and the baseline's): on a false goal a
# prover can run on without ever exhausting its step budget. The crate's
# own proof stays steps-only.
#
# Usage: scripts/h0-mutants.sh            (from anywhere in the crate)
#        scripts/h0-mutants.sh --selftest (the test classifier only)
#        ALR=/path/to/alr PROVE_JOBS=2 scripts/h0-mutants.sh
#        ONLY=field-order,rounded-m scripts/h0-mutants.sh
#        MUTANT_TIMEOUT=300 MUTANT_RSS_KB=4194304 MUTANT_WALL=3600 \
#          MUTANT_POLL=2 scripts/h0-mutants.sh
# Logs are kept in .mutants/logs/. The crate's CI does not run this
# script.

set -euo pipefail

ALR=${ALR:-alr}
PROVE_JOBS=${PROVE_JOBS:-4}
MUTANT_TIMEOUT=${MUTANT_TIMEOUT:-300}
MUTANT_RSS_KB=${MUTANT_RSS_KB:-4194304}
MUTANT_WALL=${MUTANT_WALL:-3600}
MUTANT_POLL=${MUTANT_POLL:-2}
STEP_MARGIN=5000
ONLY=${ONLY:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/.mutants"
LOGS="$WORK/logs"
SPARK_PROOF="$ROOT/scripts/spark-proof.py"
PYTHON=${PYTHON:-python3}
PROVERS="z3 cvc5 altergo"
UNITS="argon2-h0_model.adb argon2-h0.adb"

# name | file | exact text | replacement | unit to prove | must catch |
#   expected unproved checks (FILE:LINE:RULE, comma-separated, as the
#   mutated copy numbers its lines; a change to the sources can move them:
#   rerun with DISCOVER=1 and read each mutant's judge log to update them)
# Entries with the same name are one mutant changing several places; the
# unit, the layers and the expected checks are those of its first entry.
# In the text and its replacement, \n stands for a line break.
MUTANTS=(
  "field-order|src/argon2-h0.adb|        when 1 => Pr.Tag_Length,\n        when 2 => Pr.Memory,|        when 1 => Pr.Memory,\n        when 2 => Pr.Tag_Length,|argon2-h0.adb|PT|argon2-h0.adb:428:VC_ASSERT"
  "field-byte-order|src/argon2-h0.adb|        Post   => Bytes (0) = Byte (Value mod 2**8)\n                  and then Bytes (1) = Byte ((Value / 2**8) mod 2**8)\n                  and then Bytes (2) = Byte ((Value / 2**16) mod 2**8)\n                  and then Bytes (3) = Byte (Value / 2**24);|        Post   => Bytes (3) = Byte (Value mod 2**8)\n                  and then Bytes (2) = Byte ((Value / 2**8) mod 2**8)\n                  and then Bytes (1) = Byte ((Value / 2**16) mod 2**8)\n                  and then Bytes (0) = Byte (Value / 2**24);|argon2-h0.adb|PT|argon2-h0.adb:433:VC_ASSERT"
  "field-byte-order|src/argon2-h0.adb|        [Byte (Value mod 2**8), Byte ((Value / 2**8) mod 2**8),\n         Byte ((Value / 2**16) mod 2**8), Byte (Value / 2**24)];|        [Byte (Value / 2**24), Byte ((Value / 2**16) mod 2**8),\n         Byte ((Value / 2**8) mod 2**8), Byte (Value mod 2**8)];|||"
  "len-p-omitted|src/argon2-h0.adb|         Absorb_Field (St, Pr, Password, Salt, Secret, Associated_Data, Id);\n|         if Id /= 6 then\n            Absorb_Field\n              (St, Pr, Password, Salt, Secret, Associated_Data, Id);\n         end if;\n|argon2-h0.adb|PT|argon2-h0.adb:578:VC_PRECONDITION"
  "dropped-final-chunk|src/argon2-h0.adb|      while Offset < Total loop|      while Total - Offset > Chunk_Bytes loop|argon2-h0.adb|PT|argon2-h0.adb:504:VC_ASSERT"
  "rounded-m|src/argon2-h0.adb|        when 2 => Pr.Memory,|        when 2 =>\n          (if 4 * Pr.Parallelism = 0 then Pr.Memory\n           else 4 * Pr.Parallelism * (Pr.Memory / (4 * Pr.Parallelism))),|argon2-h0.adb|PT|argon2-h0.adb:430:VC_ASSERT"
  "copy-input-swap|src/argon2-h0.adb|         when 10 => Copy_Chunk (P, Offset, Chunk (0 .. Last));\n         when 11 => Copy_Chunk (S, Offset, Chunk (0 .. Last));|         when 10 => Copy_Chunk (S, Offset, Chunk (0 .. Last));\n         when 11 => Copy_Chunk (P, Offset, Chunk (0 .. Last));|argon2-h0.adb|PT|argon2-h0.adb:245:VC_POSTCONDITION"
  "client-no-bridge|src/argon2-h0.adb|         Pr.Kind, P, S, K, X, Id, I64 (Offset), Chunk (0 .. Last));|         Pr.Kind, P, S, K, X, Id, I64 (Offset), Chunk (1 .. 0));|argon2-h0.adb|P|argon2-h0.adb:465:VC_PRECONDITION"
  "model-m-prime|src/argon2-h0_model.ads|     ([0 => Parallelism, 1 => Tag_Length, 2 => Memory, 3 => Passes,|     ([0 => Parallelism, 1 => Tag_Length,\n       2 => (if 4 * Parallelism = 0 then Memory\n             else 4 * Parallelism * (Memory / (4 * Parallelism))),\n       3 => Passes,|argon2-h0.adb|P|argon2-h0.adb:428:VC_ASSERT"
  "model-m-prime|src/argon2-h0_model.ads|                              Kind, P, S, K, X) (2) = Memory|                              Kind, P, S, K, X) (2)\n                   = (if 4 * Parallelism = 0 then Memory\n                      else 4 * Parallelism\n                           * (Memory / (4 * Parallelism)))|||"
  "model-le-byte-order|src/argon2-h0_model.ads|        when 0      => Byte (Field mod 2**8),\n        when 1      => Byte ((Field / 2**8) mod 2**8),\n        when 2      => Byte ((Field / 2**16) mod 2**8),\n        when others => Byte (Field / 2**24))|        when 0      => Byte (Field / 2**24),\n        when 1      => Byte ((Field / 2**16) mod 2**8),\n        when 2      => Byte ((Field / 2**8) mod 2**8),\n        when others => Byte (Field mod 2**8))|argon2-h0.adb|P|argon2-h0.adb:433:VC_ASSERT"
  "model-schedule-swap|src/argon2-h0_model.ads|       8  => (Source => 10, Start => 0, Count => L (10), First => 28),|       8  => (Source => 11, Start => 0, Count => L (10), First => 28),|argon2-h0_model.adb|P|argon2-h0_model.ads:163:VC_POSTCONDITION"
  "model-schedule-swap|src/argon2-h0_model.ads|       10 => (Source => 11, Start => 0, Count => L (11),|       10 => (Source => 10, Start => 0, Count => L (11),|||"
  "model-formula-field|src/argon2-h0_model.ads|      elsif Pos < 28 then LE_Byte (F (6), Pos - 24)|      elsif Pos < 28 then LE_Byte (F (7), Pos - 24)|argon2-h0_model.adb|P|argon2-h0_model.adb:112:VC_ASSERT"
  "model-length|src/argon2-h0_model.ads|     (40 + L (10) + L (11) + L (12) + L (13))|     (41 + L (10) + L (11) + L (12) + L (13))|argon2-h0_model.adb|P|argon2-h0_model.ads:117:VC_POSTCONDITION"
)

copy_crate () {
  local dest=$1
  rm -rf "$dest"
  mkdir -p "$dest/tests"
  cp -R "$ROOT/src" "$ROOT/scripts" "$ROOT/alire.toml" "$ROOT/argon2.gpr" \
        "$dest/"
  # Alire's state, with the pinned dependency already deployed, so that a
  # copy builds without the network.
  [ ! -d "$ROOT/alire" ] || cp -R "$ROOT/alire" "$dest/"
  cp -R "$ROOT/tests/src" "$ROOT/tests/ref" "$ROOT/tests/alire.toml" \
        "$ROOT/tests/argon2_tests.gpr" "$dest/tests/"
  [ ! -d "$ROOT/tests/alire" ] || cp -R "$ROOT/tests/alire" "$dest/tests/"
}

# How many times $2 occurs in file $1, literally (across lines).
occurrences () {
  local content stripped
  content=$(cat "$1"; printf x); content=${content%x}
  stripped=${content//"$2"/}
  echo $(( (${#content} - ${#stripped}) / ${#2} ))
}

# Replaces the one occurrence of $2 in file $1 with $3, literally.
mutate () {
  local file=$1 search=$2 replace=$3
  local content count
  content=$(cat "$file"; printf x); content=${content%x}
  count=$(occurrences "$file" "$search")
  if [ "$count" -ne 1 ]; then
    echo "  mutation site found $count times (want exactly 1): $search"
    return 1
  fi
  printf '%s' "${content/"$search"/"$replace"}" > "$file"
}

build () {        # $1 = crate copy, $2 = log
  (cd "$1/tests" \
     && "$ALR" -n build --validation --profiles=argon2=validation) \
    > "$2" 2>&1
}

prove () {        # $1 = crate copy, $2 = unit, $3 = log
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../argon2.gpr -j"$PROVE_JOBS" -u "$2" \
     --timeout="$MUTANT_TIMEOUT") > "$3" 2>&1
}

# Proves unit $2 of crate copy $1 with prover $3 alone, from cold, into
# log $4. Some checks need another prover, so the exit status means
# nothing; the results file is what is read.
prove_alone () {
  rm -rf "$1"/obj/*/gnatprove
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../argon2.gpr -j"$PROVE_JOBS" -u "$2" --prover="$3" \
     --timeout="$MUTANT_TIMEOUT") > "$4" 2>&1 || true
}

run_tests () {    # $1 = crate copy, $2 = log
  (cd "$1/tests" && ./bin/test_main) > "$2" 2>&1
}

# The results file GNATprove wrote for unit $2 in crate copy $1 (empty if
# there is none).
spark_file () {
  local stem=${2%.adb}
  { find "$1/obj" -path "*/gnatprove/$stem.spark" 2>/dev/null || true; } \
    | head -n 1
}

# The process tree under pid $1 (itself included), from one ps snapshot.
tree_snapshot () {
  ps -A -o pid=,ppid=,rss= 2>/dev/null | awk -v root="$1" '
    { parent[$1] = $2; rss[$1] = $3 }
    END {
      keep[root] = 1
      do {
        grown = 0
        for (p in parent)
          if (!(p in keep) && (parent[p] in keep)) { keep[p] = 1; grown = 1 }
      } while (grown)
      for (p in keep) if (p in rss) print p, rss[p]
    }'
}

# Stops the whole tree under pid $1, then kills every process in it.
kill_tree () {
  local all="" pids round
  for round in 1 2 3 4 5 6 7 8; do
    pids=$(tree_snapshot "$1" | awk '{ print $1 }')
    [ -n "$pids" ] || break
    all="$all $pids"
    # shellcheck disable=SC2086
    kill -STOP $pids 2>/dev/null || true
  done
  if [ -n "$all" ]; then
    # shellcheck disable=SC2086
    kill -KILL $all 2>/dev/null || true
  fi
}

# Proves unit $2 of crate copy $1 into log $3 under the guard, and writes
# the guard's record to $4. Sets PROVE_STATUS, GUARD_FIRED, GUARD_WALL_S
# and GUARD_PEAK_TREE_KB.
guarded_prove () {
  local crate=$1 unit=$2 log=$3 record=$4
  local pid start now one tree
  GUARD_FIRED=""
  GUARD_PEAK_TREE_KB=0
  start=$(date +%s)
  prove "$crate" "$unit" "$log" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    read -r one tree < <(tree_snapshot "$pid" \
      | awk '{ t += $2; if ($2 > m) m = $2 } END { print m + 0, t + 0 }') \
      || { one=0; tree=0; }
    [ "$tree" -le "$GUARD_PEAK_TREE_KB" ] || GUARD_PEAK_TREE_KB=$tree
    now=$(date +%s)
    if [ "$one" -gt "$MUTANT_RSS_KB" ]; then
      GUARD_FIRED="memory: one process at $one KB (limit $MUTANT_RSS_KB)"
    elif [ "$tree" -gt "$MUTANT_RSS_KB" ]; then
      GUARD_FIRED="memory: process tree at $tree KB (limit $MUTANT_RSS_KB)"
    elif [ "$MUTANT_WALL" -gt 0 ] && [ $((now - start)) -gt "$MUTANT_WALL" ]
    then
      GUARD_FIRED="wall: $((now - start)) s (limit $MUTANT_WALL)"
    fi
    if [ -n "$GUARD_FIRED" ]; then
      echo "guard fired: $GUARD_FIRED" >> "$record"
      kill_tree "$pid"
      break
    fi
    sleep "$MUTANT_POLL"
  done
  PROVE_STATUS=0
  wait "$pid" 2>/dev/null || PROVE_STATUS=$?
  GUARD_WALL_S=$(( $(date +%s) - start ))
  echo "exit=$PROVE_STATUS wall=${GUARD_WALL_S}s" \
       "guard=${GUARD_FIRED:-none}" \
       "peak_rss_tree_kb=$GUARD_PEAK_TREE_KB" >> "$record"
}

# A mutant's proof, judged strictly from its results file. $1 = exit
# status, $2 = log, $3 = unit, $4 = results file (may be empty), $5 = the
# judgement's log.
proof_outcome () {   # ... $6 = expected checks (comma-separated)
  local reference=() expects=() status=0 place
  if [ "$1" -eq 0 ]; then
    echo no
    return
  fi
  if [ -z "$4" ]; then
    echo "no results file" > "$5"
    echo ERROR
    return
  fi
  if [ -f "$LOGS/baseline.costs.json" ]; then
    reference=(--costs "$LOGS/baseline.costs.json")
  fi
  IFS=',' read -r -a places <<< "$6"
  for place in "${places[@]}"; do
    [ -z "$place" ] || expects+=(--expect "$place")
  done
  "$PYTHON" -I "$SPARK_PROOF" judge "$3" "$4" "${PROVERS// /,}" \
    ${reference[@]+"${reference[@]}"} ${expects[@]+"${expects[@]}"} \
    > "$5" 2>&1 || status=$?
  case "$status" in
    0) echo yes ;;
    3) echo TAINTED ;;
    5) echo no ;;
    4)
      # Unproved checks only outside the unit: not a catch.
      if grep -qE '^ *(low|medium|high): ' "$2"; then echo no; else echo ERROR; fi
      ;;
    *) echo ERROR ;;
  esac
}

# A test run's outcome: yes only with H0 evidence (see the header).
test_outcome () {    # $1 = exit status, $2 = log
  if [ "$1" -eq 0 ]; then
    echo no
  elif grep -qE '^ *[0-9]+ passed, *[1-9][0-9]* failed' "$2" \
       && awk '/^FAIL: H0: / && tolower($0) !~ /storage_error/ { found = 1 }
               END { exit !found }' "$2"; then
    echo yes
  else
    echo ERROR
  fi
}

# The classifier's own check, on synthetic logs.
classifier_selftest () {
  local dir failures=0 got
  dir=$(mktemp -d)
  # name | exit status | log | expected outcome
  local cases=(
    "pass|0| 1444 passed, 0 failed|no"
    "h0-mismatch|1|FAIL: H0: RFC 9106 pre-hashing digest, y = 2: got 00\n 1443 passed, 1 failed|yes"
    "h0-contract|1|FAIL: H0: random case 3: unexpected exception: raised ADA.ASSERTIONS.ASSERTION_ERROR\n 1443 passed, 1 failed|yes"
    "storage-error-escapes|1|raised STORAGE_ERROR : synthetic allocation failure|ERROR"
    "storage-error-in-h0|1|FAIL: H0: random case 3: unexpected exception: raised STORAGE_ERROR\n 1443 passed, 1 failed|ERROR"
    "h-prime-only|1|FAIL: input 1 output 4 input first 0 output first 0\n 1443 passed, 1 failed|ERROR"
    "marker-without-count|1|FAIL: H0: every input empty|ERROR"
    "crash-no-log|139||ERROR"
    "many-h0-failures|1|@MANY@|yes"
  )
  local entry name status text want
  for entry in "${cases[@]}"; do
    IFS='|' read -r name status text want <<< "$entry"
    if [ "$text" = "@MANY@" ]; then
      # More than a pipe's buffer of failures (a pipeline with grep -q
      # once misread this under pipefail).
      for got in $(seq 1 3000); do
        echo "FAIL: H0: random case $got: against the C serialisation"
      done > "$dir/$name.log"
      echo " 1 passed, 3000 failed" >> "$dir/$name.log"
    else
      printf '%b\n' "$text" > "$dir/$name.log"
    fi
    got=$(test_outcome "$status" "$dir/$name.log")
    if [ "$got" != "$want" ]; then
      echo "classifier selftest FAILED: $name: got $got, want $want"
      failures=$((failures + 1))
    fi
  done
  rm -rf "$dir"
  echo "classifier selftest: $failures failed"
  [ "$failures" -eq 0 ]
}

if [ "${1-}" = "--selftest" ]; then
  classifier_selftest
  exit $?
fi

# The selected mutants, in order, without repeats.
names=()
for entry in "${MUTANTS[@]}"; do
  IFS='|' read -r name _ <<< "$entry"
  if [ -n "$ONLY" ]; then
    case ",$ONLY," in
      *",$name,"*) ;;
      *) continue ;;
    esac
  fi
  case " ${names[*]-} " in
    *" $name "*) ;;
    *) names+=("$name") ;;
  esac
done
if [ "${#names[@]}" -eq 0 ]; then
  echo "h0-mutants: no mutant matched ONLY=$ONLY"
  exit 1
fi

# The test classifier must pass its own check first.
classifier_selftest > /dev/null || { classifier_selftest; exit 2; }

# Every selected mutation site must occur exactly once in the sources, and
# every proof mutant must name the checks it expects to fail (DISCOVER=1
# lifts that, to find them: the judge then accepts any clean check),
# before any time goes into the baseline.
sites_ok=1
for entry in "${MUTANTS[@]}"; do
  IFS='|' read -r name file search replace unit expect checks <<< "$entry"
  case " ${names[*]} " in *" $name "*) ;; *) continue ;; esac
  if [ -n "$unit" ] && [ -z "$checks" ] && [ "${DISCOVER:-0}" != 1 ]; then
    echo "mutant $name: no expected checks"
    sites_ok=0
  fi
  search=${search//\\n/$'\n'}
  count=$(occurrences "$ROOT/$file" "$search")
  if [ "$count" -ne 1 ]; then
    echo "mutant $name: site found $count times in $file (want exactly 1)"
    sites_ok=0
  fi
done
[ "$sites_ok" -eq 1 ] || exit 2

rm -rf "$WORK"
mkdir -p "$LOGS"

echo "=================================================================="
echo "baseline: unmutated crate (units: $UNITS)"
base="$WORK/baseline"
copy_crate "$base"
if ! build "$base" "$LOGS/baseline.build.log"; then
  echo "  baseline does not build: see $LOGS/baseline.build.log"
  exit 2
fi
if grep -qiE 'warning|\(style\)' "$LOGS/baseline.build.log"; then
  echo "  baseline build prints warnings: see $LOGS/baseline.build.log"
  exit 2
fi
for unit in $UNITS; do
  rm -rf "$base"/obj/*/gnatprove
  if ! prove "$base" "$unit" "$LOGS/baseline.prove.$unit.log"; then
    echo "  baseline proof of $unit failed: see $LOGS/baseline.prove.$unit.log"
    exit 2
  fi
  spark=$(spark_file "$base" "$unit")
  if [ -z "$spark" ]; then
    echo "  baseline proof of $unit left no results file"
    exit 2
  fi
  cp "$spark" "$LOGS/baseline.${unit%.adb}.spark"
  for prover in $PROVERS; do
    prove_alone "$base" "$unit" "$prover" \
      "$LOGS/baseline.prove.$unit.$prover.log"
    spark=$(spark_file "$base" "$unit")
    if [ -n "$spark" ]; then
      cp "$spark" "$LOGS/baseline.${unit%.adb}.$prover.spark"
    fi
  done
done
# shellcheck disable=SC2086
if ! "$PYTHON" -I "$SPARK_PROOF" margin "$STEP_MARGIN" \
     "$LOGS/baseline.costs.json" "$LOGS" "${PROVERS// /,}" \
     $UNITS > "$LOGS/baseline.margin.log" 2>&1; then
  sed 's/^/  /' "$LOGS/baseline.margin.log"
  echo "  baseline fails the step margin: see $LOGS/baseline.margin.log"
  exit 2
fi
sed 's/^/  /' "$LOGS/baseline.margin.log"
# shellcheck disable=SC2086
if ! "$PYTHON" -I "$SPARK_PROOF" coverage 2 "$LOGS" "${PROVERS// /,}" \
     $UNITS > "$LOGS/baseline.coverage.log" 2>&1; then
  sed 's/^/  /' "$LOGS/baseline.coverage.log"
  echo "  baseline fails the prover coverage: a check is proved by fewer"
  echo "  than two provers on their own"
  exit 2
fi
sed 's/^/  /' "$LOGS/baseline.coverage.log"
if ! run_tests "$base" "$LOGS/baseline.tests.log"; then
  echo "  baseline tests failed: see $LOGS/baseline.tests.log"
  exit 2
fi
rm -rf "$base"
echo "  baseline: builds without warnings, proves and passes"

results=()
broken=0
errors=0
tainted=0
for name in "${names[@]}"; do
  echo "=================================================================="
  echo "mutant: $name"
  dir="$WORK/$name"
  copy_crate "$dir"
  unit=""
  expect=""
  checks=""
  for entry in "${MUTANTS[@]}"; do
    IFS='|' read -r ename file search replace eunit eexpect echecks \
      <<< "$entry"
    [ "$ename" = "$name" ] || continue
    if [ -z "$unit" ]; then
      unit=$eunit
      expect=$eexpect
      checks=$echecks
    fi
    search=${search//\\n/$'\n'}
    replace=${replace//\\n/$'\n'}
    mutate "$dir/$file" "$search" "$replace"
  done

  caught_p=-
  caught_t=n/a
  GUARD_WALL_S=0
  GUARD_PEAK_TREE_KB=0
  if ! build "$dir" "$LOGS/$name.build.log"; then
    # A mutant that doesn't compile tests nothing: an error in the suite,
    # not a catch.
    echo "  does not build: see $LOGS/$name.build.log"
    caught_p=ERROR
    caught_t=ERROR
  else
    guarded_prove "$dir" "$unit" "$LOGS/$name.prove.log" "$LOGS/$name.guard"
    spark=$(spark_file "$dir" "$unit")
    if [ -n "$spark" ]; then
      cp "$spark" "$LOGS/$name.spark"
      spark="$LOGS/$name.spark"
    fi
    if [ -n "$GUARD_FIRED" ]; then
      caught_p=TAINTED
      echo "  guard fired: $GUARD_FIRED"
    else
      caught_p=$(proof_outcome "$PROVE_STATUS" "$LOGS/$name.prove.log" \
                   "$unit" "$spark" "$LOGS/$name.judge.log" "$checks")
      [ ! -f "$LOGS/$name.judge.log" ] \
        || sed 's/^/  /' "$LOGS/$name.judge.log"
    fi
    case "$expect" in
      *T*)
        status=0
        run_tests "$dir" "$LOGS/$name.tests.log" || status=$?
        caught_t=$(test_outcome "$status" "$LOGS/$name.tests.log")
        ;;
    esac
  fi

  verdict=ok
  if [ "$caught_p" = ERROR ] || [ "$caught_t" = ERROR ]; then
    verdict=ERROR
    errors=$((errors + 1))
  elif [ "$caught_p" = TAINTED ]; then
    verdict=TAINTED
    tainted=$((tainted + 1))
  else
    case "$expect" in
      *P*) [ "$caught_p" = yes ] || verdict=MISSED ;;
    esac
    case "$expect" in
      *T*) [ "$caught_t" = yes ] || verdict=MISSED ;;
    esac
    [ "$verdict" = ok ] || broken=$((broken + 1))
  fi
  line=$(printf '%-22s proof:%-7s tests:%-5s must:%-3s %-7s wall:%5ss rss:%8sKB' \
         "$name" "$caught_p" "$caught_t" "$expect" "$verdict" \
         "$GUARD_WALL_S" "$GUARD_PEAK_TREE_KB")
  echo "  $line"
  results+=("$line")
  rm -rf "$dir"
done

echo
echo "mutation summary (logs in $LOGS; wall and rss: the guarded proof)"
printf '  %s\n' "${results[@]}"
status=0
if [ "$errors" -gt 0 ]; then
  echo "h0-mutants: $errors mutant(s) could not be judged (ERROR)"
  status=1
fi
if [ "$tainted" -gt 0 ]; then
  echo "h0-mutants: $tainted mutant(s) TAINTED: not catches"
  status=1
fi
if [ "$broken" -gt 0 ]; then
  echo "h0-mutants: $broken mutant(s) MISSED"
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo "h0-mutants: every mutant caught by every layer it must be"
fi
exit "$status"
