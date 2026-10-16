#!/usr/bin/env python3
"""Reads GNATprove's per-unit results (the .spark files) for scripts/h0-mutants.sh.

Two commands:

  spark-proof.py margin LIMIT COSTS.json DIR PROVER,... UNIT...
      The step-margin gate for the baseline. For each UNIT (e.g.
      argon2-h0_model.adb), DIR holds baseline.<stem>.spark, the
      proof with every prover, and baseline.<stem>.<prover>.spark, a proof
      with that prover alone, for each PROVER. A check's cost is the
      largest, over the check's VCs, of the fewest steps any prover took to
      prove the VC (in any of those runs): the cheapest prover's steps.
      With every prover at once GNATprove races them and credits the first
      to finish, which depends on timing; each prover's steps alone do
      not, so the cost is the same on every run. Prints each unit's
      costliest checks and writes every check's cost to COSTS.json; exits
      1 if any check costs more than LIMIT steps, 2 if a file is
      unreadable, a check is unproved in the all-provers proof, or a VC
      has no proof in any run.

  spark-proof.py coverage MIN DIR PROVER,... UNIT...
      The prover-coverage gate for the baseline, over the same files as
      margin: every check of the all-provers proof must be proved, in full,
      by at least MIN of the single-prover proofs on their own, so that no
      check rests on one prover. Lists each check below MIN; exits 1 if
      there is one, 2 if a file is unreadable.

  spark-proof.py judge UNIT FILE.spark PROVER,... [--costs COSTS.json]
                       [--expect FILE:LINE:RULE]...
      Judges one mutant's proof of UNIT (e.g. argon2-h0_model.adb).
      Only unproved checks located in UNIT's own spec or body count, and
      only failed proofs (severity low, medium or high on a VC_ rule), not
      proof warnings. Each is "clean" when one of its VCs was attempted by
      every PROVER (the provers the proof was asked to run; an attempt
      list that misses one is not evidence that it failed) and every
      attempt failed on the step budget or on a definite prover answer
      (Step limit exceeded, Unknown, Invalid); a VC proved by neither
      prover attempt but by a transformation (split, ...) is judged by its
      subgoals: clean when every transformation tried left a clean
      subgoal. A check is "tainted" when no VC is clean: it failed through
      a timeout, a memory exhaustion or a prover crash, which a steps-only
      proof might not reproduce, or no VC was attempted. A VC with no
      attempt (GNATprove stops after a check's first failure) is ignored.
      With --expect, only a clean unproved check at one of the given
      places (file, line and rule) is a catch: a mutant that merely makes
      some other, true goal dearer is not. Prints the checks, with the
      baseline's cost of the same check (file:line:col and rule) where
      there is one, then one verdict line. Exit status: 0 caught, 3
      tainted (unproved checks, none clean), 4 none (no unproved check in
      UNIT), 5 unexpected (clean unproved checks, none of them expected),
      2 the file is missing or unreadable, or the arguments are wrong.

  spark-proof.py selftest
      Adversarial fixtures for the margin arithmetic and for the judge;
      exit 0 if they pass.
"""

import json
import os
import re
import sys
import tempfile

CLEAN_FAILURES = ("step limit exceeded", "unknown", "invalid")
FAILED_SEVERITIES = ("low", "medium", "high")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)["proof"]


def result_of(attempt):
    """The prover's answer, lower case, whitespace collapsed."""
    return re.sub(r"\s+", " ", str(attempt.get("result", ""))).strip().lower()


def cost(check):
    """Steps of the credited prover, maximised over the check's VCs."""
    stats = check.get("stats") or {}
    return max([int(s.get("max_steps", 0)) for s in stats.values()] or [0])


def where(check):
    return "%s:%d:%d %s" % (check["file"], check["line"], check["col"],
                            check["rule"])


def key(check):
    """A check's identity across runs: where it is checked, and its rule."""
    return "%s:%d:%d %s" % (check.get("check_file", check["file"]),
                            check.get("check_line", check["line"]),
                            check.get("check_col", check["col"]),
                            check["rule"])


def identities(checks):
    """(identity, check) for each check. Several checks can share a place
    and rule, so the identity also counts which one of them it is, in the
    file's order, which is the same on every run of the same sources."""
    seen = {}
    result = []
    for check in checks:
        base = key(check)
        seen[base] = seen.get(base, 0) + 1
        result.append(("%s #%d" % (base, seen[base]), check))
    return result


def node_cost(node):
    """The fewest steps that prove one VC: a prover's own Valid attempt, or
    the dearest subgoal of a transformation that proves it; None when
    nothing here proves it (or a Valid attempt has no step count)."""
    best = None
    for attempt in (node.get("proof_attempts") or {}).values():
        if result_of(attempt) == "valid" and "steps" in attempt:
            steps = int(attempt["steps"])
            best = steps if best is None else min(best, steps)
    for subgoals in (node.get("transformations") or {}).values():
        if not isinstance(subgoals, list) or not subgoals:
            continue
        costs = [node_cost(s) for s in subgoals]
        if all(c is not None for c in costs):
            total = max(costs)
            best = total if best is None else min(best, total)
    return best


def cheapest(check, others):
    """The check's cost: per VC, the fewest steps of any prover in the
    check's own tree or the same check's trees in the other runs; the
    largest over its VCs. None if some VC has no proof anywhere, or if a
    run's tree has another shape (the match between runs is then in
    doubt, and the answer must not be a guess)."""
    trees = [check.get("check_tree") or []]
    trees += [o.get("check_tree") or [] for o in others]
    if any(len(tree) != len(trees[0]) for tree in trees):
        return None
    worst = 0
    for index in range(len(trees[0])):
        costs = [c for c in (node_cost(tree[index]) for tree in trees)
                 if c is not None]
        if not costs:
            return None
        worst = max(worst, min(costs))
    return worst


def prover_of(name):
    """A prover's name as given on the command line (z3, cvc5, altergo)."""
    return str(name).strip().lower().replace("-", "")


def node_status(node, provers):
    """proved, clean (failed within the budget, by every one of provers),
    tainted, or unattempted (GNATprove stops attempting a check's other VCs
    once one fails, so a VC with no attempt says nothing either way), for
    one VC."""
    named = node.get("proof_attempts") or {}
    attempts = list(named.values())
    if any(result_of(a) == "valid" for a in attempts):
        return "proved"
    branches = []
    for subgoals in (node.get("transformations") or {}).values():
        if not isinstance(subgoals, list):
            continue
        statuses = [node_status(s, provers) for s in subgoals]
        if all(s == "proved" for s in statuses):
            return "proved"
        branches.append("clean" if "clean" in statuses else "tainted")
    if not attempts:
        if not branches:
            return "unattempted"
        # Proved by no prover attempt here: judged by the transformations.
        return "clean" if all(b == "clean" for b in branches) else "tainted"
    attempted = {prover_of(name) for name in named}
    clean_here = (set(provers) <= attempted
                  and all(result_of(a).startswith(CLEAN_FAILURES)
                          for a in attempts))
    if not clean_here or "tainted" in branches:
        return "tainted"
    return "clean"


def check_status(check, provers):
    """clean when some VC is clean; tainted when no VC is clean and some
    failed through a timeout, memory, a crash or a prover that never ran.
    A check with no attempted VC at all is neither: it is not evidence of
    anything and counts as tainted."""
    statuses = [node_status(n, provers)
                for n in check.get("check_tree") or []]
    if "clean" in statuses:
        return "clean"
    return "tainted"


def place(check):
    """Where a check is, as --expect names it: FILE:LINE:RULE."""
    return "%s:%d:%s" % (check["file"], check["line"], check["rule"])


def margin(limit, costs_path, directory, provers, units):
    over = 0
    costs = {}
    for unit in units:
        stem = os.path.splitext(os.path.basename(unit))[0]
        path = os.path.join(directory, "baseline.%s.spark" % stem)
        try:
            checks = load(path)
            singles = [dict(identities(load(os.path.join(
                           directory, "baseline.%s.%s.spark" % (stem, p)))))
                       for p in provers]
        except (OSError, ValueError, KeyError) as error:
            print("%s: unreadable results (%s)" % (stem, error))
            return 2
        unproved = [c for c in checks if c.get("severity") != "info"]
        if unproved:
            print("%s: %d unproved check(s), first %s"
                  % (stem, len(unproved), where(unproved[0])))
            return 2
        ranked = []
        for ident, check in identities(checks):
            others = [s[ident] for s in singles if ident in s]
            if len(others) != len(singles):
                print("%s: %s is missing from a single-prover run"
                      % (stem, where(check)))
                return 2
            steps = cheapest(check, others)
            if steps is None:
                print("%s: no proof found for a VC of %s"
                      % (stem, where(check)))
                return 2
            costs[key(check)] = max(steps, costs.get(key(check), 0))
            ranked.append((steps, cost(check), check))
        ranked.sort(key=lambda r: r[0], reverse=True)
        top = ranked[0][0] if ranked else 0
        print("%s: %d checks, costliest %d steps (limit %d)"
              % (stem, len(checks), top, limit))
        for steps, raced, check in ranked[:3]:
            print("  %6d %s (raced: %d)" % (steps, where(check), raced))
        for steps, raced, check in ranked:
            if steps > limit:
                over += 1
                print("  OVER %d: %s (%d steps)" % (limit, where(check), steps))
    with open(costs_path, "w", encoding="utf-8") as handle:
        json.dump(costs, handle, indent=1, sort_keys=True)
    return 1 if over else 0


def coverage(minimum, directory, provers, units):
    short = 0
    for unit in units:
        stem = os.path.splitext(os.path.basename(unit))[0]
        try:
            checks = load(os.path.join(directory, "baseline.%s.spark" % stem))
            singles = {p: dict(identities(load(os.path.join(
                           directory, "baseline.%s.%s.spark" % (stem, p)))))
                       for p in provers}
        except (OSError, ValueError, KeyError) as error:
            print("%s: unreadable results (%s)" % (stem, error))
            return 2
        tally = {}
        for ident, check in identities(checks):
            alone = [p for p in provers
                     if ident in singles[p]
                     and singles[p][ident].get("severity") == "info"]
            tally[len(alone)] = tally.get(len(alone), 0) + 1
            if len(alone) < minimum:
                short += 1
                print("  %s: proved alone by %s only"
                      % (where(check), ", ".join(alone) or "none"))
        print("%s: %d checks; proved alone by %s provers: %s"
              % (stem, len(checks),
                 "/".join(str(n) for n in range(len(provers), -1, -1)),
                 "/".join(str(tally.get(n, 0))
                          for n in range(len(provers), -1, -1))))
    return 1 if short else 0


def judge(unit, path, provers, baseline_path=None, expects=()):
    stem = os.path.splitext(os.path.basename(unit))[0]
    own = {stem + ".ads", stem + ".adb"}
    try:
        checks = load(path)
    except (OSError, ValueError, KeyError) as error:
        print("no proof results: %s (%s)" % (path, error))
        return 2
    baseline = {}
    if baseline_path:
        try:
            with open(baseline_path, encoding="utf-8") as handle:
                baseline = json.load(handle)
        except (OSError, ValueError):
            baseline = {}
    # Only a failed proof counts: severity low, medium or high on a VC_
    # rule. A proof warning (an unreachable branch, an inconsistent
    # precondition) is not an unproved check.
    unproved = [c for c in checks
                if c.get("severity") in FAILED_SEVERITIES
                and str(c.get("rule", "")).startswith("VC_")
                and c["file"] in own]
    clean = 0
    expected = 0
    for check in unproved:
        status = check_status(check, provers)
        clean += status == "clean"
        hit = status == "clean" and place(check) in expects
        expected += hit
        base = baseline.get(key(check))
        print("  %s%s %s: %s (baseline: %s)"
              % (status, " (expected)" if hit else "", where(check),
                 check.get("message", {}).get("text", "?"),
                 "%d steps" % base if base is not None else "no such check"))
    if expects and expected:
        print("verdict: caught (%d expected clean unproved check(s) in %s)"
              % (expected, stem))
        return 0
    if not expects and clean:
        print("verdict: caught (%d clean unproved check(s) in %s)"
              % (clean, stem))
        return 0
    if clean:
        print("verdict: unexpected (%d clean unproved check(s) in %s, none"
              " at %s)" % (clean, stem, ", ".join(sorted(expects))))
        return 5
    if unproved:
        print("verdict: tainted (%d unproved check(s) in %s, none within"
              " the step budget for every prover)" % (len(unproved), stem))
        return 3
    print("verdict: none (no unproved check in %s)" % stem)
    return 4


def selftest():
    """Adversarial fixtures for the margin arithmetic and the judge.
    Returns 0 if all behave as the gates need, 1 otherwise."""
    def valid(steps):
        return {"proof_attempts": {"Z3": {"result": "Valid", "steps": steps}}}

    def check(line, tree):
        return {"file": "u.adb", "line": line, "col": 1, "rule": "VC_ASSERT",
                "severity": "info", "check_tree": tree}

    failures = []

    def expect(name, got, want):
        if got != want:
            failures.append("%s: got %r, want %r" % (name, got, want))

    # A proof by transformation costs its dearest subgoal, not zero.
    transformed = {"transformations": {"split": [valid(9000), valid(10)]}}
    expect("transformed", cheapest(check(1, [transformed]), []), 9000)
    # A cheaper plain proof of the same VC wins over the transformation.
    both = dict(transformed, **valid(40))
    expect("transformed-or-plain", cheapest(check(1, [both]), []), 40)
    # The other runs can only lower a VC's cost.
    expect("other-run", cheapest(check(1, [valid(9000)]),
                                  [check(1, [valid(7)])]), 7)
    # A VC no run proved, or a tree of another shape: no answer.
    expect("unproved", cheapest(check(1, [{}]), []), None)
    expect("shape", cheapest(check(1, [valid(5)]),
                             [check(1, [valid(5), valid(5)])]), None)
    # A valid attempt without a step count proves nothing here.
    expect("stepless", cheapest(
        check(1, [{"proof_attempts": {"Z3": {"result": "Valid"}}}]), []),
        None)
    # Checks that share a place and rule keep their own identities.
    twins = identities([check(1, [valid(9000)]), check(1, [valid(1)])])
    expect("twins", [name for name, _ in twins],
           ["u.adb:1:1 VC_ASSERT #1", "u.adb:1:1 VC_ASSERT #2"])
    lookup = dict(twins)
    expect("twin-costs",
           [cheapest(c, [lookup[n]]) for n, c in twins], [9000, 1])
    # The judge. Three provers were asked for.
    provers = ["z3", "cvc5", "altergo"]

    def failed(**results):
        return {"proof_attempts": {
            name: {"result": result, "steps": 10001}
            for name, result in results.items()}}

    every = failed(Z3="Step limit exceeded", CVC5="Unknown",
                   altergo="Step limit exceeded")
    expect("every-prover-clean", node_status(every, provers), "clean")
    # A VC whose attempts miss a prover is not clean: fail closed.
    expect("missing-prover",
           node_status(failed(Z3="Unknown"), provers), "tainted")
    expect("missing-two",
           node_status(failed(Z3="Unknown", CVC5="Unknown"), provers),
           "tainted")
    # A crash or a timeout is not clean.
    expect("crash", node_status(
        failed(Z3="High failure (signaled)", CVC5="Unknown",
               altergo="Step limit exceeded"), provers), "tainted")
    # A failure under a transformation only, with no attempt of its own,
    # is judged by its subgoals.
    expect("transformation-clean", node_status(
        {"transformations": {"split": [valid(3), every]}}, provers),
        "clean")
    expect("transformation-tainted", node_status(
        {"transformations": {"split": [valid(3), failed(Z3="Unknown")]}},
        provers), "tainted")
    expect("transformation-proved", node_status(
        {"transformations": {"split": [valid(3), valid(4)]}}, provers),
        "proved")
    expect("unattempted", node_status({}, provers), "unattempted")
    # Expected places: a clean check elsewhere is not a catch.
    def unproved(line, tree):
        return dict(check(line, tree), severity="medium")
    descriptor, fixture = tempfile.mkstemp(suffix=".spark")
    os.close(descriptor)
    try:
        with open(fixture, "w", encoding="utf-8") as handle:
            json.dump({"proof": [unproved(7, [every])]}, handle)
        quiet = open(os.devnull, "w", encoding="utf-8")
        saved, sys.stdout = sys.stdout, quiet
        try:
            verdicts = [
                judge("u.adb", fixture, provers),
                judge("u.adb", fixture, provers, None, ["u.adb:7:VC_ASSERT"]),
                judge("u.adb", fixture, provers, None, ["u.adb:8:VC_ASSERT"]),
                judge("v.adb", fixture, provers)]
        finally:
            sys.stdout = saved
            quiet.close()
        expect("judge-verdicts", verdicts, [0, 0, 5, 4])
        with open(fixture, "w", encoding="utf-8") as handle:
            json.dump({"proof": [unproved(7, [failed(Z3="Unknown")])]},
                      handle)
        quiet = open(os.devnull, "w", encoding="utf-8")
        saved, sys.stdout = sys.stdout, quiet
        try:
            verdict = judge("u.adb", fixture, provers)
        finally:
            sys.stdout = saved
            quiet.close()
        expect("judge-partial-evidence", verdict, 3)
    finally:
        if os.path.exists(fixture):
            os.remove(fixture)
    for line in failures:
        print("selftest FAILED: " + line)
    print("selftest: %d failed" % len(failures))
    return 1 if failures else 0


def main(argv):
    if argv == ["selftest"]:
        return selftest()
    if len(argv) >= 5 and argv[0] == "coverage":
        return coverage(int(argv[1]), argv[2],
                        [p for p in argv[3].split(",") if p], argv[4:])
    if len(argv) >= 6 and argv[0] == "margin":
        return margin(int(argv[1]), argv[2], argv[3],
                      [p for p in argv[4].split(",") if p], argv[5:])
    if len(argv) >= 4 and argv[0] == "judge":
        provers = [prover_of(p) for p in argv[3].split(",") if p]
        costs = None
        expects = []
        rest = argv[4:]
        while rest:
            if len(rest) >= 2 and rest[0] == "--costs":
                costs = rest[1]
            elif len(rest) >= 2 and rest[0] == "--expect":
                expects.append(rest[1])
            else:
                print(__doc__)
                return 2
            rest = rest[2:]
        if not provers:
            print(__doc__)
            return 2
        return judge(argv[1], argv[2], provers, costs, expects)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
