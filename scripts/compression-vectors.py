#!/usr/bin/env python3
"""Generates tests/src/compression_vectors.ads from tests/ref/kat-blocks.json:
published test vectors for Argon2's block compression G (RFC 9106 sections
3.5 and 3.6).

The vectors are blocks of the official Argon2 reference's own known-answer
files (kats/argon2id, kats/argon2d, kats/argon2i, at the commit recorded in
the JSON), which print all 128 words of all 32 blocks after each pass of a
32 KiB, 3-pass, 4-lane run. Every block the reference computes is G of two
earlier blocks of the same dump; that is where the vectors come from, so they
are independent of this crate and of its authors. In pass 0 a block is
G (previous block, reference block); in later passes it is the block's old
value xor G (previous block, reference block).

Each case in the JSON holds X (the previous block), Y (the reference block),
Old (the block's value before the call, used only when XOR is true) and
Expected (the published block), 128 words of 16 hex digits each, and where
they were found.

Usage (from the crate root, with an isolated interpreter):
  python3 -I scripts/compression-vectors.py          rewrite
                                                     tests/src/compression_vectors.ads
  python3 -I scripts/compression-vectors.py --check  exit 1 if that file is
      stale, or if any case fails an independent pure-Python evaluation of G
  python3 -I scripts/compression-vectors.py --extract KAT_DIR
      rebuild tests/ref/kat-blocks.json from the three KAT files (named
      argon2id, argon2d and argon2i) in KAT_DIR, searching the dump for the
      pair of earlier blocks each chosen block is G of, then rewrite the
      Ada file. Needs the three files; CI does not run this mode.

The pure-Python G below is a fourth transcription of the RFC (the others are
the model, the Ada code and the reference), used only to check the JSON.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "tests" / "ref" / "kat-blocks.json"
ADS_PATH = ROOT / "tests" / "src" / "compression_vectors.ads"

COMMIT = "f57e61e19229e23c4445b85494dbf7c07de721cb"
VARIANTS = ["argon2id", "argon2d", "argon2i"]
LANES = 4
LANE_LENGTH = 8
NAME_WIDTH = 24

MASK = (1 << 64) - 1
LOW = (1 << 32) - 1


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


def fblamka(x, y):
    return (x + y + 2 * (x & LOW) * (y & LOW)) & MASK


def gb(v, a, b, c, d):
    v[a] = fblamka(v[a], v[b])
    v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = fblamka(v[c], v[d])
    v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = fblamka(v[a], v[b])
    v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = fblamka(v[c], v[d])
    v[b] = rotr(v[b] ^ v[c], 63)


def permute(v):
    gb(v, 0, 4, 8, 12)
    gb(v, 1, 5, 9, 13)
    gb(v, 2, 6, 10, 14)
    gb(v, 3, 7, 11, 15)
    gb(v, 0, 5, 10, 15)
    gb(v, 1, 6, 11, 12)
    gb(v, 2, 7, 8, 13)
    gb(v, 3, 4, 9, 14)


def compress(x, y):
    """G (X, Y) of RFC 9106 section 3.5: rows of 16 consecutive words first,
    then the strided pairs (2i, 2i+1, 2i+16, 2i+17, ... 2i+112, 2i+113)."""
    r = [a ^ b for a, b in zip(x, y)]
    q = list(r)
    for i in range(8):
        idx = list(range(16 * i, 16 * i + 16))
        v = [q[k] for k in idx]
        permute(v)
        for k, w in zip(idx, v):
            q[k] = w
    z = list(q)
    for i in range(8):
        idx = [2 * i + 16 * k + d for k in range(8) for d in (0, 1)]
        v = [z[k] for k in idx]
        permute(v)
        for k, w in zip(idx, v):
            z[k] = w
    return [a ^ b for a, b in zip(z, r)]


def parse_dump(text):
    """The three 'After pass N' dumps of a KAT file: three lists of 32
    blocks of 128 words."""
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if l.startswith(" After pass")]
    passes = []
    for s in starts:
        blocks = {}
        for l in lines[s + 1:]:
            m = re.match(r"Block (\d+) \[\s*(\d+)\]: ([0-9a-f]{16})$", l)
            if not m:
                break
            blocks.setdefault(int(m[1]), {})[int(m[2])] = int(m[3], 16)
        assert len(blocks) == LANES * LANE_LENGTH, "block count"
        passes.append([[blocks[b][i] for i in range(128)]
                       for b in range(LANES * LANE_LENGTH)])
    assert len(passes) == 3, "three passes"
    return passes


def hexblock(b):
    return ["%016x" % w for w in b]


def find_pass0(snap, i):
    """Reference block index k with snap[i] = G (snap[i-1], snap[k])."""
    found = [k for k in range(len(snap))
             if compress(snap[i - 1], snap[k]) == snap[i]]
    assert len(found) == 1, "ambiguous or missing reference for block %d" % i
    return found[0]


def find_xor(old_snap, new_snap, i):
    """For a block of a later pass: (previous-state, reference-state, k)
    with new[i] = old[i] xor G (prev, ref). The previous block is the new
    value of i-1 (the old value of the lane's last block for the lane's
    first block); the reference is found in either snapshot."""
    lane, j = divmod(i, LANE_LENGTH)
    if j > 0:
        prev, prev_state = new_snap[i - 1], "new"
    else:
        prev, prev_state = old_snap[lane * LANE_LENGTH + LANE_LENGTH - 1], \
            "old"
    found = []
    for state, snap in (("new", new_snap), ("old", old_snap)):
        for k in range(len(snap)):
            g = compress(prev, snap[k])
            if [a ^ b for a, b in zip(old_snap[i], g)] == new_snap[i]:
                found.append((state, k))
    assert len(found) == 1, "ambiguous or missing reference for block %d" % i
    return prev_state, found[0][0], found[0][1]


def extract(kat_dir):
    cases = []
    summary = {}
    for variant in VARIANTS:
        text = (pathlib.Path(kat_dir) / variant).read_text()
        passes = parse_dump(text)
        p0, p1 = passes[0], passes[1]
        # Pass 0: every computed block must be G of two earlier blocks.
        matched = {}
        for lane in range(LANES):
            for j in range(2, LANE_LENGTH):
                i = lane * LANE_LENGTH + j
                matched[i] = find_pass0(p0, i)
        summary[variant] = {"pass0_matched": len(matched)}
        # Choose: the first computed block (its reference is in another
        # lane), the first block whose reference is in its own lane, and
        # the last block.
        same_lane = next(i for i in sorted(matched)
                         if matched[i] // LANE_LENGTH == i // LANE_LENGTH)
        for i in (2, same_lane, LANES * LANE_LENGTH - 1):
            k = matched[i]
            cases.append({
                "name": "%s-pass0-b%02d" % (variant, i),
                "kat": "kats/" + variant, "pass": 0, "block": i,
                "prev_block": i - 1, "ref_block": k, "xor": False,
                "x": hexblock(p0[i - 1]), "y": hexblock(p0[k]),
                "old": hexblock([0] * 128), "expected": hexblock(p0[i]),
            })
        # Pass 1 (the XOR form): the first block of lane 0, whose previous
        # block is the old value of the lane's last block, and the first
        # block whose previous and reference blocks are both new values and
        # whose reference is in another lane.
        for lane in range(LANES):
            for j in range(LANE_LENGTH):
                find_xor(p0, p1, lane * LANE_LENGTH + j)
        summary[variant]["pass1_matched"] = LANES * LANE_LENGTH
        picks = [0]
        for i in range(1, LANES * LANE_LENGTH):
            ps, rs, k = find_xor(p0, p1, i)
            if ps == "new" and rs == "new" and \
                    k // LANE_LENGTH != i // LANE_LENGTH:
                picks.append(i)
                break
        for i in picks:
            ps, rs, k = find_xor(p0, p1, i)
            prev = p1[i - 1] if ps == "new" else \
                p0[(i // LANE_LENGTH) * LANE_LENGTH + LANE_LENGTH - 1]
            prev_idx = i - 1 if ps == "new" else \
                (i // LANE_LENGTH) * LANE_LENGTH + LANE_LENGTH - 1
            ref = (p1 if rs == "new" else p0)[k]
            cases.append({
                "name": "%s-pass1-b%02d" % (variant, i),
                "kat": "kats/" + variant, "pass": 1, "block": i,
                "prev_block": prev_idx, "prev_state": ps,
                "ref_block": k, "ref_state": rs, "xor": True,
                "x": hexblock(prev), "y": hexblock(ref),
                "old": hexblock(p0[i]), "expected": hexblock(p1[i]),
            })
    doc = {
        "source": {
            "repository": "https://github.com/P-H-C/phc-winner-argon2",
            "commit": COMMIT,
            "files": ["kats/" + v for v in VARIANTS],
            "layout": "32 KiB, 3 passes, 4 lanes of 8 blocks; block "
                      "i = lane * 8 + j",
            "extraction": "every computed block of pass 0 and every block "
                          "of pass 1 was found to be G of two blocks of "
                          "the same dump (see scripts/compression-vectors.py "
                          "--extract); these cases are a fixed subset",
            "all_matched": summary,
        },
        "cases": cases,
    }
    JSON_PATH.write_text(json.dumps(doc, indent=1) + "\n")
    return doc


HEADER = """--  Generated by scripts/compression-vectors.py from tests/ref/kat-blocks.json.
--  Do not edit: rerun the script instead.
--
--  Published test vectors for Argon2's block compression G (RFC 9106
--  sections 3.5 and 3.6): blocks of the official reference's own
--  known-answer files (kats/argon2id, kats/argon2d, kats/argon2i, commit
--  f57e61e19229e23c4445b85494dbf7c07de721cb). Each is G of two other blocks
--  of the same dump: Expected = G (X, Y) when With_Xor is False, and
--  Expected = Old xor G (X, Y) when it is True (passes after the first).
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;

package Compression_Vectors is

   subtype Word is Interfaces.Unsigned_64;
   type Block is array (0 .. 127) of Word;

   type Vector is record
      Name     : String (1 .. %d);
      With_Xor : Boolean;
      X, Y     : Block;
      Old      : Block;
      Expected : Block;
   end record;

   Vectors : constant array (Positive range <>) of Vector :=
     [
""" % NAME_WIDTH


def ada_block(words):
    """A 128-word aggregate, three words a line, under 80 columns."""
    lines = []
    for i in range(0, 128, 3):
        chunk = words[i:i + 3]
        lines.append(", ".join("16#%s#" % w.upper() for w in chunk))
    return "         [" + ",\n          ".join(lines) + "]"


def render(doc):
    out = [HEADER]
    cases = doc["cases"]
    for n, c in enumerate(cases):
        name = c["name"].ljust(NAME_WIDTH)
        assert len(name) == NAME_WIDTH, "name too long: " + c["name"]
        out.append('      (Name     => "%s",\n' % name)
        out.append("       With_Xor => %s,\n" % ("True" if c["xor"]
                                                 else "False"))
        for field, key in (("X", "x"), ("Y", "y"), ("Old", "old"),
                           ("Expected", "expected")):
            tail = ("),\n" if n < len(cases) - 1 else ")\n") \
                if key == "expected" else ",\n"
            out.append("       %-8s =>\n%s%s" % (field,
                                                 ada_block(c[key]), tail))
    out.append("     ];\n\nend Compression_Vectors;\n")
    return "".join(out)


def check_doc(doc):
    bad = 0
    for c in doc["cases"]:
        x = [int(w, 16) for w in c["x"]]
        y = [int(w, 16) for w in c["y"]]
        old = [int(w, 16) for w in c["old"]]
        want = [int(w, 16) for w in c["expected"]]
        got = compress(x, y)
        if c["xor"]:
            got = [a ^ b for a, b in zip(old, got)]
        if got != want:
            print("case %s: G does not reproduce the published block"
                  % c["name"])
            bad += 1
        if len(x) != 128 or len(y) != 128 or len(old) != 128 \
                or len(want) != 128:
            print("case %s: wrong block length" % c["name"])
            bad += 1
    return bad


def main():
    args = sys.argv[1:]
    if args[:1] == ["--extract"]:
        if len(args) != 2:
            print(__doc__)
            return 2
        doc = extract(args[1])
    else:
        doc = json.loads(JSON_PATH.read_text())
    bad = check_doc(doc)
    text = render(doc)
    if args == ["--check"]:
        if bad:
            return 1
        if not ADS_PATH.exists() or ADS_PATH.read_text() != text:
            print("tests/src/compression_vectors.ads is stale: rerun "
                  "scripts/compression-vectors.py")
            return 1
        print("compression vectors: %d cases, current" % len(doc["cases"]))
        return 0
    if bad:
        return 1
    ADS_PATH.write_text(text)
    print("wrote %s (%d cases)" % (ADS_PATH.relative_to(ROOT),
                                   len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
