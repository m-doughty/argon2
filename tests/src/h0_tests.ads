--  Tests of Argon2.H0.Compute, RFC 9106 section 3.2's H0.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package H0_Tests is

   --  The default run: RFC 9106's three published pre-hashing digests,
   --  a table computed by CPython's hashlib (scripts/h0-vectors.py), and
   --  differential tests against two C oracles over the vendored reference
   --  BLAKE2b (src/h0_oracle.c): its own serialisation of the inputs,
   --  and a one-shot hash of the serialisation this test builds. Edge
   --  cases: empty and one-byte inputs, the 4096-byte chunk boundaries,
   --  arbitrary and extreme array bounds, distinct parameter values, m
   --  not a multiple of 4p.
   procedure Run;

   --  The long test (test_main --long): the largest H0 input, four inputs
   --  of 2**32 - 1 bytes (2**34 + 36 bytes in all), through the public
   --  Compute, against the C oracle regenerating the same bytes.
   procedure Run_Long;

   function Passed return Natural;
   function Failed return Natural;

end H0_Tests;
