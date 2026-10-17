#!/usr/bin/env bash
# Tests scripts/zeroed-at-return.awk, the parser check-h0-object.sh uses,
# against the disassembly formats CI meets: GNU objdump (Linux, Windows)
# and LLVM objdump (macOS), on x86-64 and AArch64. That includes AArch64
# immediates, which are written "#0" like an x86 comment, and the Mach-O
# section-start aliases (ltmp0) that label a function's first address.
#
# Usage: scripts/test-zeroed-at-return.sh

set -euo pipefail
cd "$(dirname "$0")/.."

pass=0
bad=0
# Runs the parser on stdin for function $2; compares with $3.
expect () {
  local label=$1 fn=$2 want=$3 got
  got=$(awk -v fn="$fn" -f scripts/zeroed-at-return.awk)
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    echo "FAILED: $label"
    echo "  want: $want"
    echo "  got:  $got"
    bad=$((bad + 1))
  fi
}

expect "x86-64, GNU objdump, with a # comment" probe \
  'ret: r8 rax rdx xmm0 xmm1' <<'EOF'
0000000000000000 <probe>:
   0:	mov    0x0(%rip),%rax        # 7 <probe+0x7>
   7:	call   c <probe+0xc>
   c:	xor    %eax,%eax
   e:	xor    %edx,%edx
  10:	pxor   %xmm0,%xmm0
  14:	pxor   %xmm1,%xmm1
  18:	xor    %r8d,%r8d
  1b:	ret
EOF

expect "x86-64: zeroing before a call doesn't count" probe \
  'ret: rax' <<'EOF'
0000000000000000 <probe>:
   0:	pxor   %xmm0,%xmm0
   4:	call   9 <probe+0x9>
   9:	xor    %eax,%eax
   b:	ret
EOF

expect "x86-64, LLVM objdump, Mach-O underscore" probe \
  'ret: rax rcx xmm2' <<'EOF'
0000000000000000 <_probe>:
       0:	xorl	%eax, %eax
       2:	xorl	%ecx, %ecx
       4:	pxor	%xmm2, %xmm2
       8:	retq
EOF

expect "AArch64, GNU objdump (Linux)" probe \
  'ret: v0 v1 x0 x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	mov	x1, #0x0                   	// #0
   8:	movi	v0.4s, #0x0
   c:	movi	v1.2d, #0x0
  10:	ret
EOF

expect "AArch64, LLVM objdump, Mach-O, alias before the symbol" probe \
  'ret: v0 v31 x0 x17' <<'EOF'
0000000000000000 <ltmp0>:
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	mov	x17, #0
       8: 	movi.2d	v0, #0000000000000000
       c: 	movi.16b	v31, #0
      10: 	ret
EOF

expect "AArch64, LLVM objdump, Mach-O, alias after the symbol" probe \
  'ret: v0 x0' <<'EOF'
0000000000000000 <_probe>:
0000000000000000 <ltmp0>:
       0: 	mov	x0, #0
       4: 	movi	d0, #0000000000000000
       8: 	ret
EOF

expect "AArch64: a later alias at another address ends the function" probe \
  'ret: x0' <<'EOF'
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	ret
0000000000000008 <ltmp1>:
       8: 	mov	x1, #0
       c: 	ret
EOF

expect "AArch64: a call ends the zeroed span" probe \
  'ret: x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0
   4:	bl	0 <other>
   8:	mov	x1, #0x0
   c:	ret
EOF

expect "no such function" probe 'none' <<'EOF'
0000000000000000 <other>:
   0:	ret
EOF

# A later write to a zeroed register un-zeroes it.
expect "x86-64: a load into a zeroed register" probe 'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %edx,%edx
   4:	mov    (%rdi),%rax
   7:	ret
EOF

expect "x86-64: a write to an 8-bit view (ah) of a zeroed register" probe \
  'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	mov    $0x1,%ah
   4:	ret
EOF

expect "AArch64: ldr and ldp into zeroed registers" probe 'ret: x2' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	mov	x1, #0x0                   	// #0
   8:	mov	x2, #0x0                   	// #0
   c:	mov	x3, #0x0                   	// #0
  10:	ldp	x0, x1, [x2]
  14:	ldr	w3, [x2, #8]
  18:	ret
EOF

expect "AArch64: movk and an element write un-zero" probe 'ret:' <<'EOF'
0000000000000000 <_probe>:
       0: 	mov	x0, #0
       4: 	movi.2d	v0, #0000000000000000
       8: 	movk	x0, #0x1, lsl #16
       c: 	mov.s	v0[1], w1
      10: 	ret
EOF

expect "store writeback writes its base, a plain store nothing" probe \
  'ret: x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	mov	x1, #0x0                   	// #0
   8:	str	xzr, [x0, #-8]!
   c:	str	x2, [x1]
  10:	ret
EOF

# Width: an 8- or 16-bit x86 clear leaves the upper bits; 32-bit and
# 64-bit clears, and every AArch64 register view but one element, clear
# the whole register.
expect "x86-64: 8- and 16-bit clears don't count" probe \
  'ret: r10 rdx rsi' <<'EOF'
0000000000000000 <probe>:
   0:	xorw   %ax,%ax
   3:	xorb   %cl,%cl
   5:	xor    %r8w,%r8w
   9:	xor    %r9b,%r9b
   c:	xor    %edx,%edx
   e:	xor    %r10d,%r10d
  11:	xorq   %rsi,%rsi
  14:	ret
EOF

expect "x86-64, LLVM: mov of zero counts in 32 bits, not in 16" probe \
  'ret: rax' <<'EOF'
0000000000000000 <_probe>:
       0:	movl	$0, %eax
       5:	movw	$0, %cx
       9:	retq
EOF

expect "AArch64: w, s, d and 64-bit vector writes clear the register" probe \
  'ret: v2 v3 v4 v5 x0 x1' <<'EOF'
0000000000000000 <probe>:
   0:	mov	w0, #0x0                   	// #0
   4:	eor	w1, w1, w1
   8:	fmov	s2, wzr
   c:	movi	d3, #0x0
  10:	fmov	d4, xzr
  14:	movi	v5.8b, #0x0
  18:	mov	v6.s[1], wzr
  1c:	ret
EOF

expect "a copy of a zeroed register is zero" probe \
  'ret: rax rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	mov    %eax,%edx
   4:	movaps %xmm0,%xmm1
   7:	ret
EOF

# Branch targets: a path that jumps past the zeroing skips it.
expect "AArch64, GNU: a branch to the ret skips the zeroing" probe \
  'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	cbz	x1, c <probe+0xc>
   4:	mov	x0, #0x0                   	// #0
   8:	nop
   c:	ret
EOF

expect "AArch64, LLVM: a branch into the zeroing" probe 'ret: x1' <<'EOF'
0000000000000000 <_probe>:
       0: 	tbz	w2, #3, 0x8 <_probe+0x8>
       4: 	mov	x0, #0
       8: 	mov	x1, #0
       c: 	ret
EOF

expect "AArch64, LLVM: a target labelled by the Mach-O alias" probe \
  'ret:' <<'EOF'
0000000000000000 <ltmp0>:
0000000000000000 <_probe>:
       0: 	cbnz	x1, 0x8 <ltmp0+0x8>
       4: 	mov	x0, #0
       8: 	ret
EOF

expect "x86-64: a conditional jump to the ret" probe 'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	test   %edi,%edi
   2:	je     8 <probe+0x8>
   4:	xor    %eax,%eax
   6:	xor    %edx,%edx
   8:	ret
EOF

expect "a branch target before the zeroing doesn't matter" probe \
  'ret: x0 x1' <<'EOF'
0000000000000000 <_probe>:
       0: 	cmp	x1, x0
       4: 	b.hs	0x10 <_probe+0x10>
       8: 	str	xzr, [x0, #-0x8]!
       c: 	b.lo	0x8 <_probe+0x8>
      10: 	ldp	x29, x30, [sp], #0x20
      14: 	mov	x0, #0
      18: 	mov	x1, #0
      1c: 	ret
EOF

expect "a jump to another symbol (a cold part) is not a target here" probe \
  'ret: rax rdx' <<'EOF'
0000000000000000 <probe>:
   0:	test   %edi,%edi
   2:	je     6 <probe.cold+0x6>
   4:	xor    %eax,%eax
   6:	xor    %edx,%edx
   8:	ret
EOF

expect "an indirect jump: any instruction may be a target" probe 'ret:' <<'EOF'
0000000000000000 <probe>:
   0:	jmp    *%rcx
   2:	xor    %eax,%eax
   4:	ret
EOF

# Epilogues: restoring callee-saved registers, sp, fp or lr after the
# zeroing keeps it.
expect "x86-64: pop, add to rsp and leave after the zeroing" probe \
  'ret: rax' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %ecx,%ecx
   4:	add    $0x8,%rsp
   8:	pop    %rbx
   9:	pop    %rbp
   a:	pop    %rcx
   b:	leave
   c:	ret
EOF

expect "AArch64: ldp of fp and lr, add to sp and autiasp after the zeroing" \
  probe 'ret: v0 x0' <<'EOF'
0000000000000000 <probe>:
   0:	mov	x0, #0x0                   	// #0
   4:	movi	v0.2d, #0x0
   8:	ldp	x29, x30, [sp], #32
   c:	ldr	x19, [sp, #16]
  10:	add	sp, sp, #0x30
  14:	autiasp
  18:	ret
EOF

expect "x86-64, GNU (Linux): endbr64 and the x87 clearing keep the span" \
  probe 'ret: rax xmm0' <<'EOF'
0000000000000000 <probe>:
   0:	endbr64
   4:	xor    %eax,%eax
   6:	fldz
   8:	fstp   %st(0)
   a:	pxor   %xmm0,%xmm0
   e:	ret
EOF

expect "an instruction with unknown destinations empties the span" probe \
  'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	cpuid
   4:	xor    %edx,%edx
   6:	ret
EOF

expect "x86-64: a string operation writes rax, rcx, rdi and rsi" probe \
  'ret: rdx' <<'EOF'
0000000000000000 <probe>:
   0:	xor    %eax,%eax
   2:	xor    %ecx,%ecx
   4:	xor    %edx,%edx
   6:	rep stos %rax,%es:(%rdi)
   9:	repz ret
EOF

echo "zeroed-at-return: $pass passed, $bad failed"
[ "$bad" -eq 0 ]
