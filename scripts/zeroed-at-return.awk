# Reads `objdump -d --no-show-raw-insn` output (GNU objdump or LLVM's)
# and prints, for each return instruction of the function named FN, the
# registers that hold zero on every path that reaches it from the
# function's last call or branch. One line per return:
#
#   ret: rax rcx rdx r8 ... xmm0 ...
#
# Used by check-h0-object.sh to confirm that GCC's zero_call_used_regs
# ("all") clears every call-used register before a hardened entry point
# returns, including registers only its callees used.
#
# How a return's list is built (a span is the run of instructions that
# ends at the return):
#   * the span starts empty after each call, branch or return, and at each
#     instruction some branch of the function targets: on a path that
#     jumps there, nothing before it ran. The targets are collected first,
#     from the direct branches' operands (GNU's "10 <fn+0x10>" and LLVM's
#     "0x10 <fn+0x10>"); a target labelled with another symbol (a cold
#     part, another function) is not in this function. A function with an
#     indirect jump (jmp *%rax, br x1), whose targets are unknown, has an
#     empty list at every return;
#   * a register enters the span when an instruction zeroes all of it: an
#     xor, pxor or eor of the register with itself, a mov, movi or fmov of
#     zero into it, vzeroall, or a copy of a register already in the span.
#     On x86-64 a 32-bit write zero-extends (xor %eax,%eax clears rax) but
#     an 8- or 16-bit one does not (xorw %ax,%ax leaves bits 16-63). On
#     AArch64 a write to w<n> zero-extends to x<n>, and every write to a
#     SIMD&FP register by its scalar (b/h/s/d/q) or vector (v<n>.<T>) name
#     clears the rest of the 128-bit register (movi d0,#0 and fmov s0,wzr
#     both zero v0); a write of one element (v0.s[1], ins) does not;
#   * a register leaves the span when a later instruction writes it (any
#     view of it): the destination of an x86 AT&T instruction (its last
#     operand) or of an AArch64 one (its first; both for ldp), the base
#     register of a pre- or post-indexed access, and the implicit
#     destinations of pop, leave, mul, div and the like. A store writes no
#     register but its base on writeback; a compare writes none. An
#     instruction whose destinations cannot be told (cpuid, syscall, an
#     undecoded byte, a mnemonic with no operands outside a short list of
#     known forms) empties the span. So an epilogue that restores only
#     callee-saved registers, sp, fp or lr keeps the call-used registers
#     zeroed before it, and a load into a zeroed register removes it.
#
# Not seen: a jump into the function from elsewhere. A cold part
# (<fn>.cold) that jumps back into its function is a separate symbol, and
# in an object file its jump shows a relocation placeholder, not the
# target; a function whose cold part rejoins it is analysed as if the cold
# path did not exist (reading the relocations, objdump -r, would close
# that). check-h0-object.sh lists every cold part and checks the returns
# in it.
#
# Registers are normalised so that the x86-64 and AArch64 spellings of one
# register compare equal: al/ah/ax/eax/rax -> rax, r8b/r8w/r8d -> r8,
# xmm/ymm/zmm -> xmm, w/x -> x, and the AArch64 SIMD&FP register views
# v/q/d/s/h/b -> v.
#
# When FN is not in the input, or has no return, the output is "none".
#
# Usage: awk -v fn=argon2__compression__compress -f zeroed-at-return.awk dis.txt
#        (fn matches the symbol with or without a leading underscore)
#
# Copyright (c) 2026, Matt Doughty
# SPDX-License-Identifier: BSD-3-Clause

function norm(r) {
  r = tolower(r)
  gsub(/[%{} \t]/, "", r)
  sub(/\[[0-9]+\]$/, "", r)                 # AArch64 element: v0[1] (LLVM)
  sub(/\..*$/, "", r)                       # AArch64 arrangement: v0.16b
  if (r ~ /^[er]?(ax|bx|cx|dx|si|di|bp|sp)$/) { sub(/^[er]/, "", r); return "r" r }
  if (r ~ /^[abcd][lh]$/) { return "r" substr(r, 1, 1) "x" }
  if (r ~ /^(sil|dil|bpl|spl)$/) { return "r" substr(r, 1, 2) }
  if (r ~ /^r[0-9]+[dwbl]?$/) { sub(/[dwbl]$/, "", r); return r }
  if (r ~ /^[xyz]mm[0-9]+$/) { sub(/^[xyz]/, "x", r); return r }
  if (r ~ /^[wx][0-9]+$/) { sub(/^[wx]/, "x", r); return r }
  if (r ~ /^[vqdshb][0-9]+$/) { sub(/^[vqdshb]/, "v", r); return r }
  if (r == "lr") return "x30"
  if (r == "fp") return "x29"
  if (r == "wsp") return "rsp"
  if (r == "wzr") return "xzr"
  return r
}

# Whether operand o names a register (not memory, an immediate or a label).
function is_reg(o) {
  if (arch == "x86") return o ~ /^%[a-z0-9]+(\([0-9]\))?(\{[^}]*\})*$/
  return o ~ /^(x[0-9]+|w[0-9]+|[vqdshb][0-9]+|z[0-9]+|p[0-9]+|sp|wsp|xzr|wzr|lr|fp)(\.[0-9]*[bhsdq])?(\[[0-9]+\])?$/
}

# Whether a write to register operand o sets the whole register (so a
# write of zero zeroes it): not an 8- or 16-bit x86 view, not one element
# of an AArch64 vector.
function is_whole(o,    r) {
  r = tolower(o)
  gsub(/[%{} \t]/, "", r)
  if (arch == "x86")
    return !(r ~ /^([abcd][xlh]|si|di|bp|sp|sil|dil|bpl|spl)$/ || r ~ /^r[0-9]+[wbl]$/)
  return r !~ /\[[0-9]+\]$/
}

function is_zero_imm(s) {
  gsub(/[ \t]/, "", s)
  return s ~ /^[#$]?(0x)?0+(\.0+)?$/ || s == "xzr" || s == "wzr"
}

# Splits operand string s at the commas outside (), [] and {} into ops[1..];
# returns the count.
function split_ops(s,    n, i, c, depth, cur) {
  n = 0; depth = 0; cur = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "(" || c == "[" || c == "{") depth++
    else if (c == ")" || c == "]" || c == "}") depth--
    if (c == "," && depth == 0) { ops[++n] = cur; cur = ""; continue }
    cur = cur c
  }
  if (cur ~ /[^ \t]/) ops[++n] = cur
  for (i = 1; i <= n; i++) gsub(/^[ \t]+|[ \t]+$/, "", ops[i])
  return n
}

# Adds the registers written by the register operand or register list o
# to wr[].
function add_written(o,    k, a, i) {
  if (o ~ /^\{/) {                          # AArch64 list: { v0.16b, v1.16b }[1]
    sub(/\}.*$/, "", o); sub(/^\{/, "", o)
    k = split(o, a, ",")
    for (i = 1; i <= k; i++) { gsub(/^[ \t]+|[ \t]+$/, "", a[i]); wr[norm(a[i])] = 1 }
    return
  }
  if (is_reg(o)) wr[norm(o)] = 1
}

# Classifies instruction (base mnemonic m, operands ops[1..n]). Fills wr[]
# with the registers it writes and returns "ok", or returns "zero" with
# zr set to the register it zeroes whole, or returns "unknown".
function classify(m, n,    i, r, same, src) {
  for (r in wr) delete wr[r]
  zr = ""
  if (arch == "x86") {
    # Zeroing idioms.
    if ((m ~ /^v?p?xor(b|w|l|q|ps|pd|d)?$/ || m ~ /^kxor[bwdq]$/) && n >= 2) {
      r = norm(ops[1]); same = is_reg(ops[1])
      for (i = 2; i <= n; i++) if (!is_reg(ops[i]) || norm(ops[i]) != r) same = 0
      if (same) {
        if (is_whole(ops[n])) { zr = r; return "zero" }
        wr[r] = 1; return "ok"
      }
    }
    if (m == "vzeroall") { zr = "*vzeroall"; return "zero" }
    if (m ~ /^mov[lq]?$/ && n == 2 && is_reg(ops[2]) && is_whole(ops[2]) \
        && is_zero_imm(ops[1])) { zr = norm(ops[2]); return "zero" }
    # A copy of a zeroed register.
    if (m ~ /^(mov[lqd]?|v?mov(aps|apd|ups|upd|dqa|dqu)|vmovdq[au](32|64)|v?movq|v?movd)$/ \
        && n == 2 && is_reg(ops[1]) && is_reg(ops[2]) && is_whole(ops[1]) \
        && is_whole(ops[2]) && (norm(ops[1]) in span)) {
      zr = norm(ops[2]); return "zero"
    }
    # String operations write rdi, rsi, rcx and rax implicitly.
    if (string_op) { wr["rax"] = wr["rcx"] = wr["rdi"] = wr["rsi"] = 1; return "ok" }
    if (n == 0) {
      if (m ~ /^(nop[wlq]?|endbr(32|64)|vzeroupper|emms|femms|fninit|finit|lfence|mfence|sfence|pause|int3|ud2|hlt|cld|std|clc|stc|cmc|fld[z1]|fldpi|fldl2[et]|fldlg2|fldln2|wait|fwait)$/)
        return "ok"
      if (m ~ /^leave[lqw]?$/) { wr["rbp"] = wr["rsp"] = 1; return "ok" }
      if (m ~ /^(cltq|cdqe|cwtl|cbtw|cwde|cbw)$/) { wr["rax"] = 1; return "ok" }
      if (m ~ /^(cqto|cqo|cltd|cdq|cwtd|cwd)$/) { wr["rax"] = wr["rdx"] = 1; return "ok" }
      return "unknown"
    }
    if (m ~ /^(cmp[bwlq]?|test[bwlq]?|bt[wlq]?|v?u?comis[sd]|v?ptest|nop[wlq]?|prefetch[a-z0-9]*|clflush[a-z]*)$/)
      return "ok"
    if (m ~ /^push[wlq]?$/) { wr["rsp"] = 1; return "ok" }
    if (m ~ /^pop[wlq]?$/) { wr["rsp"] = 1; add_written(ops[1]); return "ok" }
    if (m ~ /^(i?mul|i?div)[bwlq]?$/ && n == 1) {
      wr["rax"] = wr["rdx"] = 1; return "ok"
    }
    if (m ~ /^(xchg|xadd)[bwlq]?$/) {
      for (i = 1; i <= n; i++) add_written(ops[i])
      return "ok"
    }
    if (m ~ /^cmpxchg[bwlq]?$/) { wr["rax"] = 1; add_written(ops[n]); return "ok" }
    if (m ~ /^cmpxchg(8|16)b$/) { wr["rax"] = wr["rdx"] = 1; return "ok" }
    if (m ~ /^mulx[lq]?$/) { add_written(ops[n]); add_written(ops[n - 1]); return "ok" }
    if (m ~ /^v?pcmp[ei]stri$/) { wr["rcx"] = 1; return "ok" }
    if (m ~ /^v?pcmp[ei]strm$/) { wr["xmm0"] = 1; return "ok" }
    if (m ~ /^(cpuid|rdtscp?|rdpmc|rdmsr|syscall|sysenter|xgetbv|in[bwl]?|xlatb?|int|into|fxrstor(64)?|xrstors?(64)?)$/)
      return "unknown"
    add_written(ops[n])
    return "ok"
  }
  # AArch64.
  if ((m == "mov" || m == "movz" || m == "movi" || m == "fmov") && n == 2 \
      && is_reg(ops[1])) {
    if (is_zero_imm(ops[2])) {
      if (is_whole(ops[1])) { zr = norm(ops[1]); return "zero" }
      wr[norm(ops[1])] = 1; return "ok"
    }
    if (m != "movi" && is_reg(ops[2]) && is_whole(ops[1]) && is_whole(ops[2]) \
        && (norm(ops[2]) in span)) { zr = norm(ops[1]); return "zero" }
  }
  if (m == "eor" && n == 3 && is_reg(ops[1])) {
    r = norm(ops[1])
    if (is_reg(ops[2]) && is_reg(ops[3]) && norm(ops[2]) == r && norm(ops[3]) == r) {
      if (is_whole(ops[1])) { zr = r; return "zero" }
      wr[r] = 1; return "ok"
    }
  }
  if (m == "orr" && n == 3 && is_reg(ops[1]) && is_reg(ops[2]) && is_reg(ops[3]) \
      && norm(ops[2]) == norm(ops[3]) && is_whole(ops[1]) && (norm(ops[2]) in span)) {
    zr = norm(ops[1]); return "zero"
  }
  # The base register of a pre-indexed ([x0, #8]!) or post-indexed
  # ([x0], #8) access is written.
  for (i = 1; i <= n; i++) {
    if (ops[i] ~ /^\[/ && (ops[i] ~ /!$/ || i < n)) {
      r = ops[i]; sub(/^\[[ \t]*/, "", r); sub(/[ \t]*[],].*$/, "", r)
      wr[norm(r)] = 1
    }
  }
  if (n == 0) {
    if (m ~ /^(nop|isb|csdb|sb|ssbb|pssbb|yield|wfe|wfi|sev|sevl|esb|clrex|udf|brk)$/)
      return "ok"
    if (m ~ /^(paci|auti)[ab](sp|z)$/ || m == "xpaclri") { wr["x30"] = 1; return "ok" }
    if (m ~ /^(paci|auti)[ab]1716$/) { wr["x17"] = 1; return "ok" }
    return "unknown"
  }
  if (m ~ /^(cmp|cmn|tst|fcmpe?|ccmp|ccmn|fccmpe?|dsb|dmb|bti|hint|prfu?m|msr|dc|ic|tlbi|brk|udf|hlt)$/)
    return "ok"
  if (m ~ /^(svc|hvc|smc)$/) return "unknown"
  if (m ~ /^(casp?|swp|ld(add|clr|eor|set|smax|smin|umax|umin))(a|al|l)?[bh]?$/) {
    for (i = 1; i <= n; i++) add_written(ops[i])
    return "ok"
  }
  if (m ~ /^stl?xr[bh]?$/ || m ~ /^stl?xp$/) { add_written(ops[1]); return "ok" }
  if (m ~ /^st/) return "ok"
  if (m ~ /^ld[a-z]*p(sw)?$/) { add_written(ops[1]); add_written(ops[2]); return "ok" }
  add_written(ops[1])
  return "ok"
}

function reset_span(    k) { for (k in span) delete span[k] }

function emit(    k, list, sorted, n, i, j, t) {
  n = 0
  for (k in span) { n++; sorted[n] = k }
  for (i = 2; i <= n; i++) {                # insertion sort, for stable output
    t = sorted[i]; j = i - 1
    while (j >= 1 && sorted[j] > t) { sorted[j + 1] = sorted[j]; j-- }
    sorted[j + 1] = t
  }
  list = ""
  for (i = 1; i <= n; i++) list = list " " sorted[i]
  print "ret:" list
  found_ret = 1
}

# A hex address in a canonical form: no 0x, no leading zeros, lower case.
function canon(a) {
  a = tolower(a)
  sub(/^0x/, "", a)
  sub(/^0+/, "", a)
  return a == "" ? "0" : a
}

# Parses instruction text t into mnem (the mnemonic, without prefixes or,
# for AArch64 LLVM, the arrangement suffix: movi.2d -> movi) and ops[1..];
# returns the operand count. Sets string_op for an x86 string operation.
function parse(t,    w, n, i) {
  string_op = 0
  for (;;) {
    w = t; sub(/[ \t].*$/, "", w)
    if (w ~ /^(rep|repz|repe|repnz|repne)$/) string_op = 1
    else if (!(w ~ /^(lock|notrack|bnd|data16|data32|addr16|addr32|cs|ds|ss|es|fs|gs|rex(\.[wrxb]+)?|xacquire|xrelease|\{vex3?\}|\{evex\})$/))
      break
    if (t !~ /[ \t]/) break
    sub(/^[^ \t]+[ \t]+/, "", t)
  }
  mnem = tolower(w)
  t = substr(t, length(w) + 1)
  sub(/^[ \t]+/, "", t)
  n = split_ops(t)
  if (mnem ~ /^(ret[lqw]?|nop[wlq]?)$/) string_op = 0
  if (mnem ~ /^(stos|lods|scas|cmps|movs|ins|outs)[bwlq]?$/) {
    string_op = 1
    for (i = 1; i <= n; i++) if (ops[i] ~ /%[xyz]mm/) string_op = 0
  }
  if (mnem !~ /^bc?\./) sub(/\..*$/, "", mnem)
  return n
}

# Whether the target symbol s (from "<s+0x10>") is this function.
function own_symbol(s,    k, a, i) {
  sub(/\+.*$/, "", s)
  sub(/^_/, "", s)
  k = split(fn_names, a, " ")
  for (i = 1; i <= k; i++) {
    sub(/^_/, "", a[i])
    if (a[i] == s) return 1
  }
  return 0
}

# Analyses the buffered function: insn_addr[1..ninsn], insn_text[1..ninsn].
function analyse(    i, n, k, targets, indirect, last, a, sym, kind, isbranch) {
  arch = "aarch64"
  for (i = 1; i <= ninsn; i++) if (insn_text[i] ~ /%/) { arch = "x86"; break }
  indirect = 0
  for (i = 1; i <= ninsn; i++) {
    n = parse(insn_text[i])
    if (!is_branch(mnem)) continue
    last = n > 0 ? ops[n] : ""
    if (mnem ~ /^bra/ || mnem == "br" || last ~ /^\*/ || (arch == "aarch64" && is_reg(last)) \
        || (arch == "x86" && last ~ /%/)) { indirect = 1; continue }
    a = last; sub(/[ \t].*$/, "", a)
    if (a !~ /^(0x)?[0-9a-fA-F]+$/) { indirect = 1; continue }
    sym = ""
    if (last ~ /<[^>]+>/) { sym = last; sub(/^[^<]*</, "", sym); sub(/>.*$/, "", sym) }
    if (sym == "" || own_symbol(sym)) targets[canon(a)] = 1
  }
  reset_span()
  for (i = 1; i <= ninsn; i++) {
    if (indirect || (canon(insn_addr[i]) in targets)) reset_span()
    n = parse(insn_text[i])
    if (mnem ~ /^ret(l|q|w|aa|ab)?$/) { emit(); reset_span(); continue }
    if (is_branch(mnem) || is_call(mnem)) { reset_span(); continue }
    kind = classify(mnem, n)
    if (kind == "unknown") { reset_span(); continue }
    for (k in wr) delete span[k]
    if (kind == "zero") {
      if (zr == "*vzeroall") { for (k = 0; k < 16; k++) span["xmm" k] = 1 }
      else span[zr] = 1
    }
  }
}

function is_branch(m) {
  if (arch == "x86") return m ~ /^(l?jmp[lqw]?|j[a-z]+|loop[a-z]*|xbegin)$/
  return m ~ /^(b|bc?\.[a-z]+|cbn?z|tbn?z|br|bra[ab]z?)$/
}

function is_call(m) {
  if (arch == "x86") return m ~ /^l?call[lqw]?$/
  return m ~ /^(bl|blr|blra[ab]z?)$/
}

function finish() {
  if (inside && ninsn > 0) analyse()
  ninsn = 0
}

BEGIN { inside = 0; found_ret = 0; last_addr = ""; insn_since_header = 1; ninsn = 0; group = "" }

{ sub(/\r$/, "") }                           # output with CRLF line ends

# A symbol header: "0000000000000000 <name>:". Several can label one
# address: on Mach-O, LLVM's objdump prints section-start aliases
# (ltmp0, ...) next to the function's own symbol, in either order. Headers
# at the same address with no instruction between them are one place, so
# the function is "inside" if any of them is its name, and a branch target
# labelled with any of them is in the function.
/^[0-9a-fA-F]+ <[^>]+>:[ \t]*$/ {
  addr = $1
  name = $0
  sub(/^[0-9a-fA-F]+ </, "", name); sub(/>:[ \t]*$/, "", name)
  this = (name == fn || name == "_" fn)
  if (addr == last_addr && !insn_since_header) {
    now = inside || this
    group = group " " name
  } else {
    now = this
    group = name
  }
  if (inside && !now) finish()
  if (now && !inside) ninsn = 0
  inside = now
  if (inside) fn_names = group
  last_addr = addr
  insn_since_header = 0
  next
}

/^[ \t]+[0-9a-fA-F]+:/ { insn_since_header = 1 }

inside && /^[ \t]+[0-9a-fA-F]+:/ {
  line = $0
  a = line; sub(/^[ \t]+/, "", a); sub(/:.*$/, "", a)
  sub(/^[ \t]+[0-9a-fA-F]+:[ \t]*/, "", line)
  # Trailing comments. AArch64 disassemblers comment with // (GNU) or ;
  # (LLVM). On x86-64 a comment is # after a gap of columns. A # straight
  # after an operand separator is an AArch64 immediate (mov x0, #0), never
  # a comment.
  sub(/[ \t]*(\/\/|;).*$/, "", line)
  sub(/[ \t][ \t]+#.*$/, "", line)
  if (line == "") next
  ninsn++
  insn_addr[ninsn] = a
  insn_text[ninsn] = line
  next
}

END {
  finish()
  if (!found_ret) print "none"
}
