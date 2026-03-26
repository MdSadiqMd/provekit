#!/usr/bin/env python3
"""
Programmatic analysis of the collapsed flamegraph to compute
the exact impact of halving field multiplication time.

Reads the demangled collapsed stacks and:
1. Counts exact self-time samples per leaf function
2. Identifies every stack where mul_assign is the leaf
3. Traces the CALLER of mul_assign to attribute it precisely
4. Computes the exact speedup from halving mul_assign time
"""
import sys
from collections import defaultdict

INPUT = "/tmp/provekit_collapsed_demangled.txt"

# ── Parse collapsed stacks ──────────────────────────────────────────
leaf_counts = defaultdict(int)       # leaf function → sample count
mul_caller_counts = defaultdict(int) # caller-of-mul_assign → sample count
total_samples = 0
mul_assign_total = 0

# Also track inclusive: any stack containing mul_assign
stacks_with_mul = 0

with open(INPUT) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        # Format: "frame;frame;...;leaf COUNT"
        last_space = line.rfind(' ')
        if last_space < 0:
            continue
        stack_str = line[:last_space]
        try:
            count = int(line[last_space+1:])
        except ValueError:
            continue

        total_samples += count

        # Split into frames
        frames = stack_str.split(';')

        # Get leaf (last frame)
        leaf = frames[-1]
        # Strip binary prefix (e.g., "provekit-cli`symbol")
        if '`' in leaf:
            leaf = leaf.split('`', 1)[1]

        leaf_counts[leaf] += count

        # Check if mul_assign is in the leaf
        is_mul_leaf = ('mul_assign' in leaf and 'Mont' in leaf)

        if is_mul_leaf:
            mul_assign_total += count
            # Find the caller (second-to-last frame)
            if len(frames) >= 2:
                caller = frames[-2]
                if '`' in caller:
                    caller = caller.split('`', 1)[1]
                mul_caller_counts[caller] += count

        # Check inclusive
        if 'mul_assign' in stack_str and 'Mont' in stack_str:
            stacks_with_mul += count

# ── Output results ──────────────────────────────────────────────────
print(f"Total samples: {total_samples}")
print(f"mul_assign self-time samples: {mul_assign_total} ({100*mul_assign_total/total_samples:.1f}%)")
print(f"mul_assign inclusive samples: {stacks_with_mul} ({100*stacks_with_mul/total_samples:.1f}%)")
print()

# ── Top leaf functions ──────────────────────────────────────────────
print("=" * 80)
print("TOP 20 LEAF FUNCTIONS BY SELF-TIME")
print("=" * 80)
sorted_leaves = sorted(leaf_counts.items(), key=lambda x: -x[1])
for i, (func, cnt) in enumerate(sorted_leaves[:20], 1):
    # Shorten long names
    short = func
    if len(short) > 80:
        short = short[:77] + "..."
    print(f"  {i:2d}. {cnt:5d} ({100*cnt/total_samples:5.1f}%)  {short}")

# ── Callers of mul_assign ───────────────────────────────────────────
print()
print("=" * 80)
print("WHO CALLS mul_assign? (direct callers, by sample count)")
print("=" * 80)
sorted_callers = sorted(mul_caller_counts.items(), key=lambda x: -x[1])
caller_total = sum(c for _, c in sorted_callers)
for func, cnt in sorted_callers[:25]:
    short = func
    if len(short) > 90:
        short = short[:87] + "..."
    print(f"  {cnt:5d} ({100*cnt/caller_total:5.1f}% of mul)  {short}")

# ── Categorize callers ──────────────────────────────────────────────
print()
print("=" * 80)
print("mul_assign CALLERS GROUPED BY SUBSYSTEM")
print("=" * 80)

categories = defaultdict(int)
for func, cnt in mul_caller_counts.items():
    fl = func.lower()
    if 'ntt' in fl or 'cooley' in fl or 'twiddle' in fl:
        categories['NTT (Cooley-Tukey butterflies)'] += cnt
    elif 'skyscraper' in fl or 'compress' in fl or 'bn254_multiplier' in fl or 'montgomery_square' in fl:
        categories['Skyscraper hash (Montgomery square)'] += cnt
    elif 'mixed_dot' in fl:
        categories['mixed_dot (weight folding)'] += cnt
    elif 'sumcheck' in fl or 'eval_cubic' in fl or 'fold_map_reduce' in fl:
        categories['Sumcheck prover'] += cnt
    elif 'gamma' in fl or 'evaluate_gamma' in fl:
        categories['evaluate_gamma_block (ZK blinding)'] += cnt
    elif 'geometric' in fl:
        categories['geometric_accumulate'] += cnt
    elif 'sparse' in fl or 'hydrated' in fl or 'mul::{closure' in fl:
        categories['Sparse matrix ops (R1CS)'] += cnt
    elif 'eval_eq' in fl or 'eq_alpha' in fl:
        categories['eval_eq / eq_alpha'] += cnt
    elif 'fold_weight' in fl or 'fold_vector' in fl:
        categories['fold_weight/vector_to_mask_size'] += cnt
    elif 'prefix_covector' in fl or 'linear_form' in fl or 'accumulate' in fl:
        categories['PrefixCovector / LinearForm'] += cnt
    elif 'brillig' in fl or 'acvm' in fl or 'process_opcode' in fl or 'noirc' in fl:
        categories['Witness generation (ACVM)'] += cnt
    else:
        categories[f'Other: {func[:60]}'] += cnt

for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"  {cnt:5d} ({100*cnt/mul_assign_total:5.1f}% of mul)  {cat}")

# ── Compute exact speedup ──────────────────────────────────────────
print()
print("=" * 80)
print("FIELD MULTIPLICATION SPEEDUP ANALYSIS")
print("=" * 80)
print()
print(f"If mul_assign takes HALF as long:")
print(f"  mul_assign self-time samples: {mul_assign_total}")
print(f"  Samples saved (half of mul self-time): {mul_assign_total / 2:.0f}")
print(f"  Total samples: {total_samples}")
print()

# Method 1: Simple Amdahl's Law on self-time
saved_simple = mul_assign_total / 2
new_total_simple = total_samples - saved_simple
speedup_simple = total_samples / new_total_simple
pct_saved_simple = 100 * saved_simple / total_samples

print(f"METHOD 1: Amdahl's Law on self-time (upper bound)")
print(f"  Samples saved: {saved_simple:.0f}")
print(f"  Time reduction: {pct_saved_simple:.1f}%")
print(f"  Speedup: {speedup_simple:.3f}x")
print()

# Method 2: Exclude non-proving overhead (dyld, LZMA, kernel)
# Count overhead samples
overhead = 0
for func, cnt in leaf_counts.items():
    fl = func.lower()
    if any(k in fl for k in ['dyld', 'lzma', 'swtch_pri', 'psynch', 'ulock', 'mach_msg',
                              'mach_absolute', 'platform_mem', 'bzero', 'xzm_']):
        overhead += cnt

proving_samples = total_samples - overhead
saved_proving = mul_assign_total / 2
pct_saved_proving = 100 * saved_proving / proving_samples

print(f"METHOD 2: Proving-only (excluding I/O + OS overhead)")
print(f"  Overhead samples: {overhead} ({100*overhead/total_samples:.1f}%)")
print(f"  Proving samples: {proving_samples}")
print(f"  Samples saved: {saved_proving:.0f}")
print(f"  Proving time reduction: {pct_saved_proving:.1f}%")
print(f"  Proving speedup: {proving_samples / (proving_samples - saved_proving):.3f}x")
print()

# Method 3: Wall-clock mapping
# prove_with_witness = 1400 ms from SpanStats
prove_ms = 1400.0
total_wall = 2140.0  # total prove command wall-clock
io_ms = total_wall - prove_ms  # I/O overhead

# mul_assign fraction of proving-only samples
mul_frac_of_proving = mul_assign_total / proving_samples
mul_ms = mul_frac_of_proving * prove_ms
saved_ms = mul_ms / 2
new_prove_ms = prove_ms - saved_ms
new_total_ms = new_prove_ms + io_ms

print(f"METHOD 3: Wall-clock mapping (SpanStats-calibrated)")
print(f"  prove_with_witness: {prove_ms:.0f} ms")
print(f"  I/O overhead: {io_ms:.0f} ms")
print(f"  mul_assign fraction of proving: {100*mul_frac_of_proving:.1f}%")
print(f"  mul_assign time in proving: {mul_ms:.0f} ms")
print(f"  Time saved (half mul): {saved_ms:.0f} ms")
print(f"  New prove_with_witness: {new_prove_ms:.0f} ms")
print(f"  New total prove command: {new_total_ms:.0f} ms")
print(f"  Proving speedup: {prove_ms / new_prove_ms:.3f}x")
print(f"  End-to-end speedup: {total_wall / new_total_ms:.3f}x")
print()

# ── Cross-validation ────────────────────────────────────────────────
print("=" * 80)
print("CROSS-VALIDATION")
print("=" * 80)
print()
print("Sanity check: mul_assign self-time vs inclusive time")
print(f"  Self-time: {mul_assign_total} samples ({100*mul_assign_total/total_samples:.1f}%)")
print(f"  Inclusive:  {stacks_with_mul} samples ({100*stacks_with_mul/total_samples:.1f}%)")
print(f"  Ratio (self/inclusive): {mul_assign_total/stacks_with_mul:.2f}")
print(f"  → This means {100*mul_assign_total/stacks_with_mul:.0f}% of time in stacks containing")
print(f"    mul_assign is actually spent IN mul_assign (not in its callers' other work)")
print()
print("If mul_assign were infinitely fast (0 ns):")
saved_max = mul_assign_total
print(f"  Max samples saved: {saved_max}")
print(f"  Max proving time reduction: {100*saved_max/proving_samples:.1f}%")
print(f"  Max proving speedup: {proving_samples / (proving_samples - saved_max):.3f}x")
print(f"  Max end-to-end speedup: {total_samples / (total_samples - saved_max):.3f}x")
