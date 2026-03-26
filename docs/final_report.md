# ProveKit Prover Performance Analysis: `complete_age_check`

> Circuit: 631,480 constraints, 1,248,358 witnesses (dual-split w1/w2)
> Machine: Apple Silicon arm64, 16 cores, 48 GB RAM
> Tooling: `cargo build --release`, macOS `sample` 1 kHz profiler, `SpanStats` tracing, `samply`
> Charts: `docs/charts/*.svg` · Flamegraph: `docs/flamegraphs/flamegraph_prove.svg`

---

## 1. Where the Prover Spends Its Time

![Proving Pipeline](charts/1_pipeline.svg)

The proving computation (`prove_with_witness`) takes **1,400 ms**. The dominant phase is `prove_noir` at 830 ms (59%), which runs two full WHIR ZK proofs — one per witness split. The two polynomial commitment phases (commit w1 + commit w2) together take 360 ms (26%). Witness generation is 157 ms (11%).

The total `prove` command takes 2,140 ms wall-clock, with 570 ms spent on XZ-decompressing the prover key and 10 ms writing the proof.

### CPU Time by Subsystem (from 7,600 flamegraph samples)

![CPU Subsystems](charts/2_cpu_subsystems.svg)

| Subsystem | CPU % | What it does |
|-----------|-------|--------------|
| `ark_ff::mul_assign` | 28.1% | BN254 4-limb Montgomery multiplication |
| Skyscraper hash | 19.0% | Merkle tree hashing (S-box + SIMD Montgomery square) |
| NTT compute | 15.2% | Cooley-Tukey FFT for Reed-Solomon encoding |
| NTT transpose | 5.3% | Memory-bound data layout shuffling (32 MB) |
| mixed_dot | 6.1% | Weight folding dot products |
| Sumcheck | 5.5% | Polynomial evaluation over boolean hypercube |
| I/O + OS overhead | 15.8% | LZMA decompression, dyld init, Rayon context switches |

---

## 2. The Most Fundamental Operations

### Tier 1 — Dominant (>10% CPU each)

**BN254 Montgomery Multiplication (28.1%).**
The single hottest function. A 4-limb Montgomery multiply on a 254-bit prime field element (~15–20 ns per call on Apple Silicon). Used by the NTT, sumcheck, weight folding, and geometric accumulation — but NOT by Skyscraper (see below).

**Skyscraper Hash Compression (19.0%).**
Merkle tree hash for polynomial commitments. Processes 64-byte blocks through a byte-level S-box (bitwise rotate + AND + XOR) followed by Montgomery squaring via `bn254_multiplier::montgomery_square_log_interleaved_4` — a separate ARM NEON SIMD implementation in the `skyscraper/bn254-multiplier` crate, completely independent of `ark_ff::mul_assign`.

**NTT / Reed-Solomon Encoding (20.5% total).**
Cooley-Tukey FFT over BN254 Fr. The compute portion (butterfly operations) is 15.2%, and the data transpose (shuffling 32 MB between row-major and column-major) adds 5.3%. The largest NTT operates on 1M-element polynomials.

### Tier 2 — Significant (3–10% each)

- **Weight folding / mixed_dot (6.1%)** — dense multiply-accumulate over 1M-element vectors
- **Sumcheck prover (5.5%)** — cubic polynomial evaluation at 3 points per variable, parallelized via Rayon
- **XZ/LZMA decompression (5.5%)** — prover key I/O, not proving work

### Tier 3 — Notable (<3%)

- Sparse matrix ops (2.4%), evaluate_gamma_block (1.4%), geometric_accumulate (1.3%)
- Witness generation is only 0.6% — the Noir ACVM is cheap

### WHIR Round Cost Decay

![WHIR Rounds](charts/5_whir_rounds.svg)

Each WHIR proof runs 5 FRI-like rounds with geometrically shrinking domains. Round 1 (domain 1M) costs 75.6 ms for IRS Commit alone; by round 5 (domain 32) it's 6.4 ms. The IRS Commit phase (NTT + Merkle) dominates every round.

---

## 3. Field Multiplication 2× Speedup: Significant or Minor?

### Who calls `ark_ff::mul_assign`?

![mul_assign Callers](charts/3_mul_callers.svg)

Programmatic analysis of all 7,600 flamegraph samples (`docs/analyze_flamegraph.py`) traced every `mul_assign` leaf sample to its direct caller:

| Caller | Samples | % of mul |
|--------|---------|----------|
| NTT butterflies | 1,546 | 72.3% |
| mixed_dot | 252 | 11.8% |
| geometric_accumulate | 184 | 8.6% |
| Sumcheck | 92 | 4.3% |
| evaluate_gamma_block | 25 | 1.2% |
| Other | 39 | 1.8% |
| **Skyscraper** | **0** | **0.0%** |

**Skyscraper contributes zero `ark_ff::mul_assign` calls.** It uses a completely separate SIMD Montgomery implementation (`bn254_multiplier`). The 19% of CPU time in Skyscraper is unaffected by any `ark_ff` speedup.

### Computed Impact (3 methods, all programmatic)

![Speedup Impact](charts/4_speedup_impact.svg)

```
METHOD 1 — Amdahl's Law (total prove command)
  mul_assign self-time:    2,138 / 7,600 samples = 28.1%
  Halving saves:           1,069 samples
  Time reduction:          14.1%
  Speedup:                 1.164×

METHOD 2 — Proving-only (exclude I/O + OS)
  Proving samples:         6,231 (after removing 1,369 overhead)
  Halving saves:           1,069 samples
  Proving time reduction:  17.2%
  Proving speedup:         1.207×

METHOD 3 — Wall-clock calibrated (SpanStats)
  mul_assign % of proving: 34.3%  (2,138 / 6,231)
  mul_assign time:         480 ms
  Saved:                   240 ms
  New prove_with_witness:  1,160 ms  (was 1,400)
  Proving speedup:         1.207×
  End-to-end speedup:      1.126×
```

### Theoretical ceiling (mul_assign → 0 ns)

```
  Max proving speedup:     1.522×
  Max end-to-end speedup:  1.391×
```

Even infinitely fast field multiplication caps the proving speedup at 1.52×.

### Verdict: Significant, Not Transformative

A 2× `ark_ff::mul_assign` speedup saves **~240 ms** off a 1,400 ms prove — a **1.21× proving speedup (17% reduction)**. That's noticeable. But it's not transformative because:

1. **Skyscraper (19% of CPU) is completely unaffected** — separate SIMD Montgomery implementation
2. **NTT transposes (5.3%) are memory-bound** — halving mul doesn't help memory shuffling
3. **OS overhead (4.9%) and I/O (5.5%) are fixed costs**
4. **Amdahl's Law** — even at ∞ speed, mul_assign can only remove 34.3% of proving time

---

## 4. Additional Data

### Memory Profile

![Memory](charts/6_memory.svg)

Peak memory reaches 908 MB during `prove_noir` when R1CS matrices, the full witness, transposed matrices, and eq(alpha) evaluations coexist. System-level RSS peaks at 1.36 GB.

### Consistency (3 runs, `/usr/bin/time -l`)

| Metric | Run 1 | Run 2 | Run 3 | Variance |
|--------|-------|-------|-------|----------|
| Instructions | 188.589 B | 188.607 B | 188.627 B | <0.02% |
| Cycles | 47.157 B | 47.271 B | 47.368 B | <0.4% |
| Peak RSS | 1.363 GB | 1.357 GB | 1.362 GB | <0.4% |

IPC: 188.6B / 47.3B ≈ **3.99** — near Apple Silicon's theoretical max, confirming compute-bound workload.

### Architectural Notes

- **Dual commitment** — witness split into w1 (621K) and w2 (627K) for LogUp lookups. Circuits without lookups would need only one commitment, roughly halving proving time.
- **5 WHIR rounds** per proof, each with NTT → Merkle → sumcheck → open. Round 1 dominates (~50% of each proof's time).
- **Rayon parallelism** — 16-core parallel sumcheck and NTT, but 4.9% overhead in context switches and mutex waits.

### Optimization Targets (ranked by potential)

| Target | Current CPU % | Potential speedup | Mechanism |
|--------|--------------|-------------------|-----------|
| SIMD NTT for BN254 | 20.5% | 2–3× NTT → 10–15% total | Vectorized radix-4 + fused twiddles |
| Skyscraper S-box vectorization | 19.0% | 1.5× hash → 6% total | NEON TBL/TBX byte-shuffle |
| Reduce WHIR rounds (5→4) | ~20% of inner_blinded | 5–8% total | Adjusted security parameters |
| Fuse weight-fold + gamma-eval | 7.5% | 2–4% total | Single-pass L2 cache locality |

---

## Charts Index

All charts are SVG files in `docs/charts/`:

| File | Description |
|------|-------------|
| `1_pipeline.svg` | Proving pipeline phase durations |
| `2_cpu_subsystems.svg` | CPU time by subsystem (flamegraph) |
| `3_mul_callers.svg` | Who calls `ark_ff::mul_assign` (pie) |
| `4_speedup_impact.svg` | Field mul speedup impact (bar) |
| `5_whir_rounds.svg` | WHIR round cost decay |
| `6_memory.svg` | Peak memory by phase |

Flamegraphs in `docs/flamegraphs/`:
- `flamegraph_prove.svg` — full interactive flamegraph (29 MB, open in browser)
- `flamegraph_demangled.svg` — demangled variant
