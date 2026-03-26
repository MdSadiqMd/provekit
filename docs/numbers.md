# Where Does the Prover Spend Its Time?

An analysis of ProveKit's `complete_age_check` circuit — 631,480 R1CS constraints, 1.25 million witnesses, proving a passport holder's age via RSA certificate chain verification, SHA-256 hashing, and Merkle tree membership — all inside a zero-knowledge proof.

Profiled on Apple Silicon (arm64, 16 cores, 48 GB RAM) using flamegraph sampling (7,600 samples at 1 kHz) and ProveKit's built-in SpanStats tracing. All data is from the raw profiling report in `docs/report.md`.

---

## The Big Picture

The prover takes **1.40 seconds** of actual computation (2.14 s wall-clock including I/O) to generate a 3.3 MB WHIR proof. Here is where that time goes:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    prove_with_witness: 1,400 ms                     │
├──────────┬──────────┬──────────┬──────────────────────────────┬─────┤
│ Witness  │ Commit   │ Commit   │         prove_noir           │Ser. │
│ Gen+Solve│   w1     │   w2     │           830 ms             │     │
│  230 ms  │ 184 ms   │ 176 ms   │                              │10ms │
│  16.4%   │ 13.1%    │ 12.6%    │           59.3%              │0.7% │
├──────────┴──────────┴──────────┼──────────────────────────────┤     │
│                                │  ┌────────────────────────┐  │     │
│                                │  │  prove_from_alphas     │  │     │
│                                │  │  760 ms (91.6%)        │  │     │
│                                │  │  ┌──────┐ ┌──────┐     │  │     │
│                                │  │  │WHIR  │ │WHIR  │     │  │     │
│                                │  │  │proof │ │proof │     │  │     │
│                                │  │  │ w1   │ │ w2   │     │  │     │
│                                │  │  │372ms │ │379ms │     │  │     │
│                                │  │  └──────┘ └──────┘     │  │     │
│                                │  └────────────────────────┘  │     │
│                                └──────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

The dominant cost is `prove_noir` at 59.3%, which runs two full WHIR ZK proofs (one per witness split). The two polynomial commitment phases (w1 + w2) account for another 25.7%. Witness generation and solving together are only 16.4%.

---

## Time Breakdown by Functional Area

Grouping the 7,600 flamegraph samples by what the CPU is actually doing (not which protocol phase it is in):

```
BN254 Field Multiplication (ark_ff::mul_assign)  ████████████████████████████  28.1%
Skyscraper Merkle Hashing                         ███████████████████           19.0%
NTT / Reed-Solomon Encoding                       ███████████████               15.2%
Weight Folding (mixed_dot)                         ██████                         6.1%
I/O: XZ Decompression                             █████                          5.5%
Sumcheck Prover                                    █████                          5.5%
OS / Kernel Overhead (Rayon)                       ████                           4.9%
NTT Data Transpose                                 ███                            5.3%
Sparse Matrix Ops (R1CS)                           ██                             2.4%
ZK Blinding (gamma eval)                           █                              1.4%
Geometric Accumulate                               █                              1.3%
Other (witness gen, serialization, encoding)        ██                             5.3%
```

Three subsystems dominate: field multiplication (28.1%), Merkle hashing (19.0%), and NTT (20.5% including transposes). Together they account for two-thirds of all CPU time.

---

## The Fundamental Operations

Every phase of the prover ultimately reduces to a small set of primitive operations. Here they are, ranked by measured CPU contribution.

### 1. BN254 Montgomery Multiplication — 28.1% of CPU

The single hottest function in the entire prover. `ark_ff::mul_assign` performs a 4-limb Montgomery multiplication on 254-bit prime field elements. On Apple Silicon, each call takes roughly 15–20 ns.

This one function is called from nearly every subsystem — but not equally:

```
Where mul_assign is called from (7,600 flamegraph samples):

NTT butterfly operations     ████████████████████████████████████  72.3%  (1,546 samples)
Weight folding (mixed_dot)   ██████                                11.8%  (252 samples)
Geometric accumulate         ████                                   8.6%  (184 samples)
Sumcheck prover              ██                                     4.3%  (92 samples)
Gamma evaluation             █                                      1.2%  (25 samples)
Other                        █                                      1.8%  (39 samples)
Skyscraper hash              ▏                                      0.0%  (0 samples)
```

The NTT consumes nearly three-quarters of all field multiplications. Skyscraper contributes exactly zero — it uses its own ARM NEON SIMD Montgomery squaring routine (`bn254_multiplier::montgomery_square_log_interleaved_4`), completely independent of `ark_ff`.

### 2. Skyscraper Hash Compression — 19.0% of CPU

The Merkle tree hash function used for polynomial commitments. Each compression call processes a 64-byte block through:
1. A byte-level S-box (bitwise rotate + AND + XOR on individual bytes)
2. Montgomery squaring via a custom ARM NEON SIMD implementation
3. Modular reduction

The S-box operates on raw bytes, not field elements. The squaring uses a hand-written SIMD routine in the `bn254-multiplier` crate. This is why Skyscraper's 19% of CPU time is entirely decoupled from `ark_ff` — speeding up the generic field multiplication would not touch it.

### 3. NTT (Number Theoretic Transform) — 20.5% of CPU

The Cooley-Tukey FFT over the BN254 scalar field, used in every IRS Commit phase to Reed-Solomon encode the witness polynomial. Breaks down as:
- 15.2% in the NTT butterfly computation itself (`ntt_dispatch`)
- 5.3% in data layout transpositions (`transpose_copy`, `transpose`)

The largest NTT operates on 1M-element polynomials (32 MB of field elements). The transpose operations are pure memory movement — shuffling data between row-major and column-major layouts — and are memory-bandwidth-bound rather than compute-bound.

### 4. Sumcheck Protocol — 5.5% of CPU

The interactive sumcheck protocol evaluates the sumcheck polynomial at 3 points per variable in each round. The hot loop (`sumcheck_fold_map_reduce_inner`) performs 3 field multiplications and 3 additions per evaluation, parallelized via Rayon's recursive splitting.

### 5. Weight Folding — 6.1% of CPU

Dense dot products between weight vectors and polynomial evaluations during the ZK blinding layer. Runs once per WHIR round (5 times per proof), each time folding vectors of up to 1M elements. Pure multiply-accumulate.

---

## The WHIR Round Structure

Each WHIR proof runs 5 rounds of a FRI-like folding protocol. Each round performs: sumcheck → NTT + Merkle commit → Merkle open → proof-of-work. The domain size shrinks geometrically (8× per round):

```
Round 1:  1,048,576 elements  ──────────────────────────────────  75.6 ms commit
Round 2:    131,072 elements  ────────────────────                36.9 ms commit
Round 3:     16,384 elements  ──────────                          19.1 ms commit
Round 4:      2,048 elements  ─────                               10.6 ms commit
Round 5:        256 elements  ───                                  6.4 ms commit
```

Round 1 alone accounts for ~50% of each WHIR proof's time because the NTT and Merkle tree scale with domain size. The sumcheck cost is negligible by comparison (6.5 ms in round 1 vs. 75.6 ms for the commit).

The prover runs two of these proofs (one for w1, one for w2) because the witness is split for a challenge–response pattern required by LogUp-based lookups. Circuits without lookup tables would need only one proof, roughly halving the WHIR cost.

---

## What If Field Multiplication Were 2× Faster?

This is the central question. The answer comes from applying [Amdahl's Law](https://en.wikipedia.org/wiki/Amdahl%27s_law) to the flamegraph data.

### The Setup

`ark_ff::mul_assign` accounts for 28.1% of total CPU samples (2,138 out of 7,600). Halving its execution time saves exactly half of those samples: 1,069 samples.

But 18.0% of samples are overhead (dynamic linker startup, XZ decompression, kernel context switches) that would not change. So we need to consider two scopes:

### Method 1: End-to-End (entire `prove` command)

```
Samples saved:     1,069 out of 7,600
Time reduction:    14.1%
Speedup:           1.164×
Wall-clock:        2,140 ms → ~1,840 ms  (saves ~300 ms)
```

### Method 2: Proving-Only (excluding I/O and OS overhead)

```
Proving samples:   6,231 (after removing 1,369 overhead samples)
Samples saved:     1,069
Time reduction:    17.2%
Speedup:           1.207×
Wall-clock:        1,400 ms → ~1,160 ms  (saves ~240 ms)
```

### Method 3: Wall-Clock Calibrated (SpanStats cross-check)

```
mul_assign share of proving:  2,138 / 6,231 = 34.3%
mul_assign wall-clock time:   34.3% × 1,400 ms = ~480 ms
Time saved (÷2):              240 ms
New prove_with_witness:       1,160 ms
Proving speedup:              1.207×
End-to-end speedup:           1.126×
```

All three methods converge: a 2× field multiplication speedup yields a **~1.2× proving speedup (17% reduction, saving ~240 ms)**.

### The Theoretical Ceiling

If `mul_assign` were infinitely fast (0 ns):

```
Max proving speedup:     1.522×  (34.3% of proving time eliminated)
Max end-to-end speedup:  1.391×
```

Even with perfect field arithmetic, proving can be at most 1.52× faster. The remaining 65.7% of proving time is in:
- Skyscraper hashing (19%) — uses its own SIMD Montgomery, unaffected
- NTT memory transposes (5.3%) — memory-bound, not compute-bound
- OS/parallelism overhead (4.9%) — fixed cost of Rayon thread pool
- I/O (5.5%) — prover key decompression
- Sumcheck non-mul work, gamma evaluation, sparse matrix ops, etc.

### Verdict

A 2× `mul_assign` speedup is **significant but not transformative**. Saving a quarter-second off a 1.4-second prove is noticeable — especially on mobile where every millisecond counts — but it does not change the order of magnitude. The prover's time is spread across multiple independent bottlenecks (field arithmetic, hashing, memory movement), and no single optimization can deliver more than ~1.5× improvement.

---

## Where the Real Optimization Opportunities Are

Ranked by potential impact, derived from the flamegraph:

### 1. SIMD-Vectorized NTT for BN254 on ARM NEON

The NTT + transpose accounts for 20.5% of CPU time and consumes 72.3% of all `mul_assign` calls. A vectorized radix-4 NTT with fused twiddle application could reduce both the multiplication and transpose costs simultaneously. Research on NEON-optimized NTTs for lattice cryptography has demonstrated [2–4× speedups over scalar implementations](https://www.scribd.com/document/778659755/neon-ntt) on Armv8-A. Adapting these techniques to BN254's 254-bit field (rather than the smaller moduli used in lattice crypto) is non-trivial but high-value.

Potential: 2–3× NTT speedup → 10–15% total proving reduction.

### 2. Skyscraper S-Box Vectorization

The S-box in Skyscraper's `bar()` function operates on individual bytes with scalar bitwise operations. ARM NEON's `TBL`/`TBX` byte-shuffle instructions could vectorize the 32-byte S-box application in a single instruction. The Montgomery squaring is already SIMD-optimized, so this targets the remaining scalar portion of Skyscraper.

Potential: 1.5× Skyscraper speedup → ~6% total reduction.

### 3. Reducing the WHIR Round Count

Each of the 5 FRI-like rounds adds a full NTT + Merkle commit + sumcheck cycle. Going from 5 to 4 rounds (with adjusted security parameters — increasing the code rate or query count to compensate) would eliminate ~20% of `inner_blinded_prove` time. The [WHIR paper](https://gfenzi.io/papers/whir/) shows that the rate parameter ρ offers a direct tradeoff between round count and proof size.

Potential: 5–8% total proving reduction.

### 4. Fusing Weight-Folding and Gamma Evaluation

`zk_w_folded_compute` and `evaluate_gamma_block` both iterate over the same ~1M-element polynomial data. Fusing them into a single pass would improve L2 cache hit rates on the 32 MB witness polynomial, avoiding a redundant memory traversal.

Potential: 2–4% total reduction.

---

## Memory Profile

| Phase | Peak Memory | Notes |
|-------|------------|-------|
| Read prover key | 581 MB | XZ decompression → ~580 MB in-memory |
| Solve w1 | 389 MB | Drops after R1CS compression |
| Commit w1 | 475 MB | Merkle tree temporarily in memory |
| Solve w2 | 607 MB | Challenge-dependent witnesses |
| Commit w2 | 688 MB | Second Merkle tree |
| prove_noir | **908 MB** | R1CS + witness + transposed matrices + eq(alpha) |

Peak memory (908 MB) occurs during `prove_noir` when the R1CS matrices, full witness vector, transposed matrices, and eq(alpha) evaluations are all resident simultaneously. ProveKit's compression strategy (serialize R1CS to a blob during commitment, decompress for sumcheck) keeps this from exceeding ~1 GB despite the circuit's size.

---

## Execution Determinism

Three consecutive runs show near-perfect reproducibility:

| Metric | Run 1 | Run 2 | Run 3 | Variance |
|--------|-------|-------|-------|----------|
| Instructions retired | 188.589 B | 188.607 B | 188.627 B | <0.02% |
| Cycles | 47.157 B | 47.271 B | 47.368 B | <0.4% |
| Peak memory | 1.363 GB | 1.357 GB | 1.362 GB | <0.4% |

IPC: 188.6B / 47.3B ≈ **3.99 instructions per cycle** — near the theoretical maximum for Apple Silicon's wide-issue out-of-order cores. The workload is compute-bound on average, not memory-stalled.

---

## Key Takeaways

1. The prover's time is distributed across three roughly equal pillars: field arithmetic (28%), Merkle hashing (19%), and NTT (21%). No single pillar dominates enough for a silver-bullet optimization.

2. Halving field multiplication speed yields a 1.2× proving speedup (17% reduction). Meaningful, but the ceiling is 1.52× even with infinitely fast field math — because Skyscraper hashing uses a completely separate SIMD code path.

3. The NTT is the single largest consumer of field multiplications (72.3% of all `mul_assign` calls) and the most promising optimization target. A SIMD-vectorized NTT would attack both the compute and memory-layout bottlenecks simultaneously.

4. The dual-proof architecture (w1 + w2) doubles the WHIR cost. Circuits without LogUp lookups would prove in roughly half the time.

5. At 3.99 IPC, the prover is already extracting near-maximum throughput from the hardware. Further gains will come from algorithmic improvements (fewer rounds, fused passes) and SIMD vectorization, not from better instruction scheduling.
