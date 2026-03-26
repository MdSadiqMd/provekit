# ProveKit Pipeline Output — Term Definitions

This document explains every key term and metric from the output of running the full prepare, prove, and verify flow on the `complete_age_check` Noir circuit.

---

## Step 1: `nargo compile`

**What it does:** The Noir compiler (`nargo`) takes human-readable Noir source code (`.nr` files) and compiles it into ACIR — an intermediate representation that proof backends like ProveKit can consume.

**Output:** `complete_age_check.json` (2.39 MB)

### Terms

**Noir:** A domain-specific language for writing zero-knowledge circuits. It looks like Rust but compiles down to constraint systems instead of machine code. You write your computation in Noir, and the compiler turns it into something a proof system can work with.

**`nargo`:** The Noir compiler and toolchain CLI. It handles compiling, testing, and executing Noir programs. Think of it like `cargo` for Noir.

**ACIR (Abstract Circuit Intermediate Representation):** The intermediate format Noir compiles to. It's a list of opcodes (instructions) that describe the computation at a level between high-level Noir code and low-level R1CS constraints. ACIR is backend-agnostic — different proof systems can consume it and compile it further into their own constraint format.

**236,965 witnesses:** The total number of variables (wires) in the compiled circuit. This includes:
- `w[0] = 1` — the constant one (always present)
- `w[1]` through `w[num_public_inputs]` — public inputs visible to the verifier (e.g., the age threshold, current date)
- The remaining witnesses — private inputs and intermediate computation values (e.g., the passport data, signature components, intermediate hash states)

Each witness is a field element in the BN254 scalar field (a 254-bit number modulo a large prime). The prover must compute a value for every single witness such that all constraints are satisfied.

**80,299 ACIR opcodes:** The number of instructions in the compiled circuit. Each opcode represents an operation like:
- `AssertZero` — assert that a linear expression equals zero
- `BlackBoxFuncCall` — call an optimized built-in function (SHA256, Poseidon2, RSA verification, etc.)
- Arithmetic operations — multiplications, additions over field elements

These 80,299 opcodes will be expanded into a much larger number of R1CS constraints in the next step, because a single ACIR opcode (especially black box functions like SHA256) can generate hundreds or thousands of individual constraints.

**2.39 MB:** The size of the serialized ACIR circuit on disk. This JSON file contains the full circuit description — all opcodes, witness metadata, and public input declarations. It's the input to ProveKit's R1CS compiler.

---

## Step 2: `provekit-cli prepare`

**What it does:** Takes the ACIR circuit and compiles it into R1CS (the constraint format ProveKit's WHIR prover uses), then generates the prover and verifier keys. This is the heaviest offline step — it only needs to run once per circuit.

### Terms

**R1CS (Rank-1 Constraint System):** The mathematical representation of the circuit as a system of quadratic equations. It consists of three sparse matrices A, B, C (each of size m × n) where:
- m = number of constraints (631,480)
- n = number of witnesses (236,965+)

Each constraint enforces: `(A[i] · w) × (B[i] · w) = C[i] · w` where `w` is the witness vector and all arithmetic is modulo the BN254 prime. If every constraint is satisfied, the computation was performed correctly.

**631,480 constraints:** The total number of R1CS constraints after compilation and optimization. This is much larger than the 80,299 ACIR opcodes because:
- Each ACIR multiplication becomes at least 1 constraint
- Black box functions expand significantly (SHA256 alone can produce ~25,000 constraints per block)
- Range checks, boolean checks, and other validation logic add constraints
- The passport verification circuit includes RSA signature verification, SHA256 hashing, date comparison, and Merkle tree operations — all constraint-heavy

**Gaussian elimination:** An optimization pass applied to the R1CS. It identifies and removes redundant constraints by:
- Finding witnesses that are simple linear combinations of other witnesses
- Substituting them out, reducing the total constraint count
- This is like simplifying a system of equations by eliminating variables

The "after Gaussian elimination" qualifier means 631,480 is the optimized count — the raw count before elimination was higher.

**Prover key (4.64 MB):** A serialized data structure containing everything the prover needs to generate a proof for this specific circuit:
- The R1CS matrices (A, B, C) in compressed sparse format
- Witness builders — instructions for computing each witness value from inputs
- Layer scheduling information — the dependency order for witness solving
- Circuit metadata (number of public inputs, constraint structure)

The prover loads this key once, then can generate proofs for different inputs without recompiling.

**Verifier key (8.31 MB):** A serialized data structure containing everything the verifier needs to check a proof:
- The R1CS structure (or a commitment to it)
- Public input binding information
- WHIR verification parameters (hash configuration, domain sizes, etc.)
- Enough information to replay the Fiat-Shamir transcript and check the sumcheck protocol

The verifier key is larger than the prover key here because it includes the full constraint structure needed for WHIR verification (unlike Groth16 where the verifier key is tiny because pairings compress everything).

**~60 seconds:** The time to compile ACIR → R1CS and generate keys. This is dominated by:
- Compiling 80,299 ACIR opcodes into 631,480+ constraints
- Running Gaussian elimination (matrix operations on large sparse matrices)
- Serializing the keys to disk
- Building witness builder dependency graphs and scheduling layers

**Peak 1.37 GB memory:** The maximum RAM used during preparation. This is the most memory-intensive step because:
- The full R1CS matrices must be in memory during Gaussian elimination
- Witness builder structures are large before compression
- Intermediate compilation state (ACIR → R1CS mapping tables, temporary constraints)

This is an offline step, so high memory usage is acceptable — it runs on a developer machine, not on a phone.

---

## Step 3: `provekit-cli prove`

**What it does:** Takes the prover key and the actual inputs (from `Prover.toml`), solves all witness values, and generates a WHIR zero-knowledge proof. This is the step that would run on a mobile device in production.

### Terms

**Proof (3.27 MB):** The zero-knowledge proof itself — a cryptographic object that convinces the verifier the prover knows a valid witness without revealing it. It contains:
- Merkle tree commitments to the witness polynomial (roots and opening paths)
- Sumcheck protocol round polynomials (one per round, each a few field elements)
- Fiat-Shamir transcript data (challenges derived from hashing)
- Prover hints (polynomial evaluations that are independently verified)

3.27 MB is typical for WHIR proofs — much larger than Groth16 (~200 bytes) but the tradeoff is no trusted setup required.

**1.58 seconds:** The total proving time. This includes:
1. Loading the prover key and deserializing R1CS + witness builders
2. Solving all 236,965 witnesses layer by layer (including batch inversions via Montgomery's trick)
3. Committing to the witness polynomial by building a Merkle tree (hashing all witness values)
4. Running the sumcheck protocol (multiple rounds of polynomial evaluation and Fiat-Shamir challenges)
5. Serializing the final proof

1.58 seconds for 631K constraints is fast — this is ProveKit's mobile optimization at work (SIMD-accelerated field arithmetic, memory compression, efficient sparse matrix operations).

**Peak 908 MB memory:** The maximum RAM during proving. The memory timeline roughly looks like:
1. Load R1CS (~200 MB) and solve w1 witnesses (~50 MB)
2. Compress R1CS to a blob (~20 MB), free the matrices (saves ~180 MB)
3. Build Merkle tree for commitment (~100 MB) — this is likely the peak
4. Free Merkle tree, decompress R1CS for sumcheck
5. Run sumcheck (~50 MB additional)

Without ProveKit's compression tricks (compress R1CS during commitment, free Merkle tree after root extraction), this would peak well over 1.5 GB.

---

## Step 4: `provekit-cli verify`

**What it does:** Takes the verifier key and the proof, replays the Fiat-Shamir transcript, checks the sumcheck protocol, and verifies all Merkle tree openings. Outputs accept or reject.

### Terms

**179 milliseconds:** The verification time. Much faster than proving (1.58s) because the verifier:
- Does NOT solve witnesses or build Merkle trees
- Only replays the transcript (recomputes challenges via hashing)
- Checks sumcheck round consistency (each round: verify `g_i(0) + g_i(1) = previous_claim`)
- Verifies Merkle opening proofs (a few hash computations per opening)
- Checks public input binding

Verification is always faster than proving — that's a fundamental property of proof systems.

**Peak 593 MB memory:** The maximum RAM during verification. This is surprisingly high for verification because:
- The verifier key is 8.31 MB but must be deserialized into full R1CS structure
- WHIR verification requires evaluating the R1CS polynomial at a random point (needs the constraint matrices in memory)
- Merkle proof verification requires storing opening paths

This is a key difference from Groth16 (where verification uses ~1 MB). WHIR trades smaller proof infrastructure (no trusted setup) for heavier verification. In production, this verification would typically happen on a server, not a phone. For on-chain verification, the WHIR proof would be wrapped in a Groth16 proof via recursive verification.

**Exit code 0:** The proof is valid. The verifier confirmed that:
- All Fiat-Shamir challenges were correctly derived (transcript consistency)
- All sumcheck rounds are consistent (each round polynomial matches the previous claim)
- All Merkle tree openings are valid (committed values match the proof)
- Public inputs are correctly bound to the witness
- The R1CS relation holds at the random evaluation point (by Schwartz-Zippel, this means it holds everywhere with overwhelming probability)

---

## End-to-End Summary

```
Noir source (.nr)
    │
    ▼ nargo compile
ACIR circuit (80,299 opcodes, 236,965 witnesses)
    │
    ▼ provekit-cli prepare
R1CS (631,480 constraints) + prover key + verifier key
    │
    ▼ provekit-cli prove (with private inputs)
WHIR proof (3.27 MB)
    │
    ▼ provekit-cli verify
✓ Valid (179ms)
```

The complete_age_check circuit proves that a passport holder meets an age requirement without revealing the passport data itself. The circuit includes RSA-2048 signature verification (DKIM-style), SHA256 hashing, date arithmetic, and Merkle tree membership — all expressed as 631,480 field-level constraints over the BN254 scalar field.

---

## Flamegraph Analysis: Where the Prover Spends Its Time

**Source:** CPU flamegraphs captured during `provekit-cli prove` on the `complete_age_check` circuit (13,110 total samples). Both raw and demangled flamegraphs were analyzed.

---

### Major Time Sinks

The proving workload (running on rayon worker threads, ~90.7% of total samples) breaks down into these major areas:

**1. NTT / Cooley-Tukey FFT (~22–25%)**
The Number Theoretic Transform (`whir::algebra::ntt::cooley_tukey::NttEngine::ntt_dispatch`) is the single largest compute block. It performs polynomial evaluation and interpolation over the BN254 scalar field, dispatched in parallel chunks via rayon. The NTT is used both during witness polynomial commitment and during sumcheck rounds. Within the NTT, there is also a significant matrix transpose step (`whir::algebra::ntt::transpose::transpose_copy`, ~3%) which is memory-bandwidth bound rather than compute bound.

**2. Matrix Commitment / Row Hashing (~20–25%)**
`whir::protocols::matrix_commit::hash_rows` is a deeply recursive rayon parallel tree that dominates the commitment phase. This is the WHIR polynomial commitment scheme building its matrix commitment by hashing rows of the evaluation matrix using the Skyscraper algebraic hash function. The recursive parallel structure means this function appears at many depths in the flamegraph, each level splitting work across rayon workers.

**3. Sumcheck / evaluate_gamma_block (~12%)**
`whir::protocols::whir_zk::prover::evaluate_gamma_block` is the sumcheck prover's main loop. It evaluates gamma polynomials in parallel blocks using a fold-map-reduce pattern over enumerated chunks of field elements. Each block involves field multiplications and additions to compute the round polynomials that the verifier will check.

**4. Merkle Tree Construction (~3–5%)**
`whir::protocols::merkle_tree::parallel_hash` builds the Merkle tree over the committed matrix rows. It uses the Skyscraper hash internally and is parallelized via recursive rayon joins. This is smaller than hash_rows because the Merkle tree has O(n) nodes while the matrix has O(n × row_width) elements.

**5. Geometric Accumulation (~4%)**
`whir::algebra::geometric_accumulate` performs batched geometric series accumulation — multiply-and-add chains over field elements. This is used in the WHIR protocol for combining polynomial evaluations with powers of a challenge. It bottoms out almost entirely in Montgomery field multiplication (`mul_assign`), with 492 samples in its largest instance.

**6. Decompression / I/O (~4%)**
The prover key is LZMA-compressed on disk. Decompressing it (`lzma_code` → `lzma2_decode` → `lzma_decode`) costs ~338 samples (2.6%). LZMA CRC checking adds another ~0.5%. Deserialization via postcard/serde adds ~1–2% on top. This is a fixed overhead per proof that doesn't scale with circuit size.

**7. ACVM / Brillig Circuit Execution (~1.1%)**
The Noir virtual machine executing the circuit to produce the witness (`brillig_vm::VM::process_opcode_internal`, `acvm::pwg::ACVM::solve_opcode`). This is tiny relative to proving — the witness computation is not the bottleneck.

---

### The Most Fundamental Operations

At the very bottom of every call stack, the leaf-level primitives that actually consume CPU cycles are:

**Montgomery Field Multiplication (`MontBackend::mul_assign`)**
The BN254 scalar field multiply in Montgomery form. This is the atomic operation underlying NTT butterfly steps, geometric accumulation, and sumcheck polynomial evaluation. It appears in 344 distinct frames across the flamegraph, scattered across every major subsystem. Every algebraic operation in the prover ultimately bottoms out here (or in field addition, which is too cheap to show up significantly).

**Skyscraper Hash Permutation (`skyscraper::reference::bb`, `skyscraper::reference::bar`, `skyscraper::sponge::Skyscraper::permute`)**
The algebraic hash function used for both row hashing (matrix commitment) and Merkle tree construction. The `bb` and `bar` functions are the core permutation rounds. Skyscraper is chosen because it's efficient over prime fields — it operates natively on BN254 field elements without needing bit decomposition like SHA256 would.

**Memory Copies (`_platform_memmove`, `__bzero`)**
Data movement for NTT transpose, vector reallocation, and buffer management. These reflect the memory-bandwidth cost of operating on large polynomial vectors.

**LZMA Decompression (`lzma_decode`, `lzma2_decode`)**
Byte-level decompression of the prover key. A fixed I/O cost.

In summary: the two truly fundamental primitives are **field multiplication** (for all the algebra) and **Skyscraper hashing** (for all the commitments). Everything else is orchestration, parallelism overhead, or I/O.

---

### Thought Experiment: Halving Field Multiplication Cost

**Question:** If `mul_assign` took half as long, how much would overall proving time decrease?

**Answer: Moderate improvement — roughly 10–15% overall speedup. Meaningful but not transformative.**

**Reasoning:**

Field multiplication (`MontBackend::mul_assign`) is the leaf operation in many hot paths:
- NTT butterfly steps (each butterfly = 1 multiply + 1 add + data shuffling)
- Geometric accumulation (almost pure multiply chains — 492 samples / 3.75% in its largest instance)
- Sumcheck evaluation (multiply-accumulate over polynomial coefficients)

Summing across all call sites where `mul_assign` is the actual leaf (not just an ancestor), field multiplication accounts for roughly **20–25% of total CPU time**. Halving its cost would therefore save about half of that, yielding a **~10–12% wall-clock improvement**.

The reason it's not more dramatic:

1. **NTT is not purely multiplication.** A large fraction of NTT time is the transpose step (~3%), which is pure memory bandwidth — `_platform_memmove` copying field elements between matrix rows. Halving multiply cost doesn't touch this.

2. **Hashing is a separate bottleneck.** The matrix commitment and Merkle tree phases are dominated by Skyscraper hash permutations, not field multiplication. These two phases together account for ~25–30% of proving time and would be completely unaffected by faster multiplication.

3. **Rayon scheduling overhead.** The parallel dispatch machinery (rayon join contexts, job execution, latch spinning) consumes some fraction of time that's independent of arithmetic speed.

4. **I/O is fixed.** The ~4% spent on LZMA decompression and deserialization is unrelated to field arithmetic.

To get a larger speedup, you'd need to also accelerate the Skyscraper hash (which would help the ~25% spent in commitment/Merkle), reduce NTT transpose memory pressure (SIMD-friendly layouts, cache-oblivious algorithms), or reduce the number of NTT/sumcheck rounds (protocol-level optimization).
