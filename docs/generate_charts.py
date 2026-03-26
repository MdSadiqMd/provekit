#!/usr/bin/env python3
"""Generate SVG charts for the ProveKit profiling final report."""
import math, os

OUT = os.path.join(os.path.dirname(__file__), "charts")
os.makedirs(OUT, exist_ok=True)

# ─── Helpers ────────────────────────────────────────────────────────
def svg_header(w, h):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" font-family="system-ui,-apple-system,sans-serif">\n<rect width="{w}" height="{h}" fill="#fff"/>\n'

def svg_footer():
    return '</svg>\n'

COLORS = ["#2563eb","#f59e0b","#10b981","#ef4444","#8b5cf6",
          "#ec4899","#06b6d4","#84cc16","#f97316","#6366f1",
          "#14b8a6","#a3a3a3"]

# ─── Chart 1: Proving Pipeline Waterfall ────────────────────────────
def chart_pipeline():
    phases = [
        ("Witness gen",       157,  COLORS[0]),
        ("Solve w1",           38,  COLORS[1]),
        ("Commit w1\n(NTT+Merkle)", 184, COLORS[2]),
        ("Solve w2",           35,  COLORS[3]),
        ("Commit w2\n(NTT+Merkle)", 176, COLORS[4]),
        ("prove_noir\n(sumcheck+WHIR)", 830, COLORS[5]),
        ("Serialize proof",    10,  COLORS[11]),
    ]
    total = sum(d for _,d,_ in phases)
    W, H = 760, 320
    margin_l, margin_r, margin_t, margin_b = 140, 30, 50, 40
    bar_h = 28
    gap = 8
    chart_w = W - margin_l - margin_r
    scale = chart_w / total

    s = svg_header(W, H)
    s += f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" font-weight="600">Proving Pipeline: prove_with_witness (1,400 ms)</text>\n'

    for i, (name, dur, col) in enumerate(phases):
        y = margin_t + i * (bar_h + gap)
        bw = max(dur * scale, 2)
        # cumulative offset
        x_off = margin_l + sum(d for _,d,_ in phases[:i]) * scale * 0  # left-aligned bars
        # label
        lines = name.split('\n')
        for li, line in enumerate(lines):
            ty = y + bar_h/2 + 4 + (li - len(lines)/2 + 0.5) * 13
            s += f'<text x="{margin_l - 8}" y="{ty}" text-anchor="end" font-size="11">{line}</text>\n'
        # bar
        s += f'<rect x="{margin_l}" y="{y}" width="{bw}" height="{bar_h}" rx="3" fill="{col}" opacity="0.85"/>\n'
        # duration label
        label = f"{dur} ms ({100*dur/total:.0f}%)"
        lx = margin_l + bw + 6
        s += f'<text x="{lx}" y="{y + bar_h/2 + 4}" font-size="11" font-weight="500">{label}</text>\n'

    s += svg_footer()
    with open(os.path.join(OUT, "1_pipeline.svg"), "w") as f:
        f.write(s)

# ─── Chart 2: CPU Time by Subsystem (horizontal bar) ───────────────
def chart_cpu_subsystems():
    data = [
        ("Fr::mul_assign (ark_ff)", 28.1, COLORS[0]),
        ("Skyscraper hash",         19.0, COLORS[1]),
        ("NTT compute",             15.2, COLORS[2]),
        ("mixed_dot (weight fold)",  6.1, COLORS[4]),
        ("XZ/LZMA decompression",    5.5, COLORS[11]),
        ("Sumcheck prover",          5.5, COLORS[5]),
        ("OS/kernel overhead",       4.9, COLORS[11]),
        ("NTT transpose",            5.3, COLORS[2]),
        ("Sparse matrix ops",        2.4, COLORS[6]),
        ("Other",                    8.0, COLORS[11]),
    ]
    W, H = 700, 380
    margin_l, margin_r, margin_t, margin_b = 200, 60, 50, 30
    bar_h = 24
    gap = 6
    chart_w = W - margin_l - margin_r
    max_val = 30

    s = svg_header(W, H)
    s += f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" font-weight="600">CPU Time by Subsystem (7,600 flamegraph samples)</text>\n'

    for i, (name, pct, col) in enumerate(data):
        y = margin_t + i * (bar_h + gap)
        bw = (pct / max_val) * chart_w
        s += f'<text x="{margin_l - 8}" y="{y + bar_h/2 + 4}" text-anchor="end" font-size="11">{name}</text>\n'
        s += f'<rect x="{margin_l}" y="{y}" width="{bw}" height="{bar_h}" rx="3" fill="{col}" opacity="0.85"/>\n'
        s += f'<text x="{margin_l + bw + 6}" y="{y + bar_h/2 + 4}" font-size="11" font-weight="600">{pct:.1f}%</text>\n'

    # axis
    s += f'<line x1="{margin_l}" y1="{margin_t - 5}" x2="{margin_l}" y2="{margin_t + len(data)*(bar_h+gap)}" stroke="#ccc" stroke-width="1"/>\n'
    for tick in [0, 10, 20, 30]:
        tx = margin_l + (tick / max_val) * chart_w
        ty = margin_t + len(data) * (bar_h + gap) + 15
        s += f'<text x="{tx}" y="{ty}" text-anchor="middle" font-size="10" fill="#888">{tick}%</text>\n'

    s += svg_footer()
    with open(os.path.join(OUT, "2_cpu_subsystems.svg"), "w") as f:
        f.write(s)

# ─── Chart 3: mul_assign Caller Pie Chart ───────────────────────────
def chart_mul_callers():
    data = [
        ("NTT butterflies", 72.3, COLORS[2]),
        ("mixed_dot",       11.8, COLORS[4]),
        ("geometric_accum",  8.6, COLORS[1]),
        ("Sumcheck",         4.3, COLORS[5]),
        ("Other",            3.0, COLORS[11]),
    ]
    W, H = 520, 360
    cx, cy, r = 200, 190, 130

    s = svg_header(W, H)
    s += f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" font-weight="600">Who Calls ark_ff::mul_assign? (2,138 samples)</text>\n'

    angle = -90  # start at top
    for name, pct, col in data:
        sweep = pct / 100 * 360
        a1 = math.radians(angle)
        a2 = math.radians(angle + sweep)
        x1 = cx + r * math.cos(a1)
        y1 = cy + r * math.sin(a1)
        x2 = cx + r * math.cos(a2)
        y2 = cy + r * math.sin(a2)
        large = 1 if sweep > 180 else 0
        s += f'<path d="M{cx},{cy} L{x1:.1f},{y1:.1f} A{r},{r} 0 {large} 1 {x2:.1f},{y2:.1f} Z" fill="{col}" stroke="#fff" stroke-width="2"/>\n'
        # label
        mid_a = math.radians(angle + sweep / 2)
        lx = cx + (r * 0.65) * math.cos(mid_a)
        ly = cy + (r * 0.65) * math.sin(mid_a)
        s += f'<text x="{lx:.0f}" y="{ly:.0f}" text-anchor="middle" font-size="11" font-weight="600" fill="#fff">{pct:.0f}%</text>\n'
        angle += sweep

    # legend
    lx_start = 370
    for i, (name, pct, col) in enumerate(data):
        ly = 100 + i * 24
        s += f'<rect x="{lx_start}" y="{ly - 10}" width="14" height="14" rx="2" fill="{col}"/>\n'
        s += f'<text x="{lx_start + 20}" y="{ly + 1}" font-size="11">{name}</text>\n'

    # note
    s += f'<text x="{W/2}" y="{H - 15}" text-anchor="middle" font-size="10" fill="#888">Skyscraper hash: 0% (uses separate bn254_multiplier SIMD)</text>\n'

    s += svg_footer()
    with open(os.path.join(OUT, "3_mul_callers.svg"), "w") as f:
        f.write(s)

# ─── Chart 4: Field Mul Speedup Impact ──────────────────────────────
def chart_speedup():
    W, H = 620, 340
    margin_l, margin_t = 60, 60

    scenarios = [
        ("Current",          1400, 2140, "#94a3b8"),
        ("2× faster mul",    1160, 1900, COLORS[0]),
        ("∞ fast mul\n(theoretical max)", 920, 1660, COLORS[2]),
    ]

    bar_w = 70
    gap = 50
    group_gap = 30
    max_val = 2200
    chart_h = 220
    chart_w = len(scenarios) * (bar_w * 2 + group_gap) + (len(scenarios) - 1) * gap

    s = svg_header(W, H)
    s += f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" font-weight="600">Impact of Faster Field Multiplication</text>\n'

    base_y = margin_t + chart_h

    for i, (label, prove_ms, total_ms, col) in enumerate(scenarios):
        gx = margin_l + i * (bar_w * 2 + group_gap + gap)

        # prove bar
        ph = (prove_ms / max_val) * chart_h
        s += f'<rect x="{gx}" y="{base_y - ph}" width="{bar_w}" height="{ph}" rx="3" fill="{col}" opacity="0.85"/>\n'
        s += f'<text x="{gx + bar_w/2}" y="{base_y - ph - 6}" text-anchor="middle" font-size="10" font-weight="600">{prove_ms} ms</text>\n'

        # total bar
        th = (total_ms / max_val) * chart_h
        tx = gx + bar_w + 6
        s += f'<rect x="{tx}" y="{base_y - th}" width="{bar_w}" height="{th}" rx="3" fill="{col}" opacity="0.45"/>\n'
        s += f'<text x="{tx + bar_w/2}" y="{base_y - th - 6}" text-anchor="middle" font-size="10">{total_ms} ms</text>\n'

        # label
        lines = label.split('\n')
        for li, line in enumerate(lines):
            ly = base_y + 18 + li * 14
            s += f'<text x="{gx + bar_w + 3}" y="{ly}" text-anchor="middle" font-size="10">{line}</text>\n'

    # axis
    s += f'<line x1="{margin_l - 10}" y1="{base_y}" x2="{W - 20}" y2="{base_y}" stroke="#ccc" stroke-width="1"/>\n'

    # legend
    s += f'<rect x="{W - 200}" y="{margin_t}" width="12" height="12" rx="2" fill="{COLORS[0]}" opacity="0.85"/>\n'
    s += f'<text x="{W - 183}" y="{margin_t + 10}" font-size="10">prove_with_witness</text>\n'
    s += f'<rect x="{W - 200}" y="{margin_t + 20}" width="12" height="12" rx="2" fill="{COLORS[0]}" opacity="0.45"/>\n'
    s += f'<text x="{W - 183}" y="{margin_t + 30}" font-size="10">total prove command</text>\n'

    s += svg_footer()
    with open(os.path.join(OUT, "4_speedup_impact.svg"), "w") as f:
        f.write(s)

# ─── Chart 5: WHIR Round Cost Decay ────────────────────────────────
def chart_whir_rounds():
    rounds = [
        (1, 6.48, 75.6, 0.27),
        (2, 2.26, 36.9, 0.08),
        (3, 0.82, 19.1, 0.07),
        (4, 0.22, 10.6, 0.06),
        (5, 0.05,  6.36, 0.04),
    ]
    W, H = 560, 300
    margin_l, margin_r, margin_t, margin_b = 60, 30, 50, 50
    chart_w = W - margin_l - margin_r
    chart_h = H - margin_t - margin_b
    max_val = 80

    s = svg_header(W, H)
    s += f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" font-weight="600">WHIR Round Cost Decay (w1 inner_blinded_prove)</text>\n'

    bar_group_w = chart_w / len(rounds)
    bar_w = bar_group_w * 0.25

    for i, (rnd, sc, irs, op) in enumerate(rounds):
        gx = margin_l + i * bar_group_w + bar_group_w * 0.1
        base_y = margin_t + chart_h

        # IRS Commit bar (dominant)
        ih = (irs / max_val) * chart_h
        s += f'<rect x="{gx}" y="{base_y - ih}" width="{bar_w}" height="{ih}" rx="2" fill="{COLORS[2]}" opacity="0.85"/>\n'
        s += f'<text x="{gx + bar_w/2}" y="{base_y - ih - 4}" text-anchor="middle" font-size="9" font-weight="600">{irs:.1f}</text>\n'

        # Sumcheck bar
        sh = (sc / max_val) * chart_h
        sx = gx + bar_w + 4
        s += f'<rect x="{sx}" y="{base_y - sh}" width="{bar_w}" height="{sh}" rx="2" fill="{COLORS[5]}" opacity="0.85"/>\n'
        if sh > 8:
            s += f'<text x="{sx + bar_w/2}" y="{base_y - sh - 4}" text-anchor="middle" font-size="9">{sc:.1f}</text>\n'

        # Round label
        s += f'<text x="{gx + bar_w + 2}" y="{base_y + 16}" text-anchor="middle" font-size="11">R{rnd}</text>\n'

    # Y axis ticks
    for tick in [0, 20, 40, 60, 80]:
        ty = margin_t + chart_h - (tick / max_val) * chart_h
        s += f'<text x="{margin_l - 8}" y="{ty + 4}" text-anchor="end" font-size="9" fill="#888">{tick}</text>\n'
        s += f'<line x1="{margin_l}" y1="{ty}" x2="{W - margin_r}" y2="{ty}" stroke="#eee" stroke-width="1"/>\n'
    s += f'<text x="{margin_l - 35}" y="{margin_t + chart_h/2}" text-anchor="middle" font-size="10" fill="#888" transform="rotate(-90,{margin_l - 35},{margin_t + chart_h/2})">ms</text>\n'

    # Legend
    s += f'<rect x="{W - 170}" y="{margin_t + 5}" width="12" height="12" rx="2" fill="{COLORS[2]}"/>\n'
    s += f'<text x="{W - 153}" y="{margin_t + 15}" font-size="10">IRS Commit (NTT+Merkle)</text>\n'
    s += f'<rect x="{W - 170}" y="{margin_t + 23}" width="12" height="12" rx="2" fill="{COLORS[5]}"/>\n'
    s += f'<text x="{W - 153}" y="{margin_t + 33}" font-size="10">Sumcheck</text>\n'

    s += svg_footer()
    with open(os.path.join(OUT, "5_whir_rounds.svg"), "w") as f:
        f.write(s)

# ─── Chart 6: Memory Profile ───────────────────────────────────────
def chart_memory():
    phases = [
        ("Read key",   581),
        ("Solve w1",   389),
        ("Commit w1",  475),
        ("Solve w2",   607),
        ("Commit w2",  688),
        ("prove_noir", 908),
    ]
    W, H = 560, 280
    margin_l, margin_r, margin_t, margin_b = 80, 30, 50, 50
    chart_w = W - margin_l - margin_r
    chart_h = H - margin_t - margin_b
    max_val = 1000

    s = svg_header(W, H)
    s += f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" font-weight="600">Peak Memory by Phase (MB)</text>\n'

    n = len(phases)
    step = chart_w / (n - 1)

    # area fill
    points_top = []
    for i, (_, mem) in enumerate(phases):
        x = margin_l + i * step
        y = margin_t + chart_h - (mem / max_val) * chart_h
        points_top.append(f"{x:.0f},{y:.0f}")
    points_bot = f"{margin_l + (n-1)*step:.0f},{margin_t + chart_h:.0f} {margin_l:.0f},{margin_t + chart_h:.0f}"
    s += f'<polygon points="{" ".join(points_top)} {points_bot}" fill="{COLORS[0]}" opacity="0.15"/>\n'

    # line
    s += f'<polyline points="{" ".join(points_top)}" fill="none" stroke="{COLORS[0]}" stroke-width="2.5"/>\n'

    # dots + labels
    for i, (name, mem) in enumerate(phases):
        x = margin_l + i * step
        y = margin_t + chart_h - (mem / max_val) * chart_h
        s += f'<circle cx="{x:.0f}" cy="{y:.0f}" r="4" fill="{COLORS[0]}"/>\n'
        s += f'<text x="{x:.0f}" y="{y - 10:.0f}" text-anchor="middle" font-size="10" font-weight="600">{mem}</text>\n'
        s += f'<text x="{x:.0f}" y="{margin_t + chart_h + 18}" text-anchor="middle" font-size="9">{name}</text>\n'

    # Y axis
    for tick in [0, 250, 500, 750, 1000]:
        ty = margin_t + chart_h - (tick / max_val) * chart_h
        s += f'<text x="{margin_l - 8}" y="{ty + 4}" text-anchor="end" font-size="9" fill="#888">{tick}</text>\n'
        s += f'<line x1="{margin_l}" y1="{ty}" x2="{W - margin_r}" y2="{ty}" stroke="#f0f0f0" stroke-width="1"/>\n'

    s += svg_footer()
    with open(os.path.join(OUT, "6_memory.svg"), "w") as f:
        f.write(s)

# ─── Run all ────────────────────────────────────────────────────────
chart_pipeline()
chart_cpu_subsystems()
chart_mul_callers()
chart_speedup()
chart_whir_rounds()
chart_memory()
print(f"Charts written to {OUT}/")
for f in sorted(os.listdir(OUT)):
    if f.endswith('.svg'):
        print(f"  {f}")
