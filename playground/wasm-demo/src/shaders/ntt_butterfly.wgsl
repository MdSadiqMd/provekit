// NTT Butterfly Compute Shader for BN254 Scalar Field
// Cooley-Tukey DIT Normal-to-Reverse bit order, matching ProveKit's ntt_nr.
// One dispatch per NTT stage.

@group(0) @binding(0) var<storage, read_write> elements: array<u32>;
@group(0) @binding(1) var<storage, read> twiddles: array<u32>;
@group(0) @binding(2) var<uniform> params: NTTParams;

struct NTTParams {
    n: u32,
    log_n: u32,
    stage: u32,
    num_groups: u32,
    pairs_per_group: u32,
};

const LIMBS: u32 = 9u;
const LIMB_MASK_C: u32 = 0x1FFFFFFFu;
const LIMB_BITS_C: u32 = 29u;

// BN254 scalar field modulus (correct 9x29-bit decomposition)
const PM0: u32 = 0x10000001u;
const PM1: u32 = 0x1F0FAC9Fu;
const PM2: u32 = 0x0E5C2450u;
const PM3: u32 = 0x07D090F3u;
const PM4: u32 = 0x1585D283u;
const PM5: u32 = 0x02DB40C0u;
const PM6: u32 = 0x00A6E141u;
const PM7: u32 = 0x0E5C2634u;
const PM8: u32 = 0x0030644Eu;
const MU_C: u32 = 0x0FFFFFFFu;

fn get_p() -> array<u32, 9> {
    var p: array<u32, 9>;
    p[0] = PM0; p[1] = PM1; p[2] = PM2; p[3] = PM3;
    p[4] = PM4; p[5] = PM5; p[6] = PM6; p[7] = PM7;
    p[8] = PM8;
    return p;
}

fn f_add(a: array<u32, 9>, b: array<u32, 9>) -> array<u32, 9> {
    var result: array<u32, 9>;
    var carry: u32 = 0u;
    for (var i = 0u; i < 9u; i = i + 1u) {
        let sum = a[i] + b[i] + carry;
        result[i] = sum & LIMB_MASK_C;
        carry = sum >> LIMB_BITS_C;
    }
    return f_reduce(result);
}

fn f_sub(a: array<u32, 9>, b: array<u32, 9>) -> array<u32, 9> {
    var result: array<u32, 9>;
    var borrow: u32 = 0u;
    let p = get_p();
    for (var i = 0u; i < 9u; i = i + 1u) {
        let diff_val = a[i] + (1u << LIMB_BITS_C) - b[i] - borrow;
        result[i] = diff_val & LIMB_MASK_C;
        borrow = 1u - (diff_val >> LIMB_BITS_C);
    }
    if (borrow != 0u) {
        var c: u32 = 0u;
        for (var i = 0u; i < 9u; i = i + 1u) {
            let sum = result[i] + p[i] + c;
            result[i] = sum & LIMB_MASK_C;
            c = sum >> LIMB_BITS_C;
        }
    }
    return result;
}

fn f_reduce(a: array<u32, 9>) -> array<u32, 9> {
    let p = get_p();
    var result: array<u32, 9>;
    var borrow: u32 = 0u;
    for (var i = 0u; i < 9u; i = i + 1u) {
        let diff_val = a[i] + (1u << LIMB_BITS_C) - p[i] - borrow;
        result[i] = diff_val & LIMB_MASK_C;
        borrow = 1u - (diff_val >> LIMB_BITS_C);
    }
    if (borrow != 0u) { return a; }
    return result;
}

fn mul29(a: u32, b: u32) -> vec2<u32> {
    let a_lo = a & 0x7FFFu;
    let a_hi = a >> 15u;
    let b_lo = b & 0x7FFFu;
    let b_hi = b >> 15u;
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    let mid = lh + hl;
    let low = ll + ((mid & 0x7FFFu) << 15u);
    let carry_from_low = low >> 29u;
    return vec2<u32>(low & LIMB_MASK_C, 2u * (hh + (mid >> 15u)) + carry_from_low);
}

fn f_mul(a: array<u32, 9>, b: array<u32, 9>) -> array<u32, 9> {
    var t: array<u32, 10>;
    for (var k = 0u; k < 10u; k = k + 1u) { t[k] = 0u; }
    let p = get_p();
    for (var i = 0u; i < 9u; i = i + 1u) {
        var carry: u32 = 0u;
        for (var j = 0u; j < 9u; j = j + 1u) {
            let prod = mul29(a[i], b[j]);
            let sum = prod.x + t[j] + carry;
            t[j] = sum & LIMB_MASK_C;
            carry = prod.y + (sum >> LIMB_BITS_C);
        }
        t[9] = t[9] + carry;
        let m = (t[0] * MU_C) & LIMB_MASK_C;
        carry = 0u;
        let prod0 = mul29(m, p[0]);
        let sum0 = prod0.x + t[0] + carry;
        carry = prod0.y + (sum0 >> LIMB_BITS_C);
        for (var j = 1u; j < 9u; j = j + 1u) {
            let prod = mul29(m, p[j]);
            let sum = prod.x + t[j] + carry;
            t[j - 1u] = sum & LIMB_MASK_C;
            carry = prod.y + (sum >> LIMB_BITS_C);
        }
        t[8] = t[9] + carry;
        t[9] = 0u;
    }
    var result: array<u32, 9>;
    for (var i = 0u; i < 9u; i = i + 1u) { result[i] = t[i]; }
    return f_reduce(result);
}

fn load_element(index: u32) -> array<u32, 9> {
    var r: array<u32, 9>;
    let base = index * LIMBS;
    for (var i = 0u; i < LIMBS; i = i + 1u) { r[i] = elements[base + i]; }
    return r;
}

fn store_element(index: u32, val: array<u32, 9>) {
    let base = index * LIMBS;
    for (var i = 0u; i < LIMBS; i = i + 1u) { elements[base + i] = val[i]; }
}

fn load_twiddle(index: u32) -> array<u32, 9> {
    var r: array<u32, 9>;
    let base = index * LIMBS;
    for (var i = 0u; i < LIMBS; i = i + 1u) { r[i] = twiddles[base + i]; }
    return r;
}

@compute @workgroup_size(256)
fn ntt_butterfly(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let thread_id = global_id.x;
    let total_pairs = params.n / 2u;
    if (thread_id >= total_pairs) { return; }
    
    let group_idx = thread_id / params.pairs_per_group;
    let pair_idx = thread_id % params.pairs_per_group;
    let even_idx = group_idx * 2u * params.pairs_per_group + pair_idx;
    let odd_idx = even_idx + params.pairs_per_group;
    
    let omega = load_twiddle(group_idx);
    let even = load_element(even_idx);
    let odd = load_element(odd_idx);
    
    let omega_times_odd = f_mul(omega, odd);
    let new_even = f_add(even, omega_times_odd);
    let new_odd = f_sub(even, omega_times_odd);
    
    store_element(even_idx, new_even);
    store_element(odd_idx, new_odd);
}
