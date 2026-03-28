// BN254 Scalar Field Arithmetic for WebGPU
// Field: Fr = Z_p where p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// Representation: 9 × 29-bit "reduced-radix" limbs packed in u32 values
// This follows the Mitscha-Baude approach (ZPrize 2023 winner) which avoids
// 64-bit SIMD issues on WebGPU and keeps carry chains manageable.
//
// Total capacity: 9 × 29 = 261 bits > 254 bits needed for BN254 Fr.

// BN254 scalar field modulus p in 9×29-bit limbs (little-endian)
const P0: u32 = 0x10000001u;
const P1: u32 = 0x1F0FAC9Fu;
const P2: u32 = 0x0E5C2450u;
const P3: u32 = 0x07D090F3u;
const P4: u32 = 0x1585D283u;
const P5: u32 = 0x02DB40C0u;
const P6: u32 = 0x00A6E141u;
const P7: u32 = 0x0E5C2634u;
const P8: u32 = 0x0030644Eu;

// Montgomery constant: mu = -p^(-1) mod 2^29
const MU: u32 = 0x0FFFFFFFu;

// Bitmask for 29-bit limb
const LIMB_MASK: u32 = 0x1FFFFFFFu;
const LIMB_BITS: u32 = 29u;

// R^2 mod p for Montgomery domain conversion (R = 2^261)
const R2_0: u32 = 0x05B69BD4u;
const R2_1: u32 = 0x06170A5Au;
const R2_2: u32 = 0x020CDDCEu;
const R2_3: u32 = 0x1DB6310Bu;
const R2_4: u32 = 0x0E54D0FFu;
const R2_5: u32 = 0x1CF855E3u;
const R2_6: u32 = 0x1C15E103u;
const R2_7: u32 = 0x07D09161u;
const R2_8: u32 = 0x000A054Au;

struct FieldElement {
    limbs: array<u32, 9>,
};

fn field_add(a: FieldElement, b: FieldElement) -> FieldElement {
    var result: FieldElement;
    var carry: u32 = 0u;
    for (var i = 0u; i < 9u; i = i + 1u) {
        let sum = a.limbs[i] + b.limbs[i] + carry;
        result.limbs[i] = sum & LIMB_MASK;
        carry = sum >> LIMB_BITS;
    }
    return field_reduce(result);
}

fn field_sub(a: FieldElement, b: FieldElement) -> FieldElement {
    var result: FieldElement;
    var borrow: u32 = 0u;
    let p = get_modulus();
    for (var i = 0u; i < 9u; i = i + 1u) {
        let diff_val = a.limbs[i] + (1u << LIMB_BITS) - b.limbs[i] - borrow;
        result.limbs[i] = diff_val & LIMB_MASK;
        borrow = 1u - (diff_val >> LIMB_BITS);
    }
    if (borrow != 0u) {
        var c: u32 = 0u;
        for (var i = 0u; i < 9u; i = i + 1u) {
            let sum = result.limbs[i] + p.limbs[i] + c;
            result.limbs[i] = sum & LIMB_MASK;
            c = sum >> LIMB_BITS;
        }
    }
    return result;
}

fn field_mul(a: FieldElement, b: FieldElement) -> FieldElement {
    var t: array<u32, 10>;
    for (var k = 0u; k < 10u; k = k + 1u) { t[k] = 0u; }
    let p = get_modulus();
    for (var i = 0u; i < 9u; i = i + 1u) {
        var carry: u32 = 0u;
        for (var j = 0u; j < 9u; j = j + 1u) {
            let prod = mul29(a.limbs[i], b.limbs[j]);
            let sum = prod.x + t[j] + carry;
            t[j] = sum & LIMB_MASK;
            carry = prod.y + (sum >> LIMB_BITS);
        }
        t[9] = t[9] + carry;
        let m = (t[0] * MU) & LIMB_MASK;
        carry = 0u;
        let prod0 = mul29(m, p.limbs[0]);
        let sum0 = prod0.x + t[0] + carry;
        carry = prod0.y + (sum0 >> LIMB_BITS);
        for (var j = 1u; j < 9u; j = j + 1u) {
            let prod = mul29(m, p.limbs[j]);
            let sum = prod.x + t[j] + carry;
            t[j - 1u] = sum & LIMB_MASK;
            carry = prod.y + (sum >> LIMB_BITS);
        }
        t[8] = t[9] + carry;
        t[9] = 0u;
    }
    var result: FieldElement;
    for (var i = 0u; i < 9u; i = i + 1u) { result.limbs[i] = t[i]; }
    return field_reduce(result);
}

fn field_reduce(a: FieldElement) -> FieldElement {
    let p = get_modulus();
    var result: FieldElement;
    var borrow: u32 = 0u;
    for (var i = 0u; i < 9u; i = i + 1u) {
        let diff_val = a.limbs[i] + (1u << LIMB_BITS) - p.limbs[i] - borrow;
        result.limbs[i] = diff_val & LIMB_MASK;
        borrow = 1u - (diff_val >> LIMB_BITS);
    }
    if (borrow != 0u) { return a; }
    return result;
}

fn get_modulus() -> FieldElement {
    var p: FieldElement;
    p.limbs[0] = P0; p.limbs[1] = P1; p.limbs[2] = P2;
    p.limbs[3] = P3; p.limbs[4] = P4; p.limbs[5] = P5;
    p.limbs[6] = P6; p.limbs[7] = P7; p.limbs[8] = P8;
    return p;
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
    return vec2<u32>(low & LIMB_MASK, 2u * (hh + (mid >> 15u)) + carry_from_low);
}
