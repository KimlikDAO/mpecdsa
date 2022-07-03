// This module implements field operations modulo
// 115792089237316195423570985008687907853269984665640564039457584007908834671663
// or 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// elements are stored as 5 uint64_t's in base 2^52. The values are allowed to contain >52 each.
//
/// aas, neucrypt
use super::Fq;
use rand::Rng;
use std::fmt;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct FSecp256 {
    pub v: [u64; 5],
}

/** Implements arithmetic modulo FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F,
 *  represented as 5 uint64_t's in base 2^52. The values are allowed to contain >52 each. In particular,
 *  each FieldElem has a 'magnitude' associated with it. Internally, a magnitude M means each element
 *  is at most M*(2^53-1), except the most significant one, which is limited to M*(2^49-1). All operations
 *  accept any input with magnitude at most M, and have different rules for propagating magnitude to their
 *  output.
 */

impl fmt::Debug for FSecp256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{:0x} {:0x} {:0x} {:0x} {:0x}]",
            self.v[0], self.v[1], self.v[2], self.v[3], self.v[4]
        )
    }
}

impl fmt::Display for FSecp256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{:0x}{:0x}{:0x}{:0x}",
            self.v[3], self.v[2], self.v[1], self.v[0]
        )
    }
}

const M: u128 = 0x0000000000000000000FFFFFFFFFFFFF;
const R: u128 = 0x00000000000000000000001000003D10;

impl FSecp256 {
    fn chain(&self) -> (FSecp256, FSecp256, FSecp256) {
        //  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]

        let x2 = self.sqr();
        let x2 = x2.mul(self); // 2^2 - 1
        let x3 = x2.sqr().mul(self); // 2^3 - 1
        let x6 = x3.sqr().sqr().sqr().mul(&x3); // 2^6 - 1
        let x9 = x6.sqr().sqr().sqr().mul(&x3); // 2^9 - 1
        let x11 = x9.sqr().sqr().mul(&x2);
        let x22 = x11
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .mul(&x11);
        let x44 = {
            let mut r = x22.clone();
            for _ in 0..22 {
                r = r.sqr();
            }
            r
        }
        .mul(&x22);

        let x88 = {
            let mut r = x44.clone();
            for _ in 0..44 {
                r = r.sqr();
            }
            r
        }
        .mul(&x44);

        let x176 = {
            let mut r = x88.clone();
            for _ in 0..88 {
                r = r.sqr();
            }
            r
        }
        .mul(&x88);

        let x220 = {
            let mut r = x176;
            for _ in 0..44 {
                r = r.sqr();
            }
            r
        }
        .mul(&x44);

        let x223 = x220.sqr().sqr().sqr().mul(&x3);
        (x2, x22, x223)
    }
}

impl Fq for FSecp256 {
    const ONE: FSecp256 = FSecp256 { v: [1, 0, 0, 0, 0] };
    const ZERO: FSecp256 = FSecp256 { v: [0, 0, 0, 0, 0] };
    const NBITS: usize = 256;
    const NBYTES: usize = (256 + 7) / 8;

    fn is_zero(&self) -> bool {
        /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
        /* Reduce t4 at the start so there will be at most a single carry from the first pass */
        let x = self.v[4] >> 48;
        let t4 = self.v[4] & 0x0FFFFFFFFFFFF;

        /* The first pass ensures the magnitude is 1, ... */
        let t0 = self.v[0] + x * 0x1000003D1;
        let t1 = self.v[1] + (t0 >> 52);
        let t0 = t0 & 0xFFFFFFFFFFFFF;
        let z0 = t0;
        let z1 = t0 ^ 0x1000003D0;
        let t2 = self.v[2] + (t1 >> 52);
        let t1 = t1 & 0xFFFFFFFFFFFFF;
        let z0 = z0 | t1;
        let z1 = z1 & t1;
        let t3 = self.v[3] + (t2 >> 52);
        let t2 = t2 & 0xFFFFFFFFFFFFF;
        let z0 = z0 | t2;
        let z1 = z1 & t2;
        let t4 = t4 + (t3 >> 52);
        let t3 = t3 & 0xFFFFFFFFFFFFF;
        let z0 = z0 | t3;
        let z1 = z1 & t3;
        let z0 = z0 | t4;
        let z1 = z1 & t4 ^ 0xF000000000000;

        /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
        debug_assert!(t4 >> 49 == 0);

        return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFF);
    }

    fn is_one(&self) -> bool {
        // add reduction
        return (self.v[0] == 1) && (self.v[2] == 0) && (self.v[3] == 0) && (self.v[4] == 0);
    }

    fn rand(rng: &mut dyn Rng) -> Self {
        let r0 = rng.next_u64() & 0xFFFFFFFFFFFFF;
        let r1 = rng.next_u64() & 0xFFFFFFFFFFFFF;
        let r2 = rng.next_u64() & 0xFFFFFFFFFFFFF;
        let r3 = rng.next_u64() & 0xFFFFFFFFFFFFF;
        let r4 = rng.next_u64() & 0xFFFFFFFFFFFF;

        let mut r = FSecp256 {
            v: [r0, r1, r2, r3, r4],
        };
        r.normalize_weak();
        r
    }

    fn from_slice(r: &[u64]) -> FSecp256 {
        FSecp256 {
            v: [r[0], r[1], r[2], r[3], r[4]],
        }
    }

    // fn tostring(&self) -> String;

    fn add(&self, a: &FSecp256) -> FSecp256 {
        // secp256k1_fe_verify(a);
        return FSecp256 {
            v: [
                self.v[0] + a.v[0],
                self.v[1] + a.v[1],
                self.v[2] + a.v[2],
                self.v[3] + a.v[3],
                self.v[4] + a.v[4],
            ],
        };
        // r->magnitude += a->magnitude;
        // r->normalized = 0;
        // secp256k1_fe_verify(r);
    }

    fn sub(&self, b: &FSecp256) -> FSecp256 {
        let mut b2 = b.clone();
        b2.normalize_weak();
        self.add(&b2.neg(1))
    }

    /// only works when a has only a few bits in it
    fn muli(&self, a: u64) -> FSecp256 {
        return FSecp256 {
            v: [
                self.v[0] * a,
                self.v[1] * a,
                self.v[2] * a,
                self.v[3] * a,
                self.v[4] * a,
            ],
        };
    }

    fn equals(&self, b: &FSecp256) -> bool {
        return self.v[0] == b.v[0]
            && self.v[1] == b.v[1]
            && self.v[2] == b.v[2]
            && self.v[3] == b.v[3]
            && self.v[4] == b.v[4];
    }

    /// only works when the value is reduced
    fn bit(&self, i: u32) -> bool {
        let j = i % 52;
        let k = (i / 52) as usize;
        assert!(k < 5);

        return ((self.v[k] >> j) & 0x1) > 0;
    }

    // // memory oblivious routines
    // // sets y = (1-sel)*a + sel*b with an oblivious memory access pattern
    fn mux(y: &mut FSecp256, a: &FSecp256, b: &FSecp256, sel: u32) {
        let z0 = (sel as i64 - 1) as u64;
        let z1 = !z0;

        for i in 0..5 {
            y.v[i] = (a.v[i] & z0) ^ (b.v[i] & z1);
        }
    }

    // if sel is true, then mov a into y obliviously
    fn mov(&mut self, a: &FSecp256, sel: bool) {
        let m0 = if sel { 0 } else { !0 };
        let m1 = !m0;
        self.v[0] = (self.v[0] & m0) | (a.v[0] & m1);
        self.v[1] = (self.v[1] & m0) | (a.v[1] & m1);
        self.v[2] = (self.v[2] & m0) | (a.v[2] & m1);
        self.v[3] = (self.v[3] & m0) | (a.v[3] & m1);
        self.v[4] = (self.v[4] & m0) | (a.v[4] & m1);
    }

    // // swaps a and b if sel=1 with an oblivious memory access pattern
    fn swap(a: &mut FSecp256, b: &mut FSecp256, sel: u32) {
        let c = (!(sel as i64 - 1)) as u64; // c is either 000 or fff..f
        for i in 0..5 {
            let t = c & (a.v[i] ^ b.v[i]);
            a.v[i] = a.v[i] ^ t;
            b.v[i] = b.v[i] ^ t;
        }
    }

    // Zq for the order, field for the group
    fn mul(&self, b: &FSecp256) -> FSecp256 {
        let a = self;

        debug_assert!(a.v[0] >> 56 == 0);
        debug_assert!(a.v[1] >> 56 == 0);
        debug_assert!(a.v[2] >> 56 == 0);
        debug_assert!(a.v[3] >> 56 == 0);
        debug_assert!(a.v[4] >> 52 == 0);
        debug_assert!(b.v[0] >> 56 == 0);
        debug_assert!(b.v[1] >> 56 == 0);
        debug_assert!(b.v[2] >> 56 == 0);
        debug_assert!(b.v[3] >> 56 == 0);
        debug_assert!(b.v[4] >> 52 == 0);

        /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
         *  px is a shorthand for sum(a[i]*b[x-i], i=0..x).
         *  Note that [x 0 0 0 0 0] = [x*R].
         */

        let d = (a.v[0] as u128) * (b.v[3] as u128)
            + (a.v[1] as u128) * (b.v[2] as u128)
            + (a.v[2] as u128) * (b.v[1] as u128)
            + (a.v[3] as u128) * (b.v[0] as u128);
        debug_assert!(d >> 114 == 0);
        /* [d 0 0 0] = [p3 0 0 0] */
        let c = (a.v[4] as u128) * (b.v[4] as u128);
        debug_assert!(c >> 112 == 0);
        /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
        let d = d + (c & M) * R;
        let c = c >> 52;
        debug_assert!(d >> 115 == 0);
        debug_assert!(c >> 60 == 0);
        /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
        let t3 = d & M;
        let d = d >> 52;
        debug_assert!(t3 >> 52 == 0);
        debug_assert!(d >> 63 == 0);
        /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

        let d = d
            + (a.v[0] as u128) * (b.v[4] as u128)
            + (a.v[1] as u128) * (b.v[3] as u128)
            + (a.v[2] as u128) * (b.v[2] as u128)
            + (a.v[3] as u128) * (b.v[1] as u128)
            + (a.v[4] as u128) * (b.v[0] as u128);
        debug_assert!(d >> 115 == 0);
        // println!("d4: {:?}", d);

        // /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let d = d + c * R;
        debug_assert!(d >> 116 == 0);
        // /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let t4 = d & M;
        let d = d >> 52;
        debug_assert!(t4 >> 52 == 0);
        debug_assert!(d >> 64 == 0);
        // /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let tx = t4 >> 48;
        let t4 = t4 & (M >> 4);
        // tx = (t4 >> 48); t4 &= (M >> 4);
        debug_assert!(tx >> 4 == 0);
        debug_assert!(t4 >> 48 == 0);
        // /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let c = (a.v[0] as u128) * (b.v[0] as u128);
        debug_assert!(c >> 112 == 0);
        // /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
        let d = d
            + (a.v[1] as u128) * b.v[4] as u128
            + (a.v[2] as u128) * b.v[3] as u128
            + (a.v[3] as u128) * b.v[2] as u128
            + (a.v[4] as u128) * b.v[1] as u128;
        debug_assert!(d >> 115 == 0);

        // /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let u0 = d & M;
        let d = d >> 52;
        debug_assert!(u0 >> 52 == 0);
        debug_assert!(d >> 63 == 0);
        // /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        // /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let u0 = (u0 << 4) | tx;
        // u0 = (u0 << 4) | tx;
        debug_assert!(u0 >> 56 == 0);
        // /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let c = c + (u0 * (R >> 4));
        // c += (uint128_t)u0 * (R >> 4);
        debug_assert!(c >> 115 == 0);
        // /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let r0 = (c & M) as u64;
        let c = c >> 52;
        // r[0] = c & M; c >>= 52;
        debug_assert!(r0 >> 52 == 0);
        debug_assert!(c >> 61 == 0);
        // /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let c = c + (a.v[0] as u128) * (b.v[1] as u128) + (a.v[1] as u128) * (b.v[0] as u128);

        // c += (uint128_t)a0 * b[1]
        //    + (uint128_t)a1 * b[0];
        debug_assert!(c >> 114 == 0);
        // /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
        let d = d
            + (a.v[2] as u128) * b.v[4] as u128
            + (a.v[3] as u128) * b.v[3] as u128
            + (a.v[4] as u128) * b.v[2] as u128;
        debug_assert!(d >> 114 == 0);

        // /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
        let c = c + (d & M) * R;
        let d = d >> 52;
        debug_assert!(c >> 115 == 0);
        debug_assert!(d >> 62 == 0);
        // /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
        let r1 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r1 >> 52 == 0);
        debug_assert!(c >> 63 == 0);
        // /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
        let c = c
            + (a.v[0] as u128 * b.v[2] as u128)
            + (a.v[1] as u128 * b.v[1] as u128)
            + (a.v[2] as u128 * b.v[0] as u128);
        debug_assert!(c >> 114 == 0);
        // println!("c2: {:?}", c);

        // /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
        let d = d + (a.v[3] as u128 * b.v[4] as u128) + (a.v[4] as u128 * b.v[3] as u128);
        debug_assert!(d >> 114 == 0);
        // println!("d7: {:x}", d);
        // /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let c = c + (d & M) * R;
        let d = d >> 52;
        debug_assert!(c >> 115 == 0);
        debug_assert!(d >> 62 == 0);
        // /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        // /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let r2 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r2 >> 52 == 0);
        debug_assert!(c >> 63 == 0);
        // /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let c = c + d * R + t3;
        debug_assert!(c >> 100 == 0);
        // /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let r3 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r3 >> 52 == 0);
        debug_assert!(c >> 48 == 0);
        // /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let c = c + t4;
        debug_assert!(c >> 49 == 0);
        // /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let r4 = c as u64;
        debug_assert!(r4 >> 49 == 0);
        // /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        FSecp256 {
            v: [r0, r1, r2, r3, r4],
        }
    }

    #[inline(never)] // workaround for apparent bug in compiler after version 1.28
    fn sqr(&self) -> FSecp256 {
        let a = self;

        debug_assert!(a.v[0] >> 56 == 0);
        debug_assert!(a.v[1] >> 56 == 0);
        debug_assert!(a.v[2] >> 56 == 0);
        debug_assert!(a.v[3] >> 56 == 0);
        debug_assert!(a.v[4] >> 52 == 0);

        /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
         *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
         *  Note that [x 0 0 0 0 0] = [x*R].
         */

        let d = (a.v[0] as u128 * 2) * (a.v[3] as u128) + (a.v[1] as u128 * 2) * (a.v[2] as u128);
        debug_assert!(d >> 114 == 0);
        /* [d 0 0 0] = [p3 0 0 0] */
        let c = a.v[4] as u128 * a.v[4] as u128;
        debug_assert!(c >> 112 == 0);
        /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
        let d = d + (c & M) * R;
        let c = c >> 52;
        debug_assert!(d >> 115 == 0);
        debug_assert!(c >> 60 == 0);
        /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
        let t3 = d & M;
        let d = d >> 52;
        debug_assert!(t3 >> 52 == 0);
        debug_assert!(d >> 63 == 0);
        /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

        let a4 = a.v[4] as u128 * 2;
        let d = d
            + (a.v[0] as u128 * a4)
            + ((a.v[1] as u128 * 2) * a.v[3] as u128)
            + (a.v[2] as u128 * a.v[2] as u128);
        debug_assert!(d >> 115 == 0);
        /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let d = d + c * R;
        debug_assert!(d >> 116 == 0);
        /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let t4 = d & M;
        let d = d >> 52;
        debug_assert!(t4 >> 52 == 0);
        debug_assert!(d >> 64 == 0);
        /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
        let tx = t4 >> 48;
        let t4 = t4 & (M >> 4);
        debug_assert!(tx >> 4 == 0);
        debug_assert!(t4 >> 48 == 0);
        /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

        let c = a.v[0] as u128 * a.v[0] as u128;
        debug_assert!(c >> 112 == 0);
        /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
        let d = d + a.v[1] as u128 * a4 + (a.v[2] as u128 * 2) * a.v[3] as u128;
        debug_assert!(d >> 114 == 0);
        /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let u0 = d & M;
        let d = d >> 52;
        debug_assert!(u0 >> 52 == 0);
        debug_assert!(d >> 62 == 0);
        /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let u0 = (u0 << 4) | tx;
        debug_assert!(u0 >> 56 == 0);
        /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let c = c + u0 * (R >> 4);
        debug_assert!(c >> 113 == 0);
        /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
        let r0 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r0 >> 52 == 0);
        debug_assert!(c >> 61 == 0);
        /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

        let a0 = a.v[0] as u128 * 2;
        let c = c + a0 * a.v[1] as u128;
        debug_assert!(c >> 114 == 0);
        /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
        let d = d + a.v[2] as u128 * a4 + a.v[3] as u128 * a.v[3] as u128;
        debug_assert!(d >> 114 == 0);
        /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
        let c = c + (d & M) * R;
        let d = d >> 52;
        debug_assert!(c >> 115 == 0);
        debug_assert!(d >> 62 == 0);
        /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
        let r1 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r1 >> 52 == 0);
        debug_assert!(c >> 63 == 0);
        /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

        let c = c + a0 * a.v[2] as u128 + a.v[1] as u128 * a.v[1] as u128;
        debug_assert!(c >> 114 == 0);
        /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
        let d = d + a.v[3] as u128 * a4;
        debug_assert!(d >> 114 == 0);
        /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let c = c + (d & M) * R;
        let d = d >> 52;
        debug_assert!(c >> 115 == 0);
        debug_assert!(d >> 62 == 0);
        /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let r2 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r2 >> 52 == 0);
        debug_assert!(c >> 63 == 0);
        /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        let c = c + d * R + t3;
        debug_assert!(c >> 100 == 0);
        /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let r3 = (c & M) as u64;
        let c = c >> 52;
        debug_assert!(r3 >> 52 == 0);
        debug_assert!(c >> 48 == 0);
        /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let c = c + t4;
        debug_assert!(c >> 49 == 0);
        /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        let r4 = c as u64;
        debug_assert!(r4 >> 49 == 0);
        /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        FSecp256 {
            v: [r0, r1, r2, r3, r4],
        }
    }

    fn sqrt(&self) -> Result<FSecp256, &'static str> {
        // binary rep of p+1/4 is
        // '0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110111111111111111111111100001100
        // the runs are length 2, length 22, length 223

        let (x2, x22, x223) = self.chain();

        /* The final result is then assembled using a sliding window over the blocks. */
        let t1 = {
            let mut r = x223;
            for _ in 0..23 {
                r = r.sqr();
            }
            r
        }
        .mul(&x22);

        let t1 = t1.sqr().sqr().sqr().sqr().sqr().sqr().mul(&x2);
        let t1 = t1.sqr().sqr();
        // *  As (p+1)/4 is an even number, it will have the same result for a and for
        // *  (-a). Only one of these two numbers actually has a square root however,
        // *  so we test at the end by squaring and comparing to the input.

        if self.equals(&t1.sqr()) {
            Ok(t1)
        } else {
            Err("does not have a root")
        }
    }

    fn inv(&self) -> FSecp256 {
        let a = self;
        // The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
        //  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
        //  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
        // '0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111011111111111111111111110000101101'

        let (x2, x22, x223) = self.chain();

        let t1 = {
            let mut r = x223;
            for _ in 0..23 {
                r = r.sqr();
            }
            r
        }
        .mul(&x22);

        let t1 = t1.sqr().sqr().sqr().sqr().sqr().mul(&a);
        let t1 = t1.sqr().sqr().sqr().mul(&x2);
        let t1 = t1.sqr().sqr().mul(&a);
        t1
    }

    fn neg(&self, m: u64) -> FSecp256 {
        // VERIFY_CHECK(a->magnitude <= m);
        // secp256k1_fe_verify(a);
        let r0 = 0xFFFFEFFFFFC2F * 2 * (m + 1) - self.v[0];
        let r1 = 0xFFFFFFFFFFFFF * 2 * (m + 1) - self.v[1];
        let r2 = 0xFFFFFFFFFFFFF * 2 * (m + 1) - self.v[2];
        let r3 = 0xFFFFFFFFFFFFF * 2 * (m + 1) - self.v[3];
        let r4 = 0x0FFFFFFFFFFFF * 2 * (m + 1) - self.v[4];

        let mut r = FSecp256 {
            v: [r0, r1, r2, r3, r4],
        };
        r.normalize();
        // r->magnitude = m + 1;
        // r->normalized = 0;
        // secp256k1_fe_verify(r);
        r
    }

    fn normalize(&mut self) {
        /* Reduce t4 at the start so there will be at most a single carry from the first pass */
        let x = self.v[4] >> 48;
        let t4 = self.v[4] & 0x0FFFFFFFFFFFF;

        /* The first pass ensures the magnitude is 1, ... */
        let t0 = self.v[0] + x * 0x1000003D1;
        let t1 = self.v[1] + (t0 >> 52);
        let t0 = t0 & 0xFFFFFFFFFFFFF;
        let t2 = self.v[2] + (t1 >> 52);
        let t1 = t1 & 0xFFFFFFFFFFFFF;
        let m = t1;

        //     t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
        let t3 = self.v[3] + (t2 >> 52);
        let t2 = t2 & 0xFFFFFFFFFFFFF;
        let m = m & t2;

        //     t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;
        let t4 = t4 + (t3 >> 52);
        let t3 = t3 & 0xFFFFFFFFFFFFF;
        let m = m & t3;

        debug_assert!(t4 >> 49 == 0);
        //     /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
        //     VERIFY_CHECK(t4 >> 49 == 0);

        //     /* At most a single final reduction is needed; check if the value is >= the field characteristic */
        let x = (t4 >> 48)
            | if (t4 == 0x0FFFFFFFFFFFF) & (m == 0xFFFFFFFFFFFFF) & (t0 >= 0xFFFFEFFFFFC2F) {
                1
            } else {
                0
            };

        //  Apply the final reduction (for constant-time behaviour, we do it always)
        let t0 = t0 + x * 0x1000003D1;
        let t1 = t1 + (t0 >> 52);
        let t0 = t0 & 0xFFFFFFFFFFFFF;
        let t2 = t2 + (t1 >> 52);
        let t1 = t1 & 0xFFFFFFFFFFFFF;
        let t3 = t3 + (t2 >> 52);
        let t2 = t2 & 0xFFFFFFFFFFFFF;
        let t4 = t4 + (t3 >> 52);
        let t3 = t3 & 0xFFFFFFFFFFFFF;

        //     /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
        //     VERIFY_CHECK(t4 >> 48 == x);
        debug_assert!(t4 >> 48 == x);

        //     /* Mask off the possible multiple of 2^256 from the final reduction */
        let t4 = t4 & 0x0FFFFFFFFFFFF;

        self.v[0] = t0;
        self.v[1] = t1;
        self.v[2] = t2;
        self.v[3] = t3;
        self.v[4] = t4;

        // #ifdef VERIFY
        //     r->magnitude = 1;
        //     r->normalized = 1;
        //     secp256k1_fe_verify(r);
        // #endif
    }

    fn normalize_weak(&mut self) {
        let r = self;
        //     /* Reduce t4 at the start so there will be at most a single carry from the first pass */
        let x = r.v[4] >> 48;
        let t4 = r.v[4] & 0x0FFFFFFFFFFFF;

        //     /* The first pass ensures the magnitude is 1, ... */
        let t0 = r.v[0] + x * 0x1000003D1;
        let t1 = r.v[1] + (t0 >> 52);
        let t0 = t0 & 0xFFFFFFFFFFFFF;
        let t2 = r.v[2] + (t1 >> 52);
        let t1 = t1 & 0xFFFFFFFFFFFFF;
        let t3 = r.v[3] + (t2 >> 52);
        let t2 = t2 & 0xFFFFFFFFFFFFF;
        let t4 = t4 + (t3 >> 52);
        let t3 = t3 & 0xFFFFFFFFFFFFF;
        debug_assert!(t4 >> 49 == 0);

        //     /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
        //     VERIFY_CHECK(t4 >> 49 == 0);
        r.v[0] = t0;
        r.v[1] = t1;
        r.v[2] = t2;
        r.v[3] = t3;
        r.v[4] = t4;

        // #ifdef VERIFY
        //     r->magnitude = 1;
        //     secp256k1_fe_verify(r);
        // #endif
    }

    fn from_bytes(b: &[u8]) -> FSecp256 {
        let r0: u64 = b[31] as u64
            | (b[30] as u64) << 8
            | (b[29] as u64) << 16
            | (b[28] as u64) << 24
            | (b[27] as u64) << 32
            | (b[26] as u64) << 40
            | ((b[25] as u64 & 0xF) << 48);
        let r1 = ((b[25] as u64) >> 4) & 0xF
            | (b[24] as u64) << 4
            | (b[23] as u64) << 12
            | (b[22] as u64) << 20
            | (b[21] as u64) << 28
            | (b[20] as u64) << 36
            | (b[19] as u64) << 44;
        let r2 = b[18] as u64
            | (b[17] as u64) << 8
            | (b[16] as u64) << 16
            | (b[15] as u64) << 24
            | (b[14] as u64) << 32
            | (b[13] as u64) << 40
            | ((b[12] as u64) & 0xF) << 48;
        let r3 = ((b[12] as u64) >> 4) & 0xF
            | (b[11] as u64) << 4
            | (b[10] as u64) << 12
            | (b[9] as u64) << 20
            | (b[8] as u64) << 28
            | (b[7] as u64) << 36
            | (b[6] as u64) << 44;
        let r4 = b[5] as u64
            | (b[4] as u64) << 8
            | (b[3] as u64) << 16
            | (b[2] as u64) << 24
            | (b[1] as u64) << 32
            | (b[0] as u64) << 40;

        return if r4 == 0x0FFFFFFFFFFFF
            && (r3 & r2 & r1) == 0xFFFFFFFFFFFFF
            && r0 >= 0xFFFFEFFFFFC2F
        {
            FSecp256 { v: [0, 0, 0, 0, 0] }
        } else {
            FSecp256 {
                v: [r0, r1, r2, r3, r4],
            }
        };
    }

    fn to_bytes(&self, r: &mut [u8]) {
        // #ifdef VERIFY
        //     VERIFY_CHECK(a->normalized);
        //     secp256k1_fe_verify(a);
        // #endif
        if r.len() < 32 {
            panic!("writing into a small buffer")
        }
        r[0] = ((self.v[4] >> 40) & 0xFF) as u8;
        r[1] = ((self.v[4] >> 32) & 0xFF) as u8;
        r[2] = ((self.v[4] >> 24) & 0xFF) as u8;
        r[3] = ((self.v[4] >> 16) & 0xFF) as u8;
        r[4] = ((self.v[4] >> 8) & 0xFF) as u8;
        r[5] = (self.v[4] & 0xFF) as u8;
        r[6] = ((self.v[3] >> 44) & 0xFF) as u8;
        r[7] = ((self.v[3] >> 36) & 0xFF) as u8;
        r[8] = ((self.v[3] >> 28) & 0xFF) as u8;
        r[9] = ((self.v[3] >> 20) & 0xFF) as u8;
        r[10] = ((self.v[3] >> 12) & 0xFF) as u8;
        r[11] = ((self.v[3] >> 4) & 0xFF) as u8;
        r[12] = (((self.v[2] >> 48) & 0xF) | ((self.v[3] & 0xF) << 4)) as u8;
        r[13] = ((self.v[2] >> 40) & 0xFF) as u8;
        r[14] = ((self.v[2] >> 32) & 0xFF) as u8;
        r[15] = ((self.v[2] >> 24) & 0xFF) as u8;
        r[16] = ((self.v[2] >> 16) & 0xFF) as u8;
        r[17] = ((self.v[2] >> 8) & 0xFF) as u8;
        r[18] = (self.v[2] & 0xFF) as u8;
        r[19] = ((self.v[1] >> 44) & 0xFF) as u8;
        r[20] = ((self.v[1] >> 36) & 0xFF) as u8;
        r[21] = ((self.v[1] >> 28) & 0xFF) as u8;
        r[22] = ((self.v[1] >> 20) & 0xFF) as u8;
        r[23] = ((self.v[1] >> 12) & 0xFF) as u8;
        r[24] = ((self.v[1] >> 4) & 0xFF) as u8;
        r[25] = (((self.v[0] >> 48) & 0xF) | ((self.v[1] & 0xF) << 4)) as u8;
        r[26] = ((self.v[0] >> 40) & 0xFF) as u8;
        r[27] = ((self.v[0] >> 32) & 0xFF) as u8;
        r[28] = ((self.v[0] >> 24) & 0xFF) as u8;
        r[29] = ((self.v[0] >> 16) & 0xFF) as u8;
        r[30] = ((self.v[0] >> 8) & 0xFF) as u8;
        r[31] = (self.v[0] & 0xFF) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fc2f_mul_tests() {
        let z = FSecp256 { v: [0, 0, 0, 0, 0] };
        assert!(z.is_zero());
        assert!(!z.is_one());

        let one = FSecp256 { v: [1, 0, 0, 0, 0] };
        assert!(one.is_one());
        assert!(!one.is_zero());

        let a = FSecp256 {
            v: [0xf2f3232323, 0x0, 0x0, 0x0, 0x0],
        };
        let b = FSecp256 {
            v: [0x7358afdf6d7, 0x0, 0x0, 0x0, 0x0],
        };
        let c = FSecp256 {
            v: [0x1b7978ddd2465, 0x6d776345, 0x0, 0x0, 0x0],
        };
        let d = a.mul(&b);
        assert!(c == d);

        let a = FSecp256 {
            v: [
                0x948fe6cbfda84,
                0xcf716a6d8d2ca,
                0xf06e640da1004,
                0xd35e90cbda2c1,
                0x2c6ab1504e66,
            ],
        };
        let b = FSecp256 {
            v: [
                0x74271c6cb4241,
                0xb4509181605e,
                0x59b8c3a50b96c,
                0x5463e0ea304de,
                0x9a8d542d5e7e,
            ],
        };
        let c = FSecp256 {
            v: [
                0x74d1f04b5d91,
                0x684fc57956b57,
                0x3c26eedbca101,
                0x2001a88c7fdb3,
                0xc56757469716,
            ],
        };
        let d = a.mul(&b);
        assert!(c == d);

        let a = FSecp256 {
            v: [
                0xdb01b880bf569,
                0x1b33eb9715c20,
                0x2b044751fc55f,
                0xd3b09e67215f6,
                0xecd6ee561f55,
            ],
        };
        let b = FSecp256 {
            v: [
                0xdfaa2194ed1c1,
                0x58828cfc145cb,
                0x7be6e5fb58e1e,
                0xb7fbc3e19a0aa,
                0xd11ace0ba9c2,
            ],
        };
        let c = FSecp256 {
            v: [
                0x33733221bad67,
                0xf6c02edf4aef2,
                0xf4487b1c054bc,
                0x7e3c9b1d790b2,
                0xcd7c9e33ac9d,
            ],
        };
        let d = a.mul(&b);
        assert!(c == d);

        let a = FSecp256 {
            v: [
                0xe54e93961d57e,
                0x258ab1a469a67,
                0x5f24fc18824e7,
                0x43669a6001d33,
                0xbaf07785a062,
            ],
        };
        let b = FSecp256 {
            v: [
                0xf330263ed72d1,
                0x4457730988523,
                0xa441d727827d0,
                0x1375f423b04bf,
                0xc618df5ea932,
            ],
        };
        let c = FSecp256 {
            v: [
                0xce6f9342b2482,
                0xd12c57ae5dafc,
                0x4d5dd5188f612,
                0x9c10bb751e3ca,
                0x2c9a4b825903,
            ],
        };
        let d = a.mul(&b);
        assert!(c == d);

        let a = FSecp256 {
            v: [
                0xef56a2f75b904,
                0xe1df41f96ef17,
                0x12a23ede91fc8,
                0xd9507cf40f5cc,
                0x8fa5308760e3,
            ],
        };
        let b = FSecp256 {
            v: [
                0x544f9f64ac1f7,
                0x44e3919b4a090,
                0x260aeb700ad46,
                0xfd0df8dacdfee,
                0xe869c700ef3f,
            ],
        };
        let c = FSecp256 {
            v: [
                0x3a8271f1f4e82,
                0x86e420ef76dca,
                0xc20c656e97711,
                0xc98fae2e2dd95,
                0xc2c8cfa49cbd,
            ],
        };
        let d = a.mul(&b);
        println!(
            "d= {:x} {:x} {:x} {:x} {:x} ",
            d.v[0], d.v[1], d.v[2], d.v[3], d.v[4]
        );
        assert!(c == d);

        let a = FSecp256 {
            v: [0x0, 0x0, 0xffffffe000000, 0xfffffffffffff, 0xffffffffffff],
        };
        let b = FSecp256 {
            v: [
                0xffffefffffc2e,
                0xfffffffffffff,
                0xfffffffffffff,
                0xfffffffffffff,
                0xffffffffffff,
            ],
        };
        let c = FSecp256 {
            v: [0xffffefffffc2f, 0xfffffffffffff, 0x1ffffff, 0x0, 0x0],
        };
        let d = a.mul(&b);
        println!(
            "d= {:x} {:x} {:x} {:x} {:x} ",
            d.v[0], d.v[1], d.v[2], d.v[3], d.v[4]
        );
        println!(
            "c= {:x} {:x} {:x} {:x} {:x} ",
            c.v[0], c.v[1], c.v[2], c.v[3], c.v[4]
        );
        //assert!(c==d);

        let a = FSecp256 {
            v: [
                0xfffffffffffff,
                0xfffffffffffff,
                0xffffffdffffff,
                0xfffffffffffff,
                0xffffffffffff,
            ],
        };
        let b = FSecp256 {
            v: [
                0xffffefffffc2e,
                0xfffffffffffff,
                0xfffffffffffff,
                0xfffffffffffff,
                0xffffffffffff,
            ],
        };
        let c = FSecp256 {
            v: [0xffffefffffc30, 0xfffffffffffff, 0x1ffffff, 0x0, 0x0],
        };
        let d = a.mul(&b);
        println!(
            "d= {:x} {:x} {:x} {:x} {:x} ",
            d.v[0], d.v[1], d.v[2], d.v[3], d.v[4]
        );
        println!(
            "c= {:x} {:x} {:x} {:x} {:x} ",
            c.v[0], c.v[1], c.v[2], c.v[3], c.v[4]
        );
        // assert!(c==d);

        let a = FSecp256 {
            v: [
                0xffffeeffffc30,
                0xfffffffffffff,
                0xfffffffffffff,
                0xfffffffffffff,
                0xffffffffffff,
            ],
        };
        let b = FSecp256 {
            v: [
                0xffffefffffc2e,
                0xfffffffffffff,
                0xfffffffffffff,
                0xfffffffffffff,
                0xffffffffffff,
            ],
        };
        let c = FSecp256 {
            v: [0xfffffff, 0x0, 0x0, 0x0, 0x0],
        };
        let d = a.mul(&b);
        println!(
            "d= {:x} {:x} {:x} {:x} {:x} ",
            d.v[0], d.v[1], d.v[2], d.v[3], d.v[4]
        );
        println!(
            "c= {:x} {:x} {:x} {:x} {:x} ",
            c.v[0], c.v[1], c.v[2], c.v[3], c.v[4]
        );
        // assert!(c==d);
    }

    #[test]
    fn fc2f_sqr_tests() {
        let a = FSecp256 {
            v: [
                0x5fc94ec2e5969,
                0xbcc0ceac1c027,
                0x15e19b8675e50,
                0xd2504ff08c53,
                0x67d996df37bb,
            ],
        };
        let c = FSecp256 {
            v: [
                0x3d2017b7ae554,
                0xe4615d31d4d02,
                0x80e06838043a3,
                0x1a963f9a882ae,
                0x33fc48fae1a2,
            ],
        };
        let d = a.sqr();
        assert!(c == d);

        let d = a.sqr();
        let drt = d.sqrt().unwrap();
        let drt2 = drt.sqr();
        assert!(drt2 == d);

        let a = FSecp256 {
            v: [
                0xed5d8621f9a0f,
                0x99ba782a5c24b,
                0x611e4b2c86ae4,
                0xa8bdea00cdbac,
                0x69c2d9e078fd,
            ],
        };
        let c = FSecp256 {
            v: [
                0x4d0857c311393,
                0x1f8dc96326d70,
                0xcabd6a82b0466,
                0xdb79349f642e2,
                0xef9732d3a3fe,
            ],
        };
        let d = a.sqr();
        assert!(c == d);

        let d = a.sqr();
        let drt = d.sqrt().unwrap();
        let drt2 = drt.sqr();
        assert!(drt2 == d);

        let a = FSecp256 {
            v: [
                0x10e9a8a3bf39b,
                0x3bac7d736f907,
                0x2e92b3d7128a1,
                0x839a5a5f8b5e5,
                0x4f4a681760ea,
            ],
        };
        let c = FSecp256 {
            v: [
                0x47c5ec3e03749,
                0x5c82afbea0934,
                0x124ed9cd65c6a,
                0xf69676df700e,
                0x276bc6dfcc4a,
            ],
        };
        let d = a.sqr();
        assert!(c == d);

        let d = a.sqr();
        let drt = d.sqrt().unwrap();
        let drt2 = drt.sqr();
        assert!(drt2 == d);

        let a = FSecp256 {
            v: [
                0x79cb518e6f2d0,
                0xc58b473d3f06e,
                0x7a4d3c0bcbfd2,
                0x940f09ebcbcc4,
                0x3b594a97a501,
            ],
        };
        let c = FSecp256 {
            v: [
                0xeaec65b8bbc45,
                0x698e3afb0d19b,
                0xc9748be37667d,
                0xd974d88cc4d37,
                0x928d6680c372,
            ],
        };
        let d = a.sqr();
        assert!(c == d);

        let d = a.sqr();
        let drt = d.sqrt().unwrap();
        let drt2 = drt.sqr();
        assert!(drt2 == d);

        let a = FSecp256 {
            v: [
                0x816035b8ec4f2,
                0xad08265dfe22a,
                0xc5f9979494f00,
                0xb7239658c0da7,
                0x91901b59cadd,
            ],
        };
        let c = FSecp256 {
            v: [
                0x87366950a62b7,
                0x5c417fe974495,
                0xda88bf4f47435,
                0xe7be161e5b3c0,
                0xc12885784522,
            ],
        };
        let d = a.sqr();
        assert!(c == d);

        let d = a.sqr();
        let drt = d.sqrt().unwrap();
        let drt2 = drt.sqr();
        assert!(drt2 == d);
    }

    #[test]
    fn fc2f_inv_tests() {
        let a = FSecp256 {
            v: [
                0x5fc94ec2e5969,
                0xbcc0ceac1c027,
                0x15e19b8675e50,
                0xd2504ff08c53,
                0x67d996df37bb,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        println!("one == {:?}", one);
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x3d2017b7ae554,
                0xe4615d31d4d02,
                0x80e06838043a3,
                0x1a963f9a882ae,
                0x33fc48fae1a2,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0xed5d8621f9a0f,
                0x99ba782a5c24b,
                0x611e4b2c86ae4,
                0xa8bdea00cdbac,
                0x69c2d9e078fd,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x4d0857c311393,
                0x1f8dc96326d70,
                0xcabd6a82b0466,
                0xdb79349f642e2,
                0xef9732d3a3fe,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x10e9a8a3bf39b,
                0x3bac7d736f907,
                0x2e92b3d7128a1,
                0x839a5a5f8b5e5,
                0x4f4a681760ea,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x47c5ec3e03749,
                0x5c82afbea0934,
                0x124ed9cd65c6a,
                0xf69676df700e,
                0x276bc6dfcc4a,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x79cb518e6f2d0,
                0xc58b473d3f06e,
                0x7a4d3c0bcbfd2,
                0x940f09ebcbcc4,
                0x3b594a97a501,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0xeaec65b8bbc45,
                0x698e3afb0d19b,
                0xc9748be37667d,
                0xd974d88cc4d37,
                0x928d6680c372,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x816035b8ec4f2,
                0xad08265dfe22a,
                0xc5f9979494f00,
                0xb7239658c0da7,
                0x91901b59cadd,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());

        let a = FSecp256 {
            v: [
                0x87366950a62b7,
                0x5c417fe974495,
                0xda88bf4f47435,
                0xe7be161e5b3c0,
                0xc12885784522,
            ],
        };
        let ainv = a.inv();
        let mut one = a.mul(&ainv);
        one.normalize();
        assert!(one.is_one());
    }
}
