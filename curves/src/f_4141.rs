use super::Ford;
use rand::Rng;
///
///
// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// order of group is 115792089237316195423570985008687907852837564279074904382605163141518161494337
// or 2^256 - 432420386565659656852420866394968145599
// or 2^256 - 0x1 4551231950b75fc4 402da1732fc9bebf
//
/// aas, neucrypt
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct FSecp256Ord {
    pub v: [u64; 4],
}

pub const ORD: FSecp256Ord = FSecp256Ord {
    v: [
        0xBFD25E8CD0364141,
        0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ],
};

const R0: u128 = 0x402da1732fc9bebf; // !N0 + 1;
const R1: u128 = 0x4551231950b75fc4; // !N1;
const R2: u128 = 1;

//const NN0: u128 = 0xBAAEDCE6AF48A03BBFD25E8CD0364141;
//const NN1: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE;

const LOWER64: u128 = 0x0000000000000000FFFFFFFFFFFFFFFF;

impl fmt::Debug for FSecp256Ord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[0x{:0x}, 0x{:0x}, 0x{:0x}, 0x{:0x}]",
            self.v[0], self.v[1], self.v[2], self.v[3]
        )
    }
}

impl fmt::Display for FSecp256Ord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{:0x}{:0x}{:0x}{:0x}",
            self.v[3], self.v[2], self.v[1], self.v[0]
        )
    }
}

impl FSecp256Ord {
    pub fn reduce(r: &FSecp256Ord, overflow: u64) -> FSecp256Ord {
        assert!(overflow <= 1);

        let overflow = if r.v[3] == 0xFFFFFFFFFFFFFFFF
            && (r.v[2] > 0xFFFFFFFFFFFFFFFE
                || (r.v[2] == 0xFFFFFFFFFFFFFFFE && r.v[1] > 0xBAAEDCE6AF48A03B)
                || (r.v[2] == 0xFFFFFFFFFFFFFFFE
                    && r.v[1] == 0xBAAEDCE6AF48A03B
                    && r.v[0] >= 0xBFD25E8CD0364141))
        {
            1 + overflow
        } else {
            overflow
        };

        let t = r.v[0] as u128 + (overflow as u128 * R0);
        let r0 = (t & LOWER64) as u64;
        let t = (t >> 64) + r.v[1] as u128 + (overflow as u128 * R1) as u128;
        let r1 = (t & LOWER64) as u64;
        let t = (t >> 64) + r.v[2] as u128 + (overflow as u128 * R2);

        let r2 = (t & LOWER64) as u64;
        let t = (t >> 64) + r.v[3] as u128;
        let r3 = (t & LOWER64) as u64;
        //debug_assert!((t>>64) == 0);
        FSecp256Ord {
            v: [r0, r1, r2, r3],
        }
    }

    pub fn is_one(&self) -> bool {
        self.v[0] == 1 && self.v[1] == 0 && self.v[2] == 0 && self.v[3] == 0
    }

    fn reduce512(
        l0: u128,
        l1: u128,
        l2: u128,
        l3: u128,
        l4: u128,
        l5: u128,
        l6: u128,
        l7: u128,
    ) -> FSecp256Ord {
        // at this point, variables l0..l7 hold the intermediate results
        // now begin reduction process
        // l0 l1 l2 l3 + 2^256(l4 l5 l6 l7) mod order
        // = [l0 l1 l2 l3] + (q2 q1 q0)(l7 l6 l5 l4)
        //         q0l4
        //.      q0l5
        //.    q0l6
        //   q0l7
        //       q1l4
        //.    q1l5
        //   q1l6
        // q1l7
        // l7l6l5l4

        // println!("L0: {:x} l1: {:x} l2: {:x} l3:{:x}",l0,l1,l2,l3);
        // println!("l4: {:x} l5: {:x} l6: {:x} l7:{:x}",l4,l5,l6,l7);

        let y04 = l4 * R0; // < 127 bits
        let y05 = l5 * R0;
        let y06 = l6 * R0;
        let y07 = l7 * R0;
        let r0 = y04 & LOWER64;
        let y14 = l4 * R1;
        let y15 = l5 * R1;
        let y16 = l6 * R1;
        let y17 = l7 * R1;

        let r1 = (y04 >> 64) + (y05 & LOWER64) + (y14 & LOWER64);
        let r2 = (y05 >> 64) + (y06 & LOWER64) + (y14 >> 64) + (y15 & LOWER64) + l4;
        let r3 = (y06 >> 64) + (y07 & LOWER64) + (y15 >> 64) + (y16 & LOWER64) + l5;
        let r4 = (y07 >> 64) + (y16 >> 64) + (y17 & LOWER64) + l6;
        let r5 = (y17 >> 64) + l7;

        let r2 = r2 + (r1 >> 64);
        let r1 = r1 & LOWER64;
        let r3 = r3 + (r2 >> 64);
        let r2 = r2 & LOWER64;
        let r4 = r4 + (r3 >> 64);
        let r3 = r3 & LOWER64;
        let r5 = r5 + (r4 >> 64);
        let r4 = r4 & LOWER64;
        let r5 = r5 + (r4 >> 64);

        let l0 = l0 + r0;
        let l1 = l1 + r1;
        let l2 = l2 + r2;
        let l3 = l3 + r3;

        // reduce (r5 r4) * (1 R1 R0)
        //           R0r4
        //         R0r5
        //         R1r4
        //       R1r5
        //.      r5r4
        let z04 = r4 * R0; // each product is < 127 bits
        let z05 = r5 * R0;
        let z14 = r4 * R1;
        let z15 = r5 * R1;

        let f0 = z04 & LOWER64;
        let f1 = (z04 >> 64) + (z05 & LOWER64) + (z14 & LOWER64);
        let ov = f1 >> 64;
        let f1 = f1 & LOWER64;
        let f2 = ov + (z05 >> 64) + (z14 >> 64) + (z15 & LOWER64) + r4;
        let ov = f2 >> 64;
        let f2 = f2 & LOWER64;
        let f3 = ov + (z15 >> 64) + r5; // possibly 65 bits

        let l0 = l0 + f0;
        let l1 = (l0 >> 64) + l1 + f1;
        let l0 = l0 & LOWER64;
        let l2 = (l1 >> 64) + l2 + f2;
        let l1 = l1 & LOWER64;
        let l3 = (l2 >> 64) + l3 + f3;
        let l2 = l2 & LOWER64;
        let l4 = l3 >> 64; // possibly 2 bits
        let l3 = l3 & LOWER64;

        // l4 * (q2 q1 q0)                  // possiblt 131 bits
        let l0 = l0 + l4 * R0;
        let ov = l0 >> 64;
        let l0 = l0 & LOWER64;
        let l1 = ov + l1 + l4 * R1;
        let ov = l1 >> 64;
        let l1 = l1 & LOWER64;
        let l2 = ov + l2 + l4;
        let ov = l2 >> 64;
        let l2 = l2 & LOWER64;
        let l3 = ov + l3;

        // the result can still be between [q, 2q]
        let reduc: u128 = if l3 > 0xFFFFFFFFFFFFFFFF
            || (l3 == 0xFFFFFFFFFFFFFFFF
                && (l2 > 0xFFFFFFFFFFFFFFFE
                    || (l2 == 0xFFFFFFFFFFFFFFFE && l1 > 0xBAAEDCE6AF48A03B)
                    || (l2 == 0xFFFFFFFFFFFFFFFE
                        && l1 == 0xBAAEDCE6AF48A03B
                        && l0 >= 0xBFD25E8CD0364141)))
        {
            1
        } else {
            0
        };

        let l0 = l0 + reduc * R0;
        let ov = l0 >> 64;
        let l0 = (l0 & LOWER64) as u64;
        let l1 = ov + l1 + reduc * R1;
        let ov = l1 >> 64;
        let l1 = (l1 & LOWER64) as u64;
        let l2 = ov + l2 + reduc;
        let ov = l2 >> 64;
        let l2 = (l2 & LOWER64) as u64;
        let l3 = ((ov + l3) & LOWER64) as u64;

        FSecp256Ord {
            v: [l0, l1, l2, l3],
        }
    }
}

// impl Fq for FSecp256 {

impl Ford for FSecp256Ord {
    const ONE: FSecp256Ord = FSecp256Ord { v: [1, 0, 0, 0] };
    const ZERO: FSecp256Ord = FSecp256Ord { v: [0, 0, 0, 0] };
    const NBITS: usize = 256;
    const NBYTES: usize = (256 + 7) / 8;

    fn from_slice(v: &[u64]) -> FSecp256Ord {
        FSecp256Ord {
            v: [v[0], v[1], v[2], v[3]],
        }
    }

    fn is_zero(&self) -> bool {
        self.v[0] == 0 && self.v[1] == 0 && self.v[2] == 0 && self.v[3] == 0
    }

    fn get_window(&self, i: usize) -> u8 {
        if i >= 64 {
            return 0;
        }
        let ni = i / 16;
        let nj = (i % 16) * 4;
        ((self.v[ni] >> (nj)) & 0xf) as u8
    }

    fn rand(rng: &mut dyn Rng) -> Self {
        let r0 = rng.next_u64();
        let r1 = rng.next_u64();
        let r2 = rng.next_u64();
        let r3 = rng.next_u64();

        FSecp256Ord {
            v: [r0, r1, r2, r3],
        }
    }

    fn add(&self, b: &FSecp256Ord) -> FSecp256Ord {
        let t = self.v[0] as u128 + b.v[0] as u128;
        let r1 = self.v[1] as u128 + b.v[1] as u128;
        let r2 = self.v[2] as u128 + b.v[2] as u128;
        let r3 = self.v[3] as u128 + b.v[3] as u128;

        let r0 = t & LOWER64;
        let t = (t >> 64) + r1;
        let r1 = t & LOWER64;
        let t = (t >> 64) + r2;
        let r2 = t & LOWER64;
        let t = (t >> 64) + r3;
        let r3 = t & LOWER64;
        let t = t >> 64;

        // overflow = t + secp256k1_scalar_check_overflow(r);
        // VERIFY_CHECK(overflow == 0 || overflow == 1);
        // secp256k1_scalar_reduce(r, overflow);
        // return overflow;
        let r = FSecp256Ord {
            v: [r0 as u64, r1 as u64, r2 as u64, r3 as u64],
        };
        FSecp256Ord::reduce(&r, t as u64)
    }

    fn neg(&self) -> FSecp256Ord {
        let m = if self.is_zero() {
            0
        } else {
            0xFFFFFFFFFFFFFFFF
        };
        // uint128_t t = (uint128_t)(~a->d[0]) + SECP256K1_N_0 + 1;

        let t = (!self.v[0]) as u128 + ORD.v[0] as u128 + 1;

        let r0 = (t & m) as u64;
        let t = (t >> 64) + (!self.v[1]) as u128 + ORD.v[1] as u128;
        // r->d[0] = t & nonzero; t >>= 64;
        // t += (uint128_t)(~a->d[1]) + SECP256K1_N_1;
        let r1 = (t & m) as u64;
        let t = (t >> 64) + (!self.v[2]) as u128 + ORD.v[2] as u128;
        let r2 = (t & m) as u64;
        let t = (t >> 64) + (!self.v[3]) as u128 + ORD.v[3] as u128;
        let r3 = (t & m) as u64;

        let r = FSecp256Ord {
            v: [r0, r1, r2, r3],
        };
        FSecp256Ord::reduce(&r, 0)
    }

    fn sub(&self, b: &FSecp256Ord) -> FSecp256Ord {
        self.add(&b.neg())
    }

    //     fn inv(&self) -> Self;

    fn from_bytes(b: &[u8]) -> Self {
        if b.len() < 32 {
            panic!("calling from_bytes on a small slice");
        }
        // static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
        let r0 = b[31] as u64
            | (b[30] as u64) << 8
            | (b[29] as u64) << 16
            | (b[28] as u64) << 24
            | (b[27] as u64) << 32
            | (b[26] as u64) << 40
            | (b[25] as u64) << 48
            | (b[24] as u64) << 56;
        let r1 = (b[23] as u64)
            | (b[22] as u64) << 8
            | (b[21] as u64) << 16
            | (b[20] as u64) << 24
            | (b[19] as u64) << 32
            | (b[18] as u64) << 40
            | (b[17] as u64) << 48
            | (b[16] as u64) << 56;
        let r2 = (b[15] as u64)
            | (b[14] as u64) << 8
            | (b[13] as u64) << 16
            | (b[12] as u64) << 24
            | (b[11] as u64) << 32
            | (b[10] as u64) << 40
            | (b[9] as u64) << 48
            | (b[8] as u64) << 56;
        let r3 = (b[7] as u64)
            | (b[6] as u64) << 8
            | (b[5] as u64) << 16
            | (b[4] as u64) << 24
            | (b[3] as u64) << 32
            | (b[2] as u64) << 40
            | (b[1] as u64) << 48
            | (b[0] as u64) << 56;
        let r = FSecp256Ord {
            v: [r0, r1, r2, r3],
        };
        FSecp256Ord::reduce(&r, 0)

        //     over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
        //     if (overflow) {
        //         *overflow = over;
        //     }
    }

    fn from_native(b: u64) -> Self {
        let r = FSecp256Ord { v: [b, 0, 0, 0] };
        FSecp256Ord::reduce(&r, 0)
    }

    fn to_bytes(&self, b: &mut [u8]) {
        if b.len() < 32 {
            panic!("using to_bytes on a small slice");
        }
        b[0] = (self.v[3] >> 56) as u8;
        b[1] = (self.v[3] >> 48) as u8;
        b[2] = (self.v[3] >> 40) as u8;
        b[3] = (self.v[3] >> 32) as u8;
        b[4] = (self.v[3] >> 24) as u8;
        b[5] = (self.v[3] >> 16) as u8;
        b[6] = (self.v[3] >> 8) as u8;
        b[7] = self.v[3] as u8;
        b[8] = (self.v[2] >> 56) as u8;
        b[9] = (self.v[2] >> 48) as u8;
        b[10] = (self.v[2] >> 40) as u8;
        b[11] = (self.v[2] >> 32) as u8;
        b[12] = (self.v[2] >> 24) as u8;
        b[13] = (self.v[2] >> 16) as u8;
        b[14] = (self.v[2] >> 8) as u8;
        b[15] = self.v[2] as u8;
        b[16] = (self.v[1] >> 56) as u8;
        b[17] = (self.v[1] >> 48) as u8;
        b[18] = (self.v[1] >> 40) as u8;
        b[19] = (self.v[1] >> 32) as u8;
        b[20] = (self.v[1] >> 24) as u8;
        b[21] = (self.v[1] >> 16) as u8;
        b[22] = (self.v[1] >> 8) as u8;
        b[23] = self.v[1] as u8;
        b[24] = (self.v[0] >> 56) as u8;
        b[25] = (self.v[0] >> 48) as u8;
        b[26] = (self.v[0] >> 40) as u8;
        b[27] = (self.v[0] >> 32) as u8;
        b[28] = (self.v[0] >> 24) as u8;
        b[29] = (self.v[0] >> 16) as u8;
        b[30] = (self.v[0] >> 8) as u8;
        b[31] = self.v[0] as u8;
    }

    //     fn muli(&self, b: u64) -> Self;

    //     fn equals(&self, b: &Self) -> bool;

    //     fn cswap(&mut self, d: &mut Self, b: isize);

    /// only works when the value is reduced
    fn bit(&self, i: usize) -> bool {
        let j = i % 64;
        let k = (i / 64) as usize;
        assert!(k < 4);

        return ((self.v[k] >> j) & 0x1) > 0;
    }

    //     fn normalize(&self) -> Self;
    //     fn normalize_weak(&self) -> Self;

    //     // memory oblivious routines
    //     // sets y = (1-sel)*a + sel*b with an oblivious memory access pattern
    //     fn mux(y: &mut Self, a: &Self, b: &Self, sel: u32);
    //     // swaps a and b if sel=1 with an oblivious memory access pattern
    //     fn swap(a: &mut Self, b: &mut Self, sel:u32);

    fn mul(&self, b: &FSecp256Ord) -> FSecp256Ord {
        // b3 b2 b1 b0
        // a3 a2 a1 a0
        // res = p11 * 2^256 + (a1a0 * b3b2 + a3a2*b1b0)*2^128 + a1a0*b1b0
        // since 2^256 mod ord = q, we have
        // res mod order = p1*q + p0
        //
        // so first goal is to compute p1
        // b3 b2
        // a3 a2 where a2, b2 in [0,2^64-2]

        let t00 = self.v[0] as u128 * b.v[0] as u128;
        let t01 = self.v[0] as u128 * b.v[1] as u128;
        let t10 = self.v[1] as u128 * b.v[0] as u128;
        let l0 = t00 & LOWER64;
        let l1 = (t00 >> 64) + (t01 & LOWER64) + (t10 & LOWER64);
        let ov = l1 >> 64;
        let l1 = l1 & LOWER64;
        let t02 = self.v[0] as u128 * b.v[2] as u128;
        let t11 = self.v[1] as u128 * b.v[1] as u128;
        let t20 = self.v[2] as u128 * b.v[0] as u128;
        let l2 =
            ov + (t01 >> 64) + (t02 & LOWER64) + (t10 >> 64) + (t11 & LOWER64) + (t20 & LOWER64);
        let ov = l2 >> 64;
        let l2 = l2 & LOWER64;
        let t03 = self.v[0] as u128 * b.v[3] as u128;
        let t12 = self.v[1] as u128 * b.v[2] as u128;
        let t21 = self.v[2] as u128 * b.v[1] as u128;
        let t30 = self.v[3] as u128 * b.v[0] as u128;
        let l3 = ov
            + (t02 >> 64)
            + (t03 & LOWER64)
            + (t11 >> 64)
            + (t12 & LOWER64)
            + (t20 >> 64)
            + (t21 & LOWER64)
            + (t30 & LOWER64);
        let ov = l3 >> 64;
        let l3 = l3 & LOWER64;

        let t13 = self.v[1] as u128 * b.v[3] as u128;
        let t22 = self.v[2] as u128 * b.v[2] as u128;
        let t31 = self.v[3] as u128 * b.v[1] as u128;

        let l4 = ov
            + (t03 >> 64)
            + (t12 >> 64)
            + (t13 & LOWER64)
            + (t21 >> 64)
            + (t22 & LOWER64)
            + (t30 >> 64)
            + (t31 & LOWER64);
        let ov = l4 >> 64;
        let l4 = l4 & LOWER64;

        let t23 = self.v[2] as u128 * b.v[3] as u128;
        let t32 = self.v[3] as u128 * b.v[2] as u128;

        let l5 = ov + (t13 >> 64) + (t22 >> 64) + (t23 & LOWER64) + (t31 >> 64) + (t32 & LOWER64);
        let ov = l5 >> 64;
        let l5 = l5 & LOWER64;

        let t33 = self.v[3] as u128 * b.v[3] as u128;

        let l6 = ov + (t23 >> 64) + (t32 >> 64) + (t33 & LOWER64);
        let ov = l6 >> 64;
        let l6 = l6 & LOWER64;

        let l7 = ov + (t33 >> 64);
        let ov = l7 >> 64;
        debug_assert!(ov == 0);

        FSecp256Ord::reduce512(l0, l1, l2, l3, l4, l5, l6, l7)
    }

    fn inv(&self) -> FSecp256Ord {
        // 11111111111111111111
        // 11111111111111111111
        // 11111111111111111111
        // 11111111111111111111
        // 11111111111111111111
        // 11111111111111111111
        // 111111
        // 101
        // 0111
        // 0101
        // 01011
        // 1011
        // 0111
        // 00111
        // 001101
        // 0101
        // 111
        // 01001
        // 000101
        // 0000000111
        // 0111
        // 011111111
        // 01001
        // 001011
        // 1101
        // 000110011010000001101100100000100111111
        // addition chain to get to order - 2.
        // uN stands for g^N
        // xN stands for g^{2^N - 1}

        let u2 = self.sqr();
        let x2 = u2.mul(&self);
        let u5 = u2.mul(&x2);

        let x3 = u5.mul(&u2);
        let u9 = x3.mul(&u2);
        let u11 = u9.mul(&u2);
        let u13 = u11.mul(&u2);

        let x6 = u13.sqr();
        let x6 = x6.sqr();
        let x6 = x6.mul(&u11);

        let x8 = x6.sqr();
        let x8 = x8.sqr();
        let x8 = x8.mul(&x2);

        let x14 = x8.sqr().sqr().sqr().sqr().sqr().sqr();
        let x14 = x14.mul(&x6);

        let mut x28 = x14.sqr();
        for _ in 0..13 {
            x28 = x28.sqr();
        }
        let x28 = x28.mul(&x14);

        let mut x56 = x28.sqr();
        for _ in 0..27 {
            x56 = x56.sqr();
        }
        let x56 = x56.mul(&x28);

        let mut x112 = x56.sqr();
        for _ in 0..55 {
            x112 = x112.sqr();
        }
        let x112 = x112.mul(&x56);

        let mut x126 = x112.sqr();
        for _ in 0..13 {
            x126 = x126.sqr();
        }
        let x126 = x126.mul(&x14);

        /* Then accumulate the final result (t starts at x126). */
        let t = x126.sqr().sqr().sqr();

        let t = t.mul(&u5); /* 101 */
        let t = t.sqr().sqr().sqr().sqr();

        let t = t.mul(&x3); /* 0111 */
        let t = t.sqr().sqr().sqr().sqr();

        let t = t.mul(&u5); /* 0101 */
        let t = t.sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u11); /* 01011 */
        let t = t.sqr().sqr().sqr().sqr();
        let t = t.mul(&u11); /* 1011 */
        let t = t.sqr().sqr().sqr().sqr();
        let t = t.mul(&x3); /* 0111 */
        let t = t.sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&x3); /* 00111 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u13); /* 001101 */
        let t = t.sqr().sqr().sqr().sqr();
        let t = t.mul(&u5); /* 0101 */
        let t = t.sqr().sqr().sqr();
        let t = t.mul(&x3); /* 111 */
        let t = t.sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u9); /* 01001 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u5); /* 000101 */
        let t = t
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr();

        let t = t.mul(&x3); /* 0000000111 */
        let t = t.sqr().sqr().sqr().sqr();
        let t = t.mul(&x3); /* 0111 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&x8); /* 011111111 */
        let t = t.sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u9); /* 01001 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u11); /* 001011 */
        let t = t.sqr().sqr().sqr().sqr();
        let t = t.mul(&u13); /* 1101 */
        let t = t.sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&x2); /* 00011 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&u13); /* 001101 */
        let t = t
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr()
            .sqr();
        let t = t.mul(&u13); /* 0000001101 */
        let t = t.sqr().sqr().sqr().sqr();
        let t = t.mul(&u9); /* 1001 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr();
        let t = t.mul(&self); /* 000001 */
        let t = t.sqr().sqr().sqr().sqr().sqr().sqr().sqr().sqr();
        let r = t.mul(&x6); /* 00111111 */
        r
    }

    fn sqr(&self) -> FSecp256Ord {
        // a3 a2 a1 a0
        // a3 a2 a1 a0
        // res = a3a2^2 * 2^256 + (a1a0 * a3a2 + a3a2*a1a0)*2^128 + a1a0^2

        let t00 = self.v[0] as u128 * self.v[0] as u128;
        let t01 = self.v[0] as u128 * self.v[1] as u128;
        let l0 = t00 & LOWER64;
        let l1 = (t00 >> 64) + (t01 & LOWER64) * 2;
        let ov = l1 >> 64;
        let l1 = l1 & LOWER64;
        let t02 = self.v[0] as u128 * self.v[2] as u128;
        let t11 = self.v[1] as u128 * self.v[1] as u128;
        let l2 = ov + (t01 >> 64) * 2 + (t02 & LOWER64) * 2 + (t11 & LOWER64);
        let ov = l2 >> 64;
        let l2 = l2 & LOWER64;
        let t03 = self.v[0] as u128 * self.v[3] as u128;
        let t12 = self.v[1] as u128 * self.v[2] as u128;
        let l3 = ov + (t02 >> 64) * 2 + (t03 & LOWER64) * 2 + (t11 >> 64) + (t12 & LOWER64) * 2;
        let ov = l3 >> 64;
        let l3 = l3 & LOWER64;

        let t13 = self.v[1] as u128 * self.v[3] as u128;
        let t22 = self.v[2] as u128 * self.v[2] as u128;

        let l4 = ov + (t03 >> 64) * 2 + (t12 >> 64) * 2 + (t13 & LOWER64) * 2 + (t22 & LOWER64);
        let ov = l4 >> 64;
        let l4 = l4 & LOWER64;

        let t23 = self.v[2] as u128 * self.v[3] as u128;

        let l5 = ov + (t13 >> 64) * 2 + (t22 >> 64) + (t23 & LOWER64) * 2;
        let ov = l5 >> 64;
        let l5 = l5 & LOWER64;

        let t33 = self.v[3] as u128 * self.v[3] as u128;

        let l6 = ov + (t23 >> 64) * 2 + (t33 & LOWER64);
        let ov = l6 >> 64;
        let l6 = l6 & LOWER64;

        let l7 = ov + (t33 >> 64);
        let ov = l7 >> 64;
        assert!(ov == 0);
        FSecp256Ord::reduce512(l0, l1, l2, l3, l4, l5, l6, l7)
    }

    fn pow_native(&self, n: u64) -> FSecp256Ord {
        if n == 0 {
            return FSecp256Ord::ONE;
        }

        let mut n = n;
        let mut x = self.clone();
        let mut y = FSecp256Ord::ONE;

        while n > 1 {
            if n % 2 == 0 {
                x = x.sqr();
                n = n / 2;
            } else {
                y = x.mul(&y);
                x = x.sqr();
                n = (n - 1) / 2;
            }
        }

        x.mul(&y)
    }
}

#[test]
fn secp256k1_ord_mul_tests() {
    let a = FSecp256Ord {
        v: [0x7cf1bb69abb65af4, 0x895226b5e95d05a4, 0, 0],
    };
    let b = FSecp256Ord {
        v: [0xe2da678a3bd9f587, 0x4bac621d4ea8a910, 0, 0],
    };
    let c = FSecp256Ord {
        v: [
            0x3da8be2067097aac,
            0x720c36a46b88884c,
            0x25ad0ca524dfd0c8,
            0x2897892a78e8917d,
        ],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0x7cf1bb69abb65af4,
            0x895226b5e95d05a4,
            0xfda3e96dd6e46282,
            0xe8f4a37d6822745c,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0xe2da678a3bd9f587,
            0x4bac621d4ea8a910,
            0xc1ef8744f93ea5bf,
            0xc312a8317baa6ef8,
        ],
    };
    let c = FSecp256Ord {
        v: [
            0xe50869bae6e498b1,
            0x7a8fb650e90e23a0,
            0xf7dfab85418e2d39,
            0x8fd65c3ba8ea7394,
        ],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0x683815888e0d92f4,
            0xf0c09326565cd85c,
            0x16c582d119939355,
            0x23f5beeebe460ab2,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0x3c3429ef8429d1,
            0xf5e4f42942510923,
            0x3ca4c3b30a24e04d,
            0xf681f880579d369e,
        ],
    };
    let c = FSecp256Ord {
        v: [
            0x99c75ab576f0eaea,
            0x2ce1fef91c39ae4e,
            0x7f005bffd186bcb5,
            0x50b998e17524c7d6,
        ],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0x433a24161f6f745d,
            0x488fd4c542fdfb78,
            0x4e9cf66908bb7e2f,
            0xed805549c354f6ab,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0xd8763fc041b37c40,
            0xa8f9a298fd273ca0,
            0xa9a4767a7b9aed8b,
            0x480a21b26398b137,
        ],
    };
    let c = FSecp256Ord {
        v: [
            0xcedc7e2a92366974,
            0x187c06863a07b247,
            0xd91ac60a8472bdb2,
            0xa3952ee002fc816e,
        ],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0x13f11ca9caac665f,
            0xaa9172e1f1644a9,
            0x9fd9a89af800a9c4,
            0x29b811c09192a9aa,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0x84d0a83965fe3861,
            0x5f3d5e3fa97a750e,
            0xb1d9e0446088fcd8,
            0xf0c38823260ac6a5,
        ],
    };
    let c = FSecp256Ord {
        v: [
            0xd0f897566ef28356,
            0xdcc5ffbabecfb80a,
            0xd750a4e63e7815ad,
            0xd2f688b634d5c47c,
        ],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0xe95905861ab01e7d,
            0x5efbbcf92263b64f,
            0xbef6609471a10c6b,
            0xef41826d28c2c6fa,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0x33c0eb7d6b0d5495,
            0x354c3bf89d0ed9e8,
            0x27a17a9b0f3cda50,
            0xbdf099620c387e55,
        ],
    };
    let c = FSecp256Ord {
        v: [
            0xd1f8fa316b5ba849,
            0x1754adf586713033,
            0x78fc16390d7e09df,
            0x88abfa378719eb29,
        ],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [0x0, 0x0, 0xfffffffffffffffe, 0xffffffffffffffff],
    };
    let b = FSecp256Ord {
        v: [
            0xbfd25e8cd0364140,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let c = FSecp256Ord {
        v: [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0x0, 0x0],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xfffffffffffffffd,
            0xffffffffffffffff,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0xbfd25e8cd0364140,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let c = FSecp256Ord {
        v: [0xbfd25e8cd0364142, 0xbaaedce6af48a03b, 0x0, 0x0],
    };
    let d = a.mul(&b);
    assert!(c == d);

    let a = FSecp256Ord {
        v: [
            0xbfd25e8cc0364142,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let b = FSecp256Ord {
        v: [
            0xbfd25e8cd0364140,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let c = FSecp256Ord {
        v: [0xfffffff, 0x0, 0x0, 0x0],
    };
    let d = a.mul(&b);
    assert!(c == d);
}

#[test]
fn secp256k1_ord_neg_tests() {
    let a = FSecp256Ord {
        v: [
            0x433a24161f6f745d,
            0x488fd4c542fdfb78,
            0x4e9cf66908bb7e2f,
            0xed805549c354f6ab,
        ],
    };
    let a2 = a.neg();
    let a3 = a.add(&a2);
    println!("a : {:?}", a);
    println!("-a: {:?}", a2);
    println!("a3: {:?}", a3);
    assert!(a3 == FSecp256Ord::ZERO);
}

#[test]
fn secp256k1_ord_sub_tests() {
    let a = FSecp256Ord {
        v: [
            0x433a24161f6f745d,
            0x488fd4c542fdfb78,
            0x4e9cf66908bb7e2f,
            0xed805549c354f6ab,
        ],
    };
    let a2 = FSecp256Ord {
        v: [
            0xe95905861ab01e7d,
            0x5efbbcf92263b64f,
            0xbef6609471a10c6b,
            0xef41826d28c2c6fa,
        ],
    };
    let a3 = a.add(&a2);
    let a4 = a3.sub(&a);
    assert!(a4 == a2);
}

#[test]
fn secp256k1_ord_sqr_tests() {
    let a = FSecp256Ord {
        v: [
            0x433a24161f6f745d,
            0x488fd4c542fdfb78,
            0x4e9cf66908bb7e2f,
            0xed805549c354f6ab,
        ],
    };
    let a2 = a.sqr();
    let aa = a.mul(&a);
    assert!(a2 == aa);

    let a = FSecp256Ord {
        v: [
            0xe95905861ab01e7d,
            0x5efbbcf92263b64f,
            0xbef6609471a10c6b,
            0xef41826d28c2c6fa,
        ],
    };
    let a2 = a.sqr();
    let aa = a.mul(&a);
    assert!(a2 == aa);

    let a = FSecp256Ord {
        v: [
            0x6cf5d18fee5877a2,
            0xbaaedce6af48a03a,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let a2 = a.sqr();
    let aa = a.mul(&a);
    assert!(a2 == aa);
}

#[test]
fn secp256k1_ord_inv_tests() {
    let a = FSecp256Ord {
        v: [
            0x433a24161f6f745d,
            0x488fd4c542fdfb78,
            0x4e9cf66908bb7e2f,
            0xed805549c354f6ab,
        ],
    };
    let ainv = a.inv();
    let one = a.mul(&ainv);
    assert!(one == FSecp256Ord::ONE);

    let b = FSecp256Ord {
        v: [
            0xd8763fc041b37c40,
            0xa8f9a298fd273ca0,
            0xa9a4767a7b9aed8b,
            0x480a21b26398b137,
        ],
    };
    let binv = b.inv();
    let one = b.mul(&binv);
    assert!(one == FSecp256Ord::ONE);

    let c = FSecp256Ord {
        v: [
            0xcedc7e2a92366974,
            0x187c06863a07b247,
            0xd91ac60a8472bdb2,
            0xa3952ee002fc816e,
        ],
    };
    let cinv = c.inv();
    let one = c.mul(&cinv);
    assert!(one == FSecp256Ord::ONE);

    let d = FSecp256Ord {
        v: [
            0xbfd25e8cd0364122,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let dinv = d.inv();
    let one = d.mul(&dinv);
    assert!(one == FSecp256Ord::ONE);

    let e = FSecp256Ord {
        v: [
            0xbfd25e8cd0361fff,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let einv = e.inv();
    let one = e.mul(&einv);
    assert!(one == FSecp256Ord::ONE);

    let e = FSecp256Ord {
        v: [
            0x6cf5d18fee5877a2,
            0xbaaedce6af48a03a,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ],
    };
    let einv = e.inv();
    let one = e.mul(&einv);
    assert!(one == FSecp256Ord::ONE);

    let e = FSecp256Ord {
        v: [0x0, 0x0, 0xfffffffffffffffe, 0xffffffffffffffff],
    };
    let einv = e.inv();
    let one = e.mul(&einv);
    assert!(one == FSecp256Ord::ONE);
}
