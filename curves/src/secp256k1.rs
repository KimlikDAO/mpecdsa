///
/// Curve equation y^2 = x^3 + 7.
///
/// The field is mod
/// 115792089237316195423570985008687907853269984665640564039457584007908834671663
///
///
/// Generator is
/// (55066263022277343669578718895168534326250603453777594175500187360389116729240 : 32670510020758816978083085130507043184471273380659243275938904335757337482424 : 1)
/// (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)
///
///
/// aas, neucrypt
use super::{ECGroup, Ford, Fq};
use rand::Rng;
use std::fmt;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct P256<F: Fq + Copy + Eq, T: Ford> {
    pub x: F,
    pub y: F,
    pub z: F,
    pub inf: bool,

    /// this field is used only because the rand/scalar trait methods
    /// require a type T that handles order arithmetic
    pub p: PhantomData<T>,
}

const CURVE_B: u64 = 7;
const CURVE_B3: u64 = 3 * CURVE_B;

impl<F, T> Debug for P256<F, T>
where
    F: Fq,
    T: Ford,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "x: {:?}\n      y: {:?}\n      z: {:?} i:{:?}",
            self.x, self.y, self.z, self.inf
        )
    }
}

impl<F, T> Display for P256<F, T>
where
    F: Fq,
    T: Ford,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "x:{}, y:{}, z:{}, inf:{}",
            self.x, self.y, self.z, self.inf
        )
    }
}

impl<F, T> ECGroup<F, T> for P256<F, T>
where
    F: Fq,
    T: Ford,
{
    const INF: Self = P256 {
        x: F::ZERO,
        y: F::ONE,
        z: F::ZERO,
        inf: true,
        p: PhantomData,
    };
    const NBYTES: usize = 2 * F::NBYTES;

    fn gen() -> Self {
        P256 {
            x: F::from_slice(&[
                0x2815B16F81798,
                0xDB2DCE28D959F,
                0xE870B07029BFC,
                0xBBAC55A06295C,
                0x79BE667EF9DC,
            ]),
            y: F::from_slice(&[
                0x7D08FFB10D4B8,
                0x48A68554199C4,
                0xE1108A8FD17B4,
                0xC4655DA4FBFC0,
                0x483ADA7726A3,
            ]),
            z: F::ONE,
            p: PhantomData,
            inf: false,
        }
    }

    fn x(&self) -> F {
        self.x
    }
    fn y(&self) -> F {
        self.y
    }

    /// Should return a Result() that is the point, or an error if the
    /// x and y are not on the point
    fn from_xy(x: &F, y: &F) -> Result<Self, &'static str> {
        let x2 = x.sqr();
        let x3 = x2.mul(&x);
        let mut lhs = x3.add(&F::from_slice(&[CURVE_B, 0, 0, 0, 0]));
        let mut rhs = y.sqr();
        lhs.normalize();
        rhs.normalize();

        if lhs == rhs {
            Result::Ok(P256 {
                x: *x,
                y: *y,
                z: F::ONE,
                inf: false,
                p: PhantomData,
            })
        } else {
            Result::Err("Point is not on curve (y^2 = x^3 + 7)")
        }
    }

    // can also generate by hashing to the curve
    fn rand(rng: &mut dyn Rng) -> (T, Self) {
        let x = <T as Ford>::rand(rng);
        let p = Self::scalar_gen(&x).affine();
        (x, p)
    }

    fn is_infinity(&self) -> bool {
        self.inf
    }

    fn affine(&self) -> Self {
        if self.inf {
            Self::INF
        } else {
            let zi = self.z.inv();
            let mut x = self.x.mul(&zi);
            let mut y = self.y.mul(&zi);

            x.normalize();
            y.normalize();

            P256 {
                x: x,
                y: y,
                z: F::ONE,
                inf: self.inf,
                p: PhantomData,
            }
        }
    }

    fn op(a: &Self, b: &Self) -> Self {
        // algorithm 7 from https://eprint.iacr.org/2015/1060.pdf
        if b.inf {
            return P256 {
                x: a.x,
                y: a.y,
                z: a.z,
                inf: a.inf,
                p: PhantomData,
            };
        } else if a.inf {
            return P256 {
                x: b.x,
                y: b.y,
                z: b.z,
                inf: b.inf,
                p: PhantomData,
            };
        }

        let t0 = a.x.mul(&b.x);
        let t1 = a.y.mul(&b.y); // 2 t1 = y1 * y2
        let t2 = a.z.mul(&b.z); // 3 t2 = z1 * Z2
        let t3 = a.x.add(&a.y); // 4 t3 = X1 + Y1
        let t4 = b.x.add(&b.y); // 5. t4 ← X2 + Y2
        let t3 = t3.mul(&t4); // 6. t3 ← t3 · t4
        let t4 = t0.add(&t1); // 7. t4 ← t0 + t1
        let t3 = t3.add(&t4.neg(2)); // 8. t3 ← t3−t4
        let t4 = a.y.add(&a.z); // 9. t4 ← Y1+Z1
        let x3 = b.y.add(&b.z); // 10. X3 ← Y2+b.z
        let t4 = t4.mul(&x3); // 11. t4 ← t4·X3
        let x3 = t1.add(&t2); // 12. X3 ← t1+t2
        let t4 = t4.add(&x3.neg(2)); // 13. t4 ← t4−x3
        let x3 = a.x.add(&a.z); // 14. x3 ← X1+Z1
        let y3 = b.x.add(&b.z); // 15. Y3 ← X2+Z2
        let x3 = x3.mul(&y3); // 16. x3 ← x3·y3
        let y3 = t0.add(&t2); // 17. y3 ← t0+t2
        let y3 = x3.add(&y3.neg(2)); // 18. y3 ← x3−y3
        let x3 = t0.add(&t0); // 19. x3 ← t0+t0
        let t0 = x3.add(&t0); // 20. t0 ← x3+t0

        let t2 = t2.muli(CURVE_B3); // 21. t2 ← b3·t2
        let mut z3 = t1.add(&t2); // 22. Z3 ← t1+t2
        let mut t1 = t1.add(&t2.neg(21)); // 23. t1 ← t1−t2
        let mut y3 = y3.muli(CURVE_B3); // 24. y3 ← b3·y3
        y3.normalize_weak();
        z3.normalize_weak();

        let x3 = t4.mul(&y3); // 25. x3 ← t4·y3
        t1.normalize();
        let t2 = t3.mul(&t1); // 26. t2 ← t3·t1

        let mut x3 = t2.add(&x3.neg(1)); // 27. x3 ← t2−x3
        let y3 = y3.mul(&t0); // 28. y3 ← y3·t0

        let t1 = t1.mul(&z3); // 29. t1 ← t1·z3
        let mut y3 = t1.add(&y3); // 30. y3 ← t1+y3

        let t0 = t0.mul(&t3); // 31. t0 ← t0·t3
        let z3 = z3.mul(&t4); // 32. z3 ← z3·t4
        let mut z3 = z3.add(&t0); // 33. z3 ← z3+t0

        x3.normalize();
        y3.normalize();
        z3.normalize();

        let inf = x3.is_zero() && z3.is_zero();
        P256 {
            x: x3,
            y: y3,
            z: z3,
            inf: inf,
            p: PhantomData,
        }
    }

    fn dbl(&self) -> Self {
        let t0 = self.y.sqr(); // 1. t0 ← Y·Y
        let z3 = t0.add(&t0); // 2. Z3 ← t0+t0
        let z3 = z3.add(&z3); // 3. Z3 ← Z3+Z3
        let z3 = z3.add(&z3); // 4. Z3 ← Z3+Z3
        let t1 = self.y.mul(&self.z); // 5. t1 ← Y·Z
        let t2 = self.z.sqr(); // 6. t2 ← Z·Z
        let mut t2 = t2.muli(CURVE_B3); // 7. t2 ← b3·t2
        t2.normalize();
        let x3 = t2.mul(&z3); // 8. X3 ← t2·Z3
        let y3 = t0.add(&t2); // 9. Y3 ← t0+t2
        let mut z3 = t1.mul(&z3); // 10. Z3 ← t1·Z3
        let t1 = t2.add(&t2); // 11. t1 ← t2+t2
        let t2 = t1.add(&t2); // 12. t2 ← t1+t2
        let t0 = t0.add(&t2.neg(3)); // 13. t0 ← t0−t2
        let y3 = t0.mul(&y3); // 14. Y3 ← t0·Y3
        let mut y3 = x3.add(&y3); // 15. Y3 ← X3+Y3
        let t1 = self.x.mul(&self.y); // 16. t1 ← X·Y
        let x3 = t0.mul(&t1); // 17. X3 ← t0·t1
        let mut x3 = x3.add(&x3); // 18. X3 ← X3+X3

        z3.normalize();
        x3.normalize();
        y3.normalize();

        P256 {
            x: x3,
            y: y3,
            z: z3,
            inf: self.inf,
            p: PhantomData,
        }
    }

    fn neg(&self) -> Self {
        let mut y = self.y.clone();
        y.normalize_weak();
        let y = y.neg(1);
        P256 {
            x: self.x,
            y: y,
            z: self.z,
            inf: self.inf,
            p: PhantomData,
        }
    }

    fn scalar(&self, x: &T) -> Self {
        if x.is_zero() || self.inf {
            return P256::INF;
        }
        // /* use Ladder, replace conditional with mux and swap */
        let mut r0 = P256::INF;
        let mut r1 = self.clone();

        let nb = T::NBITS;
        for i in (0..nb).rev() {
            let b = x.bit(i as usize);

            let sum = P256::op(&r0, &r1);

            let mut db = P256 {
                x: r0.x,
                y: r0.y,
                z: r0.z,
                inf: r0.inf,
                p: PhantomData,
            };
            F::mux(&mut db.x, &r0.x, &r1.x, b as u32);
            F::mux(&mut db.y, &r0.y, &r1.y, b as u32);
            F::mux(&mut db.z, &r0.z, &r1.z, b as u32);
            db.inf = ((b == false) & r0.inf) | (b == true) & r1.inf;

            let db = db.dbl();

            // if b==0 { r1 = t; r0 = dbl(r0); }
            // if b==1 { r0 = t; r1 = dbl(r1); }
            r0 = db;
            r1 = sum;
            F::swap(&mut r0.x, &mut r1.x, b as u32);
            F::swap(&mut r0.y, &mut r1.y, b as u32);
            F::swap(&mut r0.z, &mut r1.z, b as u32);
            r0.inf = ((b == false) & r0.inf) | ((b == true) & r1.inf);
            r1.inf = ((b == false) & r1.inf) | ((b == true) & r0.inf);
        }

        let inf = r0.x.is_zero() && r0.z.is_zero();
        if inf {
            r0.y = F::ONE;
        }
        return P256 {
            x: r0.x,
            y: r0.y,
            z: r0.z,
            inf: inf,
            p: PhantomData,
        };
    }

    fn scalar_table(&self, x: &T) -> Self {
        let table = Self::precomp_table(self);
        Self::scalar_table_multi(&table[..], x)
    }

    /// Yao Multiexp. This method is not constant time, and has cache-line miss side-channels
    fn scalar_table_multi(table: &[Self], x: &T) -> Self {
        let mut dz = [Self::INF; 16];

        let nw = T::NBITS / 4;
        for j in 0..nw {
            let mut w = x.get_window(j as usize);
            // // write c_j = 2^p * q where q is odd
            if w != 0 {
                let mut p = 0;
                while (w & 1) == 0 {
                    p = p + 1;
                    w = w >> 1
                }
                debug_assert!((w % 2) == 1);

                dz[w as usize] = Self::op(&dz[w as usize], &table[j * 4 + p]);
            }
        }

        // sum d[z]*z for odd terms
        let a = Self::op(&dz[15], &dz[13]);
        let r = Self::op(&a, &dz[15]);
        let a = Self::op(&a, &dz[11]);
        let r = Self::op(&r, &a);
        let a = Self::op(&a, &dz[9]);
        let r = Self::op(&r, &a);
        let a = Self::op(&a, &dz[7]);
        let r = Self::op(&r, &a);
        let a = Self::op(&a, &dz[5]);
        let r = Self::op(&r, &a);
        let a = Self::op(&a, &dz[3]);
        let r = Self::op(&r, &a);
        let r = r.dbl();
        let a = Self::op(&a, &dz[1]);
        let r = Self::op(&r, &a);

        r.affine()
    }

    default fn scalar_gen(x: &T) -> Self {
        Self::gen().scalar(x)
    }

    fn precomp_table(x: &Self) -> Vec<Self> {
        let mut table = Vec::<Self>::with_capacity(T::NBITS);
        table.push(*x);
        for i in 1..T::NBITS {
            let nextentry = table[i - 1].dbl();
            table.push(nextentry);
        }
        table
    }

    /// self needs to be normalized before calling this method
    fn to_bytes(&self, b: &mut [u8]) {
        self.x.to_bytes(&mut b[0..32]);
        self.y.to_bytes(&mut b[32..64]);
    }

    fn from_bytes(b: &[u8]) -> Self {
        let x = F::from_bytes(&b[0..32]);
        let y = F::from_bytes(&b[32..64]);

        P256 {
            x: x,
            y: y,
            z: F::ONE,
            inf: false,
            p: PhantomData,
        }
    }
}

//Note: this will hopefully work when Rust gets specialization right, but not yet.
/*impl P256<FSecp256, FSecp256Ord> {
    fn scalar_gen(x:&FSecp256Ord) -> Self {
        Self::scalar_table_multi(&precomp::P256_TABLE[..], x)
    }
}*/

impl<F, T> P256<F, T>
where
    F: Fq,
    T: Ford,
{
    // fast scalar
    // fast multi-exp

    //	const table: [ P256<F, T>; 5] = tab();

    // fn hash_to_curve(message: &[u8]) -> Self;

    // This method is taken from the C language secp256k1 implementation
    // to compare speed.  It is not a constant time operation.
    pub fn op2(a: &P256<F, T>, b: &P256<F, T>) -> P256<F, T> {
        //     VERIFY_CHECK(!b->infinity);
        //     VERIFY_CHECK(a->infinity == 0 || a->infinity == 1);

        //     /** In:
        //      *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
        //      *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
        //      *  we find as solution for a unified addition/doubling formula:
        //      *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
        //      *    x3 = lambda^2 - (x1 + x2)
        //      *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
        //      *
        //      *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
        //      *    U1 = X1*Z2^2, U2 = X2*Z1^2
        //      *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
        //      *    Z = Z1*Z2
        //      *    T = U1+U2
        //      *    M = S1+S2
        //      *    Q = T*M^2
        //      *    R = T^2-U1*U2
        //      *    X3 = 4*(R^2-Q)
        //      *    Y3 = 4*(R*(3*Q-2*R^2)-M^4)
        //      *    Z3 = 2*M*Z
        //      *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
        //      *
        //      *  This formula has the benefit of being the same for both addition
        //      *  of distinct points and doubling. However, it breaks down in the
        //      *  case that either point is infinity, or that y1 = -y2. We handle
        //      *  these cases in the following ways:
        //      *
        //      *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
        //      *
        //      *    - If a is infinity, we detect this, and at the end of the
        //      *      computation replace the result (which will be meaningless,
        //      *      but we compute to be constant-time) with b.x : b.y : 1.
        //      *
        //      *    - If a = -b, we have y1 = -y2, which is a degenerate case.
        //      *      But here the answer is infinity, so we simply set the
        //      *      infinity flag of the result, overriding the computed values
        //      *      without even needing to cmov.
        //      *
        //      *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
        //      *      properties of our curve (specifically, 1 has nontrivial cube
        //      *      roots in our field, and the curve equation has no x coefficient)
        //      *      then the answer is not infinity but also not given by the above
        //      *      equation. In this case, we cmov in place an alternate expression
        //      *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
        //      *      expressions for lambda are defined, they are equal, and can be
        //      *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
        //      *      then substitution of x^3 + 7 for y^2 (using the curve equation).
        //      *      For all pairs of nonzero points (a, b) at least one is defined,
        //      *      so this covers everything.
        //      */
        let zz = a.z.sqr(); /* z = Z1^2 */
        let mut u1 = a.x; /* u1 = U1 = X1*Z2^2 (1) */
        u1.normalize_weak();
        let u2 = b.x.mul(&zz); /* u2 = U2 = X2*Z1^2 (1) */
        let mut s1 = a.y; /* s1 = S1 = Y1*Z2^3 (1) */
        s1.normalize_weak();
        let s2 = b.y.mul(&zz); /* s2 = Y2*Z1^2 (1) */
        let s2 = s2.mul(&a.z); /* s2 = S2 = Y2*Z1^3 (1) */
        let t = u1.add(&u2); /* t = T = U1+U2 (2) */
        let m = s1.add(&s2); /* m = M = S1+S2 (2) */
        let rr = t.sqr(); /* rr = T^2 (1) */
        // //     secp256k1_fe_neg(&m_alt, &u2, 1);                /* Malt = -X2*Z1^2 */
        let malt = u2.neg(1);
        // //     secp256k1_fe_mul(&tt, &u1, &m_alt);                 /* tt = -U1*U2 (2) */
        let tt = u1.mul(&malt);
        // //     secp256k1_fe_add(&rr, &tt);                         /* rr = R = T^2-U1*U2 (3) */
        let rr = rr.add(&tt);
        //     /** If lambda = R/M = 0/0 we have a problem (except in the "trivial"
        //      *  case that Z = z1z2 = 0, and this is special-cased later on). */
        let degenerate = m.is_zero() & rr.is_zero();
        //     degenerate = secp256k1_fe_normalizes_to_zero(&m) &
        //                  secp256k1_fe_normalizes_to_zero(&rr);
        //     /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
        //      * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
        //      * a nontrivial cube root of one. In either case, an alternate
        //      * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
        //      * so we set R/M equal to this. */
        let mut rr_alt = s1.muli(2);
        // //     secp256k1_fe_mul_int(&rr_alt, 2);       /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
        let mut malt = malt.add(&u1);
        // //     secp256k1_fe_add(&m_alt, &u1);          /* Malt = X1*Z2^2 - X2*Z1^2 */
        rr_alt.mov(&rr, !degenerate);
        malt.mov(&m, !degenerate);
        // //     secp256k1_fe_cmov(&rr_alt, &rr, !degenerate);
        // //     secp256k1_fe_cmov(&m_alt, &m, !degenerate);

        // //     /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
        // //      * From here on out Ralt and Malt represent the numerator
        // //      * and denominator of lambda; R and M represent the explicit
        // //      * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
        let n = malt.sqr();
        let q = n.mul(&t);
        // //     secp256k1_fe_sqr(&n, &m_alt);                       /* n = Malt^2 (1) */
        // //     secp256k1_fe_mul(&q, &n, &t);                       /* q = Q = T*Malt^2 (1) */
        // //     /* These two lines use the observation that either M == Malt or M == 0,
        // //      * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
        // //      * zero (which is "computed" by cmov). So the cost is one squaring
        // //      * versus two multiplications. */
        // //     secp256k1_fe_sqr(&n, &n);
        // //     secp256k1_fe_cmov(&n, &m, degenerate);              /* n = M^3 * Malt (2) */
        let mut n = n.sqr();
        n.mov(&m, degenerate);
        // //     secp256k1_fe_sqr(&t, &rr_alt);                      /* t = Ralt^2 (1) */
        let t = rr_alt.sqr();
        // //     secp256k1_fe_mul(&r->z, &a->z, &m_alt);             /* r->z = Malt*Z (1) */
        let rz = a.z.mul(&malt);
        // //     infinity = secp256k1_fe_normalizes_to_zero(&r->z) * (1 - a->infinity);
        let infinity = rz.is_zero() & !a.inf;
        // //     secp256k1_fe_mul_int(&r->z, 2);                     /* r->z = Z3 = 2*Malt*Z (2) */
        let mut rz = rz.muli(2);
        // //     secp256k1_fe_neg(&q, &q, 1);                     /* q = -Q (2) */
        let q = q.neg(1);
        // //     secp256k1_fe_add(&t, &q);                           /* t = Ralt^2-Q (3) */
        let mut t = t.add(&q);
        // //     secp256k1_fe_normalize_weak(&t);
        t.normalize_weak();
        let rx = t;
        // //     r->x = t;                                           /* r->x = Ralt^2-Q (1) */
        // //     secp256k1_fe_mul_int(&t, 2);                        /* t = 2*x3 (2) */
        let t = t.muli(2);
        // //     secp256k1_fe_add(&t, &q);                           /* t = 2*x3 - Q: (4) */
        let t = t.add(&q);
        // //     secp256k1_fe_mul(&t, &t, &rr_alt);                  /* t = Ralt*(2*x3 - Q) (1) */
        let t = t.mul(&rr_alt);
        // //     secp256k1_fe_add(&t, &n);                           /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
        let t = t.add(&n);
        // //     secp256k1_fe_neg(&r->y, &t, 3);                  /* r->y = Ralt*(Q - 2x3) - M^3*Malt (4) */
        let mut ry = t.neg(3);
        ry.normalize_weak();
        // //     secp256k1_fe_normalize_weak(&r->y);
        // //     secp256k1_fe_mul_int(&r->x, 4);                     /* r->x = X3 = 4*(Ralt^2-Q) */
        // //     secp256k1_fe_mul_int(&r->y, 4);                     /* r->y = Y3 = 4*Ralt*(Q - 2x3) - 4*M^3*Malt (4) */
        let mut rx = rx.muli(4);
        let mut ry = ry.muli(4);

        // //     /** In case a->infinity == 1, replace r with (b->x, b->y, 1). */
        // //     secp256k1_fe_cmov(&r->x, &b->x, a->infinity);
        // //     secp256k1_fe_cmov(&r->y, &b->y, a->infinity);
        // //     secp256k1_fe_cmov(&r->z, &fe_1, a->infinity);

        rx.mov(&b.x, a.inf);
        ry.mov(&b.y, a.inf);
        rz.mov(&F::ONE, a.inf);
        P256 {
            x: rx,
            y: ry,
            z: rz,
            inf: infinity,
            p: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    const N: usize = 1000;

    use super::super::f_4141::FSecp256Ord;
    use super::super::f_fc2f::FSecp256;
    use super::*;
    extern crate rand;
    use test::Bencher;

    #[test]
    fn test_secp() {
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();

        // check that generator is on the curve
        let x2 = g.x.sqr();
        let x3 = x2.mul(&g.x);
        let x37 = x3.add(&FSecp256::from_slice(&[7, 0, 0, 0, 0]));
        let y2 = g.y.sqr();
        assert!(x37 == y2);

        let g2 = g.dbl();
        let gg = P256::op(&g, &g);
        assert!(g2 == gg);

        // let h2 = P256::op2(&g, &g).affine();
        // println!("h2 = {:?}",h2);

        println!("g2 = {:?}", g2.affine());

        let g3 = P256::op(&g2, &g);
        println!("g3 = {:?}", g3.affine());

        let g4 = P256::op(&g, &g3);
        println!("g4 = {:?}", g4.affine());
        let g7 = P256::op(&g4, &g3).affine();
        println!("g7 = {:?}", g7);

        let r = g.scalar(&FSecp256Ord::from_slice(&[0x7, 0, 0, 0])).affine();
        println!("r = {:?}", r);
        assert!(r == g7);
    }

    #[test]
    fn test_op_inf() {
        let inf = P256::<FSecp256, FSecp256Ord>::INF;

        let ord = FSecp256Ord::from_slice(&[
            0xBFD25E8CD0364141,
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
        ]);
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();
        let gx = g.scalar(&ord).affine();

        assert!(gx == inf);

        let ord = FSecp256Ord::from_slice(&[
            0xBFD25E8CD0364140,
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
        ]);
        let gxi = g.scalar(&ord).affine();
        let id = P256::op(&g, &gxi).affine();

        assert!(id == inf);

        let gi = g.neg();
        let id = P256::op(&g, &gi).affine();

        assert!(id == inf);

        let ga = P256::op(&g, &inf).affine();
        assert!(ga == g);

        let ga = P256::op(&inf, &g).affine();
        assert!(ga == g);

        let ga = P256::op(&inf, &inf).affine();
        assert!(ga == inf);

        let h = P256 {
            x: FSecp256::from_slice(&[
                0x1f9c9f527a236,
                0xdd306f4eef9fa,
                0x515a3a3c1c99d,
                0x1d7adf97384d4,
                0x52a3e8ff594f,
            ]),
            y: FSecp256::from_slice(&[
                0xf3af0c5cda397,
                0xca9fa1b05bedf,
                0xdb5a09a48a033,
                0xdd716f63fc61a,
                0xa90fdb8a7146,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        let ga = P256::op(&h, &inf).affine();
        assert!(ga == h);

        let hi = h.neg();
        let id = P256::op(&h, &hi).affine();
        assert!(id == inf);
    }

    #[test]
    fn test_scalar() {
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();

        let test = |g: P256<FSecp256, FSecp256Ord>, a, ga| {
            let x = g.scalar(&a).affine();
            println!(" ga: {:?}", ga);
            println!("  x: {:?}", x);
            assert!(x == ga);
            let fx = g.scalar(&a).affine();
            println!(" fx: {:?}", fx);
            assert!(fx == ga);
        };

        let a = FSecp256Ord::from_slice(&[0x26fe, 0x0, 0x0, 0x0]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0x13263f90ea75c,
                0x2425e810119dd,
                0xfe562feb0752,
                0xdf86500f3f199,
                0x4659812777be,
            ]),
            y: FSecp256::from_slice(&[
                0x802233c467eb3,
                0xa1a3b6fd9348d,
                0x86a5417d0a357,
                0xf29a5735a2950,
                0x79e0f22c13c7,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[0xc618f3ed, 0x0, 0x0, 0x0]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0xed8e90c86e390,
                0x9b3d78d9fed2d,
                0xc72ec9749dd91,
                0x592a27abeb755,
                0x39bd595e528,
            ]),
            y: FSecp256::from_slice(&[
                0xefd7780266439,
                0xae7a93b9ff8d9,
                0xf6011fd7740ac,
                0x8af482a1648bb,
                0xc53a52861dd,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[0x2dcba694033655c4, 0x2e, 0x0, 0x0]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0x5ff5d1cd6de0e,
                0x23a7f5254afd1,
                0x838c6e21bc34a,
                0x8c82c3fa058ce,
                0xb93aa08b92e4,
            ]),
            y: FSecp256::from_slice(&[
                0xc3578c5067efa,
                0x17b8be93d58d4,
                0x8745a1fc20b12,
                0xc5fb244a8d49b,
                0xce46028cdcc2,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[0x70e212955a161c1, 0xab62294f3829fcb7, 0x1, 0x0]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0x20bd68d31dc85,
                0x2e1a6729bf8c3,
                0xa4dee0c643903,
                0x49aa8c52d995f,
                0x4494de998d64,
            ]),
            y: FSecp256::from_slice(&[
                0x1c799615c9ebe,
                0xefe4801766c0b,
                0x88de11760be9d,
                0x81aee3bcf20b6,
                0x9a6ff21e213b,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[
            0xf3bc8e7468d31971,
            0xb52d50b1711eb143,
            0xb16e51ec1649c5b4,
            0xe2,
        ]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0x78277ef831227,
                0xc748792170501,
                0xaec56a20c3ab1,
                0xec4fc50410aae,
                0x72f1e506d223,
            ]),
            y: FSecp256::from_slice(&[
                0x2e982b7f64695,
                0x332e487292f1d,
                0x78b1091ac1a6f,
                0x40ca8c0b64fb4,
                0xd703ffdf153b,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[
            0x7bc42ecefd6bbefc,
            0x866417a1d7f66cc4,
            0x78d5683c92b5a85a,
            0xfd22581fef3a5f4a,
        ]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0x2dbccf2409831,
                0xfcfadc00b85ea,
                0x2c2181c2f96e0,
                0x1a26f4fb3d9e0,
                0x97edbf1b423e,
            ]),
            y: FSecp256::from_slice(&[
                0x7e91ea68343d0,
                0x6e8afa5b2e053,
                0x924dbbcd3fa65,
                0xcf2c0bc361664,
                0x6b119fbe1c69,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[
            0xb75db84fcf3100fa,
            0x91b7d3f504137195,
            0xdf77ea40442457c7,
            0xd2942f7da864b8f7,
        ]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0xce1fc14c40964,
                0x878e5a24ba89b,
                0x7b94afbe0497b,
                0xc34d08ba41fe0,
                0x8ed182cfabb3,
            ]),
            y: FSecp256::from_slice(&[
                0xb7159d7e6174b,
                0xe8eda690f07d,
                0xddb2ab6e7d875,
                0xf383bff267d94,
                0xbb310a08591a,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        let a = FSecp256Ord::from_slice(&[
            0xf78541d24fe89bc7,
            0x8a7007a0f47ac5b0,
            0x9dce2824684f345f,
            0x10ab8a41b7cd99b0,
        ]);
        let ga = P256 {
            x: FSecp256::from_slice(&[
                0x145fdb43a578a,
                0xfd2e7448e6ab1,
                0x753ac359ab721,
                0x7ce216f629eb8,
                0x7fd815a70e7a,
            ]),
            y: FSecp256::from_slice(&[
                0x53e6edf689eb9,
                0xff265e7abfbf6,
                0xc0016cb2c92a8,
                0x7e005c1e293f1,
                0xf48a0781973c,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(g, a, ga);

        // test different bases

        let a = FSecp256Ord::from_slice(&[
            0xb0691497e7bf4b99,
            0xd9dcbf24f0445346,
            0xce481f6dc2749af3,
            0x1c,
        ]);
        let h = P256 {
            x: FSecp256::from_slice(&[
                0xcf1af7b337e4e,
                0xe12f2076cb56d,
                0x45e71b7c5338a,
                0xec368f90cf58,
                0x3bd3f7d2c159,
            ]),
            y: FSecp256::from_slice(&[
                0x6ae3949d01e47,
                0x4a534948ca8ca,
                0x7549d9835a27d,
                0x7fc815495d549,
                0xb83cdd607c90,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        let ha = P256 {
            x: FSecp256::from_slice(&[
                0xce4ef839827db,
                0x3089be0cd069d,
                0x4a84319529969,
                0xff5230b41e41c,
                0x136f79d4dcff,
            ]),
            y: FSecp256::from_slice(&[
                0x5542ba4ac45c0,
                0xfb4ea43b01f60,
                0x918d733a42f96,
                0x505aac7f71176,
                0x1bf29aee3bdf,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(h, a, ha);

        let h = P256 {
            x: FSecp256::from_slice(&[
                0x1f9c9f527a236,
                0xdd306f4eef9fa,
                0x515a3a3c1c99d,
                0x1d7adf97384d4,
                0x52a3e8ff594f,
            ]),
            y: FSecp256::from_slice(&[
                0xf3af0c5cda397,
                0xca9fa1b05bedf,
                0xdb5a09a48a033,
                0xdd716f63fc61a,
                0xa90fdb8a7146,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        let a = FSecp256Ord::from_slice(&[
            0xbad5eb77a36f35bb,
            0x6abe415244e51651,
            0x1945e7cb89686466,
            0xc6a1b0154b2c43db,
        ]);
        let ha = P256 {
            x: FSecp256::from_slice(&[
                0x228802496188d,
                0x3bef55f2b071d,
                0xb938461a56530,
                0x874313449fe28,
                0xbba7fea0f464,
            ]),
            y: FSecp256::from_slice(&[
                0xf74fd3c55ab34,
                0xd626a915fa8,
                0x469d99767b837,
                0x9c5cffa04c632,
                0xb4ab605d0f52,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(h, a, ha);

        let h = P256 {
            x: FSecp256::from_slice(&[
                0x786c94789e82c,
                0x9c4e03e271608,
                0x7ff5c0e2a8eca,
                0xd75e2a06f3c90,
                0xaef122acbb3b,
            ]),
            y: FSecp256::from_slice(&[
                0x2f1ecbf9c1685,
                0xa43d471424995,
                0xc5aa5c86a225c,
                0xb8e9e329b8434,
                0x7908afbd6254,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        let a = FSecp256Ord::from_slice(&[
            0x190e5240baf32821,
            0x7143472686f0c572,
            0x13f6fe3565b7e930,
            0x1c6eab73e39330b9,
        ]);
        let ha = P256 {
            x: FSecp256::from_slice(&[
                0xec1fe348ca067,
                0x8740c0030110,
                0xad7d8de52f7d5,
                0x963c6cae1a656,
                0xdbfdb05db3cb,
            ]),
            y: FSecp256::from_slice(&[
                0x26e561a144029,
                0xe599b42febb03,
                0xe467aa771caab,
                0x90bb161d5a374,
                0xcf7dec736205,
            ]),
            z: FSecp256::from_slice(&[0x1, 0x0, 0x0, 0x0, 0x0]),
            inf: false,
            p: PhantomData,
        };
        test(h, a, ha);

        // test infinity
    }

    #[test]
    fn test_scalar_table() {
        let mut rng = rand::os::OsRng::new().unwrap();
        let mut x: [FSecp256Ord; N] = [FSecp256Ord::ZERO; N];
        for i in 0..x.len() {
            x[i] = FSecp256Ord::rand(&mut rng);
        }

        let h: P256<FSecp256, FSecp256Ord> = P256::gen();
        let table_h = P256::precomp_table(&h);

        for i in 0..N {
            let y1 = P256::scalar_table_multi(&table_h[..], &x[i]).affine();
            let y2 = P256::scalar_gen(&x[i]).affine();
            let y3 = h.scalar(&x[i]).affine();
            // println!(" gx: {:?}", gx[i]);
            // println!("  y: {:?}", y);
            assert!(y1 == y3);
            assert!(y2 == y3);
        }
    }

    #[bench]
    fn bench_dbl(b: &mut Bencher) {
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();

        b.iter(|| {
            for _i in 0..N {
                g.dbl();
            }
        });
    }

    #[bench]
    fn bench_op(b: &mut Bencher) {
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();

        b.iter(|| {
            for _i in 0..N {
                P256::op(&g, &g);
            }
        });
    }

    #[bench]
    fn bench_op2(b: &mut Bencher) {
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();

        b.iter(|| {
            for _i in 0..N {
                P256::op2(&g, &g);
            }
        });
    }

    #[bench]
    fn bench_scalar(b: &mut Bencher) {
        let mut rng = rand::os::OsRng::new().unwrap();
        let g: P256<FSecp256, FSecp256Ord> = P256::gen();
        let mut x: [FSecp256Ord; N] = [FSecp256Ord::ZERO; N];
        for i in 0..x.len() {
            x[i] = FSecp256Ord::rand(&mut rng);
        }

        b.iter(|| {
            for i in 0..N {
                let _gx = g.scalar(&x[i]).affine();
            }
        });
        //let a = FSecp256Ord::from_slice( &[0xf78541d24fe89bc7, 0x8a7007a0f47ac5b0, 0x9dce2824684f345f, 0x10ab8a41b7cd99b0] );
        //b.iter(|| g.scalar(&a).affine() );
    }

    #[bench]
    fn bench_scalar_table(b: &mut Bencher) {
        let mut rng = rand::os::OsRng::new().unwrap();
        let mut x: [FSecp256Ord; N] = [FSecp256Ord::ZERO; N];
        let h: P256<FSecp256, FSecp256Ord> = P256::gen();
        let table_h = P256::precomp_table(&h);

        for i in 0..x.len() {
            x[i] = FSecp256Ord::rand(&mut rng);
        }

        b.iter(|| {
            for i in 0..N {
                let _gx: P256<FSecp256, FSecp256Ord> =
                    P256::scalar_table_multi(&table_h[..], &x[i]).affine();
            }
        });
    }

    #[bench]
    fn bench_scalar_gen(b: &mut Bencher) {
        let mut rng = rand::os::OsRng::new().unwrap();
        let mut x: [FSecp256Ord; N] = [FSecp256Ord::ZERO; N];

        for i in 0..x.len() {
            x[i] = FSecp256Ord::rand(&mut rng);
        }

        b.iter(|| {
            for i in 0..N {
                let _gx: P256<FSecp256, FSecp256Ord> = P256::scalar_gen(&x[i]).affine();
            }
        });
    }

    #[bench]
    fn bench_precomp_table(b: &mut Bencher) {
        let x: P256<FSecp256, FSecp256Ord> = P256::gen();

        b.iter(|| {
            for _i in 0..N {
                P256::precomp_table(&x);
            }
        });
    }
}
