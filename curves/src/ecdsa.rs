use super::{ECGroup, Ford, Fq};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
///
/// test implementation of ecdsa operations
///
/// aas, neucrypt
use rand::Rng;

fn hash<'a>(msg: &[u8], res: &mut [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.input(msg);
    hasher.result(&mut res[0..32]);
}

pub fn ecdsa_keygen<F: Fq, T: Ford, E: ECGroup<F, T>>(rng: &mut dyn Rng) -> (T, E) {
    let (sk, pk): (T, E) = E::rand(rng);
    debug_assert!(E::gen().scalar(&sk).affine() == pk);
    (sk, pk)
}

pub fn ecdsa_verify_with_tables<F: Fq, T: Ford, E: ECGroup<F, T>>(
    msg: &[u8],
    sig: (&T, &T),
    gentable: &[E],
    pktable: &[E],
) -> bool {
    let r = sig.0;
    let s = sig.1;

    if r.is_zero() || s.is_zero() {
        return false;
    }

    // r,s are in range [1,order-1]
    // z = hash(msg)
    let mut z = [0; 32];
    hash(msg, &mut z);
    let z = T::from_bytes(&z[0..32]);

    // w = s^{-1}
    // u1 = zw mod n
    // u2 = rw mod n
    let w = s.inv();
    let u1 = z.mul(&w);
    let u2 = r.mul(&w);

    // p = g^u1 * pk^u2
    // check p.x == r
    let p = E::op(
        &E::scalar_table_multi(pktable, &u2),
        &E::scalar_table_multi(gentable, &u1),
    )
    .affine();
    let mut pb = [0; 32];
    p.x().to_bytes(&mut pb);
    let px = T::from_bytes(&pb[..]);
    if px == *r {
        return true;
    }

    return false;
}

pub fn ecdsa_verify<F: Fq, T: Ford, E: ECGroup<F, T>>(msg: &[u8], sig: (&T, &T), pk: &E) -> bool {
    if pk.is_infinity() {
        return false;
    }
    // pk lies on curve
    // pk has order n
    let pktable = E::precomp_table(pk);
    let gentable = E::precomp_table(&E::gen());
    ecdsa_verify_with_tables(msg, sig, &gentable[..], &pktable[..])
}

pub fn ecdsa_sign<F: Fq, T: Ford, E: ECGroup<F, T>>(
    msg: &[u8],
    sk: &T,
    rng: &mut dyn Rng,
) -> (T, T) {
    // Calculate e = HASH ( m )
    // Let z be the L_{n} leftmost bits of e where L_{n} is the bit len of the grp order n.
    // Select k in [1,order-1]
    // Compute (x,y) <-- k * g
    // Compute r = x mod n
    // Compute s =  s=k^{-1}(z+r sk) mod n. If s = 0, go back to step 3.
    // The signature is the pair (r,s).

    let (k, gk): (T, E) = E::rand(rng);
    let mut rxb = [0; 32];
    gk.x().to_bytes(&mut rxb[0..32]);
    let r = T::from_bytes(&rxb[0..32]);

    // probability that r == 0 is exponentially small. we skip the check

    let kinv = k.inv();

    let mut z = [0; 32];
    hash(msg, &mut z);
    let z = T::from_bytes(&z[0..32]);

    // s = k^{-1} * ( z + r * sk ) mod order
    let s = kinv.mul(&z.add(&r.mul(&sk)));
    // probability that s == 0 is exponentially small. we skip the check

    (r, s)
}

#[cfg(test)]
mod tests {
    extern crate rand;
    use super::super::f_4141::FSecp256Ord;
    use super::super::f_fc2f::FSecp256;
    use super::super::secp256k1::P256;
    use super::*;
    use test::Bencher;

    #[test]
    fn test_ecdsa() {
        let mut rng = rand::os::OsRng::new().unwrap();
        let (sk, pk): (FSecp256Ord, P256<FSecp256, FSecp256Ord>) = ecdsa_keygen(&mut rng);

        let pkt = P256::gen().scalar(&sk).affine();
        assert!(pk == pkt);

        let msg = &"this is a random test message that is long".as_bytes();

        let (rx, s) =
            ecdsa_sign::<FSecp256, FSecp256Ord, P256<FSecp256, FSecp256Ord>>(msg, &sk, &mut rng);

        assert!(ecdsa_verify(msg, (&rx, &s), &pk));

        assert!(ecdsa_verify(msg, (&FSecp256Ord::ZERO, &s), &pk) == false);

        assert!(ecdsa_verify(msg, (&rx, &FSecp256Ord::ONE), &pk) == false);

        let inf = P256::<FSecp256, FSecp256Ord>::INF;
        assert!(ecdsa_verify(msg, (&rx, &s), &inf) == false);

        assert!(ecdsa_verify(&"other msg".as_bytes(), (&rx, &s), &pk) == false);
    }

    #[test]
    fn test_sign() {
        let mut rng = rand::os::OsRng::new().unwrap();
        let pk = P256::from_xy(
            &FSecp256::from_slice(&[
                0x7af580e1c312a,
                0xd6836084d8c4e,
                0x5052dc1851870,
                0xafe55d61c400,
                0x8d7b1eb00714,
            ]),
            &FSecp256::from_slice(&[
                0x58828dca1f64e,
                0xcf1ed800b91e9,
                0x4de0a50ffa76e,
                0xdd6b840fa7b97,
                0xb261db36aebe,
            ]),
        )
        .unwrap();

        let sk = FSecp256Ord::from_slice(&[
            0x2944b11bef5b2ec9,
            0xdeedd1bda9f8eacd,
            0x5c1f888b21b87605,
            0x31c615aca4a906c6,
        ]);

        let msg = &"this is a test".as_bytes();

        let (rx, s): (FSecp256Ord, FSecp256Ord) =
            ecdsa_sign::<FSecp256, FSecp256Ord, P256<FSecp256, FSecp256Ord>>(msg, &sk, &mut rng);
        println!(" r = {:?}", rx);
        println!(" s = {:?}", s);

        assert!(ecdsa_verify(msg, (&rx, &s), &pk));
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) -> () {
        let mut rng = rand::thread_rng();
        let sk = FSecp256Ord::rand(&mut rng);

        let msg = &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();

        b.iter(|| {
            ecdsa_sign::<FSecp256, FSecp256Ord, P256<FSecp256, FSecp256Ord>>(msg, &sk, &mut rng);
        });
    }
}
