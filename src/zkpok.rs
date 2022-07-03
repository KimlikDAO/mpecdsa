use std::io::prelude::*;

use rand::Rng;

use curves::{precomp, ECGroup, Ford, Secp, SecpOrd};

use super::mpecdsa_error::*;
use super::ro::*;
use super::*;

pub const FS_PROOF_SIZE: usize = SecpOrd::NBYTES + Secp::NBYTES;

pub fn prove_dl_fs<T: Write>(
    x: &SecpOrd,
    gx: &Secp,
    ro: &dyn ro::ModelessROTagger,
    rng: &mut dyn Rng,
    send: &mut T,
) -> Result<(), MPECDSAError> {
    let mut buf = [0u8; 2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE];
    buf[0..RO_TAG_SIZE].copy_from_slice(&ro.next_tag()?);
    gx.to_bytes(&mut buf[RO_TAG_SIZE..(Secp::NBYTES + RO_TAG_SIZE)]);
    let (randcommitted, randcommitment) = Secp::rand(rng);
    randcommitment
        .to_bytes(&mut buf[(Secp::NBYTES + RO_TAG_SIZE)..(2 * Secp::NBYTES + RO_TAG_SIZE)]);
    let mut challenge = [0u8; HASH_SIZE];
    hash(&mut challenge, &buf[0..(2 * Secp::NBYTES + RO_TAG_SIZE)]); // TODO: tag
    let challenge = SecpOrd::from_bytes(&challenge[..]);

    let z = x.mul(&challenge).add(&randcommitted);
    z.to_bytes(&mut buf[(2 * Secp::NBYTES + RO_TAG_SIZE)..]);

    send.write(&buf[(Secp::NBYTES + RO_TAG_SIZE)..])?;
    Ok(())
}

pub fn verify_dl_fs<T: Read>(
    gx: &Secp,
    ro: &ModelessDyadicROTagger,
    recv: &mut T,
) -> Result<bool, MPECDSAError> {
    let mut buf = [0u8; 2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE];
    gx.to_bytes(&mut buf[RO_TAG_SIZE..(Secp::NBYTES + RO_TAG_SIZE)]);

    buf[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_counterparty_tag()?);

    recv.read_exact(&mut buf[(Secp::NBYTES + RO_TAG_SIZE)..])?;
    let randcommitment: Secp =
        Secp::from_bytes(&buf[(Secp::NBYTES + RO_TAG_SIZE)..(2 * Secp::NBYTES + RO_TAG_SIZE)]);

    let mut challenge = [0u8; HASH_SIZE];
    hash(&mut challenge, &buf[0..(2 * Secp::NBYTES + RO_TAG_SIZE)]); // TODO: tag

    let challenge = SecpOrd::from_bytes(&challenge[..]);
    let z = SecpOrd::from_bytes(
        &buf[(2 * Secp::NBYTES + RO_TAG_SIZE)..(2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE)],
    );

    let gresp = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &z).affine();
    let gresp_exp = Secp::op(&gx.scalar_table(&challenge), &randcommitment).affine();

    Ok(gresp == gresp_exp)
}

pub fn prove_dl_fs_to_com(
    x: &SecpOrd,
    gx: &Secp,
    ro: &dyn ModelessROTagger,
    rng: &mut dyn Rng,
) -> Result<([u8; HASH_SIZE], [u8; SecpOrd::NBYTES + Secp::NBYTES]), MPECDSAError> {
    // write proof into a memory buffer
    let mut proof = std::io::Cursor::new(vec![0u8; SecpOrd::NBYTES + Secp::NBYTES + RO_TAG_SIZE]);

    // we perform only local IO, so there should never be an error
    prove_dl_fs(x, gx, ro, rng, &mut proof)?;

    let mut proof = proof.into_inner();
    proof[(SecpOrd::NBYTES + Secp::NBYTES)..].copy_from_slice(&ro.next_tag()?);
    let mut com = [0u8; HASH_SIZE];
    hash(&mut com, &proof);
    let mut proofout = [0u8; SecpOrd::NBYTES + Secp::NBYTES];
    proofout.copy_from_slice(&proof[0..(SecpOrd::NBYTES + Secp::NBYTES)]);
    Ok((com, proofout))
}

pub fn verify_dl_fs_with_com<T: Read>(
    gx: &Secp,
    proofcommitment: &[u8; HASH_SIZE],
    ro: &ModelessDyadicROTagger,
    recv: &mut T,
) -> Result<bool, MPECDSAError> {
    let mut buf = [0u8; 2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE];
    gx.to_bytes(&mut buf[0..Secp::NBYTES]);

    recv.read_exact(&mut buf[Secp::NBYTES..(2 * Secp::NBYTES + SecpOrd::NBYTES)])?;

    let pass = {
        let mut proof =
            std::io::Cursor::new(&buf[Secp::NBYTES..(2 * Secp::NBYTES + SecpOrd::NBYTES)]);
        verify_dl_fs(gx, ro, &mut proof)?
    };

    buf[(2 * Secp::NBYTES + SecpOrd::NBYTES)..]
        .copy_from_slice(&ro.next_dyadic_counterparty_tag()?);

    let mut exp_commitment = [0u8; HASH_SIZE];
    hash(
        &mut exp_commitment,
        &buf[Secp::NBYTES..(2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE)],
    );

    Ok(pass && (proofcommitment == &exp_commitment))
}

pub fn verify_dl_fs_with_com_grouped<T: Read>(
    gx: &[Secp],
    proofcommitment: &[[u8; HASH_SIZE]],
    counterparties: &[usize],
    ro: &dyn ModelessROTagger,
    recv: &mut [&mut Option<T>],
) -> Result<bool, MPECDSAError> {
    let mut comspass = true;
    let mut randcommitment = Secp::INF;
    let mut gxc = Secp::INF;
    let mut z = SecpOrd::ZERO;
    for ii in 0..recv.len() {
        let mut buf = [0u8; 2 * Secp::NBYTES + SecpOrd::NBYTES + 2 * RO_TAG_SIZE];
        if recv[ii].is_some() {
            recv[ii].as_mut().unwrap().read_exact(
                &mut buf[(RO_TAG_SIZE + Secp::NBYTES)
                    ..(2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE)],
            )?;

            randcommitment = Secp::op(
                &randcommitment,
                &Secp::from_bytes(
                    &buf[(Secp::NBYTES + RO_TAG_SIZE)..(2 * Secp::NBYTES + RO_TAG_SIZE)],
                ),
            );

            let tag2 = ro.next_counterparty_tag(counterparties[ii])?;
            buf[0..RO_TAG_SIZE].copy_from_slice(&tag2[..]);

            gx[ii].to_bytes(&mut buf[RO_TAG_SIZE..(Secp::NBYTES + RO_TAG_SIZE)]);

            let mut challenge = [0u8; HASH_SIZE];
            hash(&mut challenge, &buf[0..2 * Secp::NBYTES + RO_TAG_SIZE]); // TODO: tag

            let challenge = SecpOrd::from_bytes(&challenge[..]);
            gxc = Secp::op(&gxc, &gx[ii].scalar_table(&challenge));
            z = z.add(&SecpOrd::from_bytes(
                &buf[(2 * Secp::NBYTES + RO_TAG_SIZE)
                    ..(2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE)],
            ));

            buf[(2 * Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE)..]
                .copy_from_slice(&ro.next_counterparty_tag(counterparties[ii])?);
            let mut exp_commitment = [0u8; HASH_SIZE];
            hash(
                &mut exp_commitment,
                &buf[(RO_TAG_SIZE + Secp::NBYTES)
                    ..(2 * Secp::NBYTES + SecpOrd::NBYTES + 2 * RO_TAG_SIZE)],
            ); // TODO: tag
            comspass = comspass && (proofcommitment[ii] == exp_commitment);
        }
    }

    let gresp = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &z).affine();
    let gresp_exp = Secp::op(&gxc, &randcommitment).affine();

    Ok((gresp == gresp_exp) && comspass)
}
