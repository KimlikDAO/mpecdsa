use std::io;
use std::io::prelude::*;

use rand::{Rng};

use curves::{Ford, ECGroup, Secp, SecpOrd, precomp};

use super::*;

pub const FS_PROOF_SIZE: usize = SecpOrd::NBYTES + Secp::NBYTES;

pub fn prove_dl_fs<T:Write>(x:&SecpOrd, gx:&Secp , rng:&mut Rng, send:&mut T) -> io::Result<()> {
	let mut buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES];
	gx.to_bytes(&mut buf[0..Secp::NBYTES]);
	let (randcommitted,randcommitment) = Secp::rand(rng);
	randcommitment.to_bytes(&mut buf[Secp::NBYTES..2*Secp::NBYTES]);
	let mut challenge = [0u8; HASH_SIZE];
	hash(&mut challenge, &buf[0..2*Secp::NBYTES]);
	let challenge = SecpOrd::from_bytes(&challenge[..]);

	let z = x.mul(&challenge).add(&randcommitted);
	z.to_bytes(&mut buf[2*Secp::NBYTES..]);

	try!(send.write( &buf[Secp::NBYTES..]));
	Ok(())
}

pub fn verify_dl_fs<T:Read>(gx:&Secp, recv:&mut T) -> io::Result<bool> {
	let mut buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES];
	gx.to_bytes(&mut buf[0..Secp::NBYTES]);

	try!(recv.read_exact(&mut buf[Secp::NBYTES..]));
	let randcommitment: Secp = Secp::from_bytes(&buf[Secp::NBYTES..2*Secp::NBYTES]);

	let mut challenge = [0u8; HASH_SIZE];
	hash(&mut challenge, &buf[0..2*Secp::NBYTES]);

	let challenge = SecpOrd::from_bytes(&challenge[..]);
	let z = SecpOrd::from_bytes(&buf[2*Secp::NBYTES..2*Secp::NBYTES+SecpOrd::NBYTES]);

	let gresp = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &z).affine();
	let gresp_exp = Secp::op(&gx.scalar_table(&challenge),&randcommitment).affine();

	Ok(gresp == gresp_exp)
}

pub fn prove_dl_fs_to_com(x:&SecpOrd, gx:&Secp , rng:&mut Rng) -> ([u8;HASH_SIZE], [u8;SecpOrd::NBYTES + Secp::NBYTES]) {
	// write proof into a memory buffer
	let mut proof  = std::io::Cursor::new(vec![0u8; SecpOrd::NBYTES + Secp::NBYTES]);

	// we perform only local IO, so there should never be an error
	prove_dl_fs(x, gx, rng, &mut proof).unwrap();

	let proof = proof.into_inner();
	let mut com = [0u8;HASH_SIZE];
	hash(&mut com, &proof);
	let mut proofout = [0u8; SecpOrd::NBYTES + Secp::NBYTES];
	proofout.copy_from_slice(&proof);
	(com, proofout)
}

pub fn verify_dl_fs_with_com<T:Read>(gx:&Secp, proofcommitment:&[u8;HASH_SIZE], recv:&mut T) -> io::Result<bool> {
	let mut buf = [0u8; 2*Secp::NBYTES+SecpOrd::NBYTES];
	gx.to_bytes(&mut buf[0..Secp::NBYTES]);

	try!(recv.read_exact(&mut buf[Secp::NBYTES..(2*Secp::NBYTES+SecpOrd::NBYTES)]));
	let mut proof  = std::io::Cursor::new(&buf[Secp::NBYTES..(2*Secp::NBYTES+SecpOrd::NBYTES)]);

	let pass = try!(verify_dl_fs(gx, &mut proof));

	let mut exp_commitment = [0u8; HASH_SIZE];
	hash(&mut exp_commitment, &buf[Secp::NBYTES..(2*Secp::NBYTES+SecpOrd::NBYTES)]);

	Ok(pass && (proofcommitment==&exp_commitment))
}