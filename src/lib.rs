#![feature(test)]
#![feature(vec_resize_default)]
#![feature(fixed_size_array)]
#![feature(integer_atomics)]
#![feature(atomic_min_max)]

pub mod mpecdsa_error;
pub mod ro; // random oracle
pub mod zkpok; // zero knowledge proofs (incl NIZK)
pub mod rot; // random OT
pub mod ote; // OT extension
pub mod mul; // two-party multiplication
pub mod mpmul; // multiparty multiplication
pub mod mpecdsa; // threshold ECDSA
pub mod channelstream; // mock networking for testing

use std::io::prelude::*;
use std::io;

extern crate core;
extern crate rand;
extern crate curves;
extern crate time;
extern crate byteorder;
extern crate bit_reverse;
extern crate rayon;
extern crate test;

#[cfg(feature="openmp")]
extern crate openmp_sys;


extern crate crypto;
use curves::{SecpOrd, Ford};
use crypto::sha2::Sha256;
use crypto::digest::Digest;

extern crate hex;


/* The hash size is essentially a security parameter.
   Note that the hash algorithm must be changed with
   the output size, so that they match. Note also that
   the hash block size must be somewhat larger than
   the hash output size, or things will break. This
   should be done more intelligently in the future.
   */

const RO_TAG_SIZE: usize = 20; // Why 20? Because our vectorized SHA-256 impl takes only 52 = 32+20 bytes as input
pub const HASH_SIZE: usize = 32;
const HASH_BLOCK_SIZE: usize = 64;
const ENCODING_PER_ELEMENT_BITS: usize = SecpOrd::NBITS + 160;
const ENCODING_EXTRA_BITS: usize = 0; // From IN96, this must be 2*s
const RAND_ENCODING_PER_ELEMENT_BITS: usize = SecpOrd::NBITS + 160;
const RAND_ENCODING_EXTRA_BITS: usize = 0; // From IN96, this must be 2*s
const OT_SEC_PARAM: usize = 128 + 80; // From KOS, this should be 128+s



fn ecdsa_hash(res: &mut [u8; HASH_SIZE], msg: &[u8]) {
	let mut hasher = Sha256::new();
	hasher.input(msg);
	hasher.result(res);
}

fn vec_eq(va: &[u8], vb: &[u8]) -> bool {
	(va.len() == vb.len()) &&  // zip stops at the shortest
	 va.iter()
	   .zip(vb)
	   .all(|(a,b)| a == b)
}



#[cfg(feature="blake2")]
extern { 
	fn blake2s(output: *mut u8, outlen: usize, input: *const u8, inlen: usize, key: *const u8, keylen: usize); 
	fn blake2s_multi_raw(input: *const u8, output: *mut u8, count: usize); 
}

#[cfg(feature="blake2")]
fn blake2s_multi(src: &[u8], dst: &mut [u8], count: usize) {
	unsafe {
		//for ii in 0..count {
		//	blake2s(dst[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)].as_mut_ptr(), HASH_SIZE, src[(ii*HASH_BLOCK_SIZE)..((ii+1)*HASH_BLOCK_SIZE)].as_ptr(), HASH_BLOCK_SIZE, std::ptr::null(), 0);
		//}
		blake2s_multi_raw(src.as_ptr(), dst.as_mut_ptr(), count);
	}
}

#[cfg(feature="blake2")]
fn hash_multi(src: &[u8], dst: &mut [u8], count: usize) {
	blake2s_multi(src, dst, count);
}

#[cfg(feature="blake2")]
fn hash(res: &mut [u8; HASH_SIZE], msg: &[u8]) {
	unsafe {
		blake2s(res.as_mut_ptr(), HASH_SIZE, msg.as_ptr(), msg.len(), std::ptr::null(), 0);
	}
}


#[cfg(all(not(feature="blake2"),target_arch="x86_64"))]
extern { 
	// NOTE: assumes count is divisible by 8; assumes inputs are 52 bytes each
	// (last 12 bytes are lost to padding)
	fn sha256_multi_52b(input: *const u8, output: *mut u8, count: usize); 
}

#[cfg(all(not(feature="blake2"),target_arch="x86_64"))]
fn sha256_multi(src: &[u8], dst: &mut [u8], count: usize) {
	unsafe {
		sha256_multi_52b(src.as_ptr(), dst.as_mut_ptr(), count);
	}
}

#[cfg(all(not(feature="blake2"),not(target_arch="x86_64")))]
fn sha256_multi(src: &[u8], dst: &mut [u8], count: usize) {
	let mut hasher = Sha256::new();
	for ii in 0..count {
		hasher.input(&src[(ii*HASH_BLOCK_SIZE)..(ii*HASH_BLOCK_SIZE+52)]);
		hasher.result(&mut dst[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]);
		hasher.reset();
	}
}

#[cfg(not(feature="blake2"))]
fn hash_multi(src: &[u8], dst: &mut [u8], count: usize) {
	sha256_multi(src, dst, count);
}

#[cfg(not(feature="blake2"))]
fn hash(res: &mut [u8; HASH_SIZE], msg: &[u8]) {
	let mut hasher = Sha256::new();
	hasher.input(msg);
	hasher.result(res);
}