#![feature(test)]
#![feature(vec_resize_default)]
//pub mod setup;
pub mod zkpok;
pub mod mpecdsa_error;
pub mod rot;
pub mod ote;
pub mod mpecdsa;

use std::io::prelude::*;
use std::io;

extern crate rand;
extern crate curves;
extern crate time;
extern crate byteorder;
extern crate bit_reverse;
extern crate rayon;
extern crate test;

extern crate crypto;
use crypto::sha2::Sha256;
use crypto::digest::Digest;


/* The hash size is essentially a security parameter.
   Note that the hash algorithm must be changed with
   the output size, so that they match. Note also that
   the hash block size must be somewhat larger than
   the hash output size, or things will break. This
   should be done more intelligently in the future.
   */

const HASH_SIZE: usize = 32;
const HASH_BLOCK_SIZE: usize = 64;
const ENCODING_SEC_PARAM: usize = 160;
const OT_SEC_PARAM: usize = 128 + 80;

extern { 
	//fn sha256_octa_52b(input: *const u8, output: *mut u8);
	fn sha256_multi_52b(input: *const u8, output: *mut u8, count: usize); 
}

/*fn sha256_octa(src: &[u8], dst: &mut [u8]) {
	unsafe {
		sha256_octa_52b(src.as_ptr(), dst.as_mut_ptr());
	}
}*/

fn sha256_multi(src: &[u8], dst: &mut [u8], count: usize) {
	unsafe {
		sha256_multi_52b(src.as_ptr(), dst.as_mut_ptr(), count);
	}
}

fn hash(res: &mut [u8; HASH_SIZE], msg: &[u8]) {
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