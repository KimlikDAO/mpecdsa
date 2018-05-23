use std::io::{BufWriter};
use std::result::{Result};
//use std::sync::atomic::{AtomicUsize,Ordering};

use rand::{Rng};

use curves::{Ford, SecpOrd, precomp};

use byteorder::{ByteOrder, LittleEndian};

use bit_reverse::ParallelReverse;

//use time::{PreciseTime,Duration};

use super::mpecdsa_error::*;
use super::rot::*;
use super::*;

/* Notes:
   OT Extensions and transmissions are numbered by a parameter instead of a counter in the object
   so that we can reuse the extension object in multiple threads and still ensure deterministic
   numbering
   */

// move diagonals
// 11-12-13-14-15-16-17-18 21-22-23-24-25-26-27-28 31-32-33-34-35-36-37-38 41-42-43-44-45-46-47-48 51-52-53-54-55-56-57-58 
// 11                         22                         33                         44                         55
//                         12                         23                         34
// ... to get      
// 11-21-31-41-51-61-71-81 12-22-32-42-52-62-72-82 13-23-33-43-53-63-73-83
fn transpose8x8(w: u64) -> u64 {
	((w & 0x8040201008040201)      )|   
	((w & 0x4020100804020100) >> 7 )|
	((w & 0x2010080402010000) >> 14)|
	((w & 0x1008040201000000) >> 21)|
	((w & 0x0804020100000000) >> 28)|
	((w & 0x0402010000000000) >> 35)|
	((w & 0x0201000000000000) >> 42)|
	((w & 0x0100000000000000) >> 49)|
	((w & 0x0080402010080402) << 7 )|
	((w & 0x0000804020100804) << 14)|
	((w & 0x0000008040201008) << 21)|
	((w & 0x0000000080402010) << 28)|
	((w & 0x0000000000804020) << 35)|
	((w & 0x0000000000008040) << 42)|
	((w & 0x0000000000000080) << 49)
}

//assumes rows and columns are both multiples of 8
fn transpose(data: &Vec<u8>, majtilelen: usize) -> Vec<u8> {
	let minlen = data.len()/majtilelen;
	let mintilelen = minlen/8;
	let mut result: Vec<u8> = Vec::with_capacity(data.len());
	result.resize_default(data.len()); //fill with 0
	for jj in 0..mintilelen {
		for ii in 0..majtilelen {
			let chunk:u64 = ((data[(jj * 8 + 0) * majtilelen + ii] as u64) << 56)
						  | ((data[(jj * 8 + 1) * majtilelen + ii] as u64) << 48)
						  | ((data[(jj * 8 + 2) * majtilelen + ii] as u64) << 40)
						  | ((data[(jj * 8 + 3) * majtilelen + ii] as u64) << 32)
						  | ((data[(jj * 8 + 4) * majtilelen + ii] as u64) << 24)
						  | ((data[(jj * 8 + 5) * majtilelen + ii] as u64) << 16)
						  | ((data[(jj * 8 + 6) * majtilelen + ii] as u64) << 8)
						  | ((data[(jj * 8 + 7) * majtilelen + ii] as u64) << 0);
			let transchunk: u64 = transpose8x8(chunk).swap_bits();
			result[(ii * 8 + 0) * mintilelen + jj] = ((transchunk >> 56) & 0xFF) as u8;
			result[(ii * 8 + 1) * mintilelen + jj] = ((transchunk >> 48) & 0xFF) as u8;
			result[(ii * 8 + 2) * mintilelen + jj] = ((transchunk >> 40) & 0xFF) as u8;
			result[(ii * 8 + 3) * mintilelen + jj] = ((transchunk >> 32) & 0xFF) as u8;
			result[(ii * 8 + 4) * mintilelen + jj] = ((transchunk >> 24) & 0xFF) as u8;
			result[(ii * 8 + 5) * mintilelen + jj] = ((transchunk >> 16) & 0xFF) as u8;
			result[(ii * 8 + 6) * mintilelen + jj] = ((transchunk >> 8) & 0xFF) as u8;
			result[(ii * 8 + 7) * mintilelen + jj] = ((transchunk >> 0) & 0xFF) as u8;
		}
	}
	result
}

#[derive(Clone)]
pub struct OTESender {
	publicrandomvec: [SecpOrd;SecpOrd::NBITS+ENCODING_SEC_PARAM],
	correlation: [bool; SecpOrd::NBITS],
	compressed_correlation: [u8; SecpOrd::NBYTES],
	seeds: Vec<[u8;HASH_SIZE]>,
	//extindex: AtomicUsize,
	//transindex: AtomicUsize
}

#[derive(Clone)]
pub struct OTERecver {
	publicrandomvec: [SecpOrd;SecpOrd::NBITS+ENCODING_SEC_PARAM],
	seeds: Vec<([u8;HASH_SIZE],[u8;HASH_SIZE])>,
	//extindex: AtomicUsize,
	//transindex: AtomicUsize
}

#[derive(Clone)]
pub enum OTEPlayer {
	Sender(OTESender),
	Recver(OTERecver),
	Null
}

impl OTESender {
	pub fn new<T1:Read, T2:Write>(rng: &mut Rng, recv:&mut T1, send: &mut T2) -> Result<OTESender,MPECDSAError> {
		let mut correlation = [false;SecpOrd::NBITS];
		for ii in 0..SecpOrd::NBITS {
			correlation[ii] = (rng.next_u32() % 2)>0;
		}

		let mut compressed_correlation = [0u8; SecpOrd::NBYTES];
		for ii in 0..SecpOrd::NBYTES {
			compressed_correlation[ii] = ((correlation[ii*8+0] as u8) << 0)
										|((correlation[ii*8+1] as u8) << 1)
										|((correlation[ii*8+2] as u8) << 2)
										|((correlation[ii*8+3] as u8) << 3)
										|((correlation[ii*8+4] as u8) << 4)
										|((correlation[ii*8+5] as u8) << 5)
										|((correlation[ii*8+6] as u8) << 6)
										|((correlation[ii*8+7] as u8) << 7);
		}

		let mut publicrandomvec = [SecpOrd::ZERO;ENCODING_SEC_PARAM+SecpOrd::NBITS];
		let mut raw_nonce = [0u8;SecpOrd::NBYTES];
		try!(recv.read_exact(&mut raw_nonce));
		let mut nonce = SecpOrd::from_bytes(&raw_nonce);
		let mut prv_element = [0u8;SecpOrd::NBYTES];
		for ii in 0..(ENCODING_SEC_PARAM+SecpOrd::NBITS) {
			nonce = nonce.add(&SecpOrd::ONE);
			nonce.to_bytes(&mut raw_nonce);
			hash(&mut prv_element, &raw_nonce);
			publicrandomvec[ii] = SecpOrd::from_bytes(&prv_element);
		}

		let seeds = try!(rot_recv_batch(&correlation, rng, recv, send));

		Ok(OTESender {
			publicrandomvec: publicrandomvec,
			correlation: correlation,
			compressed_correlation,
			seeds: seeds
		})
	}

	pub fn mul_extend<T:Read>(&self, extindex: usize, input_count: usize, recv:&mut T) -> Result<(Vec<[u8;HASH_SIZE*2*SecpOrd::NBITS]>,[u8;ENCODING_SEC_PARAM*HASH_SIZE]),MPECDSAError> {
		//let extindex = self.extindex.fetch_add(1, Ordering::Relaxed);
		let prgoutputlen = input_count*2*SecpOrd::NBITS + ENCODING_SEC_PARAM + OT_SEC_PARAM;
		let mut expanded_seeds: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
		let prgiterations = ((prgoutputlen/8) + HASH_SIZE - 1) / HASH_SIZE;

		debug_assert!((SecpOrd::NBYTES * prgoutputlen)%HASH_SIZE ==0);

		//let t1 = PreciseTime::now();

		let mut prgoutput = vec![0u8; HASH_SIZE*prgiterations*SecpOrd::NBITS];
		let mut hasherinput = vec![0u8; HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS];
		for ii in 0..SecpOrd::NBITS {
			for jj in 0..prgiterations {
				LittleEndian::write_u64(&mut hasherinput[((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE)..((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 8)], extindex as u64);
				LittleEndian::write_u64(&mut hasherinput[((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 8)..((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 16)], (jj*SecpOrd::NBITS + ii) as u64);
				hasherinput[((ii*prgiterations+jj) * HASH_BLOCK_SIZE)..((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE)].copy_from_slice(&self.seeds[ii]);
			}
		}

		sha256_multi(&hasherinput, &mut prgoutput, SecpOrd::NBITS*prgiterations);

		for ii in 0..SecpOrd::NBITS {
			expanded_seeds.extend_from_slice(&prgoutput[(ii*prgiterations*HASH_SIZE)..(ii*prgiterations*HASH_SIZE+prgoutputlen/8)]);
		}

		//let t2 = PreciseTime::now();
		//println!("Seed Expansion: {} microseconds", t1.to(t2).num_microseconds().unwrap());

		let mut seeds_combined: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
		seeds_combined.resize_default(SecpOrd::NBYTES * prgoutputlen);
		let mut sampled_bits = [0u8; SecpOrd::NBYTES];
		let mut sampled_seeds = [0u8; SecpOrd::NBYTES];
		try!(recv.read_exact(&mut seeds_combined));
		try!(recv.read_exact(&mut sampled_bits));
		try!(recv.read_exact(&mut sampled_seeds));

		//let t3 = PreciseTime::now();
		//println!("Read: {} microseconds", t2.to(t3).num_microseconds().unwrap());

		let mut random_samples = vec![0u8; HASH_SIZE * prgoutputlen];
		let mut seeds_shortened = [0u8;HASH_SIZE];
		let mut hash_input = vec![0u8;HASH_BLOCK_SIZE*prgoutputlen];
		hash(&mut seeds_shortened, &seeds_combined);
		for ii in 0..prgoutputlen {
			hash_input[(ii*HASH_BLOCK_SIZE)..(ii*HASH_BLOCK_SIZE+HASH_SIZE)].copy_from_slice(&seeds_shortened);
			LittleEndian::write_u64(&mut hash_input[(ii*HASH_BLOCK_SIZE+HASH_SIZE)..(ii*HASH_BLOCK_SIZE+HASH_SIZE+8)], ii as u64);
		}
		sha256_multi(&hash_input, &mut random_samples, prgoutputlen);

		//let t4 = PreciseTime::now();
		//println!("Sampling: {} microseconds", t3.to(t4).num_microseconds().unwrap());

		let mut check_vec: Vec<u8> = Vec::with_capacity(SecpOrd::NBITS * prgoutputlen/8);
		for ii in 0..SecpOrd::NBITS {
			for jj in 0..(prgoutputlen/8) {
				check_vec.push(expanded_seeds[ii * (prgoutputlen/8) + jj] ^ ((self.correlation[ii] as u8) * seeds_combined[ii * (prgoutputlen/8) + jj]));
			}
		}

		let transposed_check_vec = transpose(&check_vec, prgoutputlen/8);

		//let t5 = PreciseTime::now();
		//println!("Seed Expansion: {} microseconds", t4.to(t5).num_microseconds().unwrap());

		let mut sampled_check = [0u8; SecpOrd::NBYTES];
		for ii in 0..prgoutputlen {
			for jj in 0..SecpOrd::NBYTES {
				sampled_check[jj] ^= transposed_check_vec[ii * SecpOrd::NBYTES + jj] & random_samples[ii * SecpOrd::NBYTES + jj];
			}
		}

		let mut rhs = [0u8; SecpOrd::NBYTES];
		for ii in 0..SecpOrd::NBYTES {
			rhs[ii] = sampled_seeds[ii] ^ (self.compressed_correlation[ii] & sampled_bits[ii]);
		}

		//let t6 = PreciseTime::now();
		//println!("Verification: {} microseconds", t5.to(t6).num_microseconds().unwrap());

		//finally, collate the output
		let mut transposed_seed_fragments:Vec<[u8;HASH_SIZE * 2 * SecpOrd::NBITS]> = Vec::with_capacity(input_count);
		for ii in 0..input_count {
			let mut fragment = [0u8;2*SecpOrd::NBITS*HASH_SIZE];
			fragment.copy_from_slice(&transposed_check_vec[(ii * 2*SecpOrd::NBITS*HASH_SIZE)..((ii+1) * 2*SecpOrd::NBITS*HASH_SIZE)]);
			transposed_seed_fragments.push(fragment);
		}
		let mut transposed_seed_encoding_fragment = [0u8;ENCODING_SEC_PARAM*HASH_SIZE];
		transposed_seed_encoding_fragment.copy_from_slice(&transposed_check_vec[(input_count * 2*SecpOrd::NBITS*HASH_SIZE)..(input_count * 2*SecpOrd::NBITS * HASH_SIZE + ENCODING_SEC_PARAM * HASH_SIZE)]);

		if vec_eq(&sampled_check, &rhs) {
			Ok((transposed_seed_fragments,transposed_seed_encoding_fragment))
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Verification Failed for OTE (receiver cheated)")))
		}
	}

	pub fn  mul_transfer<T:Write>(&self, transindex: usize, input_alpha: &SecpOrd, transposed_seed_fragment: &[u8;2*SecpOrd::NBITS*HASH_SIZE], transposed_seed_encoding_fragment: &[u8;ENCODING_SEC_PARAM*HASH_SIZE], rng:&mut Rng, send: &mut T) -> Result<SecpOrd,MPECDSAError> {
		//let transindex = self.transindex.fetch_add(1, Ordering::Relaxed);

		let gadget_table = match SecpOrd::NBITS {
			256 => &precomp::GADGET_TABLE_256,
			_ => { return Err(MPECDSAError::General); }
		};


		let mut transposed_seed = [0u8;(2*SecpOrd::NBITS + ENCODING_SEC_PARAM)*HASH_SIZE];
		transposed_seed[0..(2*SecpOrd::NBITS*HASH_SIZE)].copy_from_slice(transposed_seed_fragment);
		transposed_seed[(2*SecpOrd::NBITS * HASH_SIZE)..].copy_from_slice(transposed_seed_encoding_fragment);

		let mut hasherinput = [0u8; 2*HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM)];
		let mut hashoutput = [0u8; 2*HASH_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM)];
		let mut vals0 = [SecpOrd::ZERO; 2*SecpOrd::NBITS + ENCODING_SEC_PARAM];
		let mut check_hashoutput = [0u8; 2*HASH_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM)];
		let mut check_vals0 = [SecpOrd::ZERO; 2*SecpOrd::NBITS + ENCODING_SEC_PARAM];
		let mut result = SecpOrd::ZERO;
		let check_alpha = SecpOrd::rand(rng);

		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			LittleEndian::write_u64(&mut hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)], (2*transindex) as u64);
			LittleEndian::write_u64(&mut hasherinput[(HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + HASH_SIZE)..(HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)], (2*transindex) as u64);
			LittleEndian::write_u64(&mut hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 16)], ii as u64);
			LittleEndian::write_u64(&mut hasherinput[(HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)..(HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + HASH_SIZE + 16)], ii as u64);
			hasherinput[(ii * HASH_BLOCK_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE)].copy_from_slice(&transposed_seed[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]);
			hasherinput[(HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE)..(HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + HASH_SIZE)].copy_from_slice(&transposed_seed[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]);
			for jj in 0..HASH_SIZE {
				hasherinput[HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + jj] ^= self.compressed_correlation[jj];	
			}
		}

		sha256_multi(&hasherinput, &mut hashoutput, 2*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM));

		let mut correction_vec_raw = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * SecpOrd::NBYTES];
		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			// primary value
			vals0[ii] = SecpOrd::from_bytes(&hashoutput[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]);
			let offset = if ii < SecpOrd::NBITS {
				&gadget_table[SecpOrd::NBITS - (ii/8)*8 -8 + (ii%8)]
			} else {
				&self.publicrandomvec[(ii/8)*8-SecpOrd::NBITS+ii%8]
			};
			result = result.add(&vals0[ii].mul(offset));
			let val1 = SecpOrd::from_bytes(&hashoutput[(HASH_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii*HASH_SIZE)..(HASH_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + (ii+1)*HASH_SIZE)]);
			val1.sub(&vals0[ii]).add(&input_alpha).to_bytes(&mut correction_vec_raw[(ii*SecpOrd::NBYTES)..((ii+1)*SecpOrd::NBYTES)]);
		}
		try!(send.write(&correction_vec_raw));

		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			let mut temp = [0u8;8];
			temp.copy_from_slice(&hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)]);
			LittleEndian::write_u64(&mut hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)], (2*transindex+1) as u64);
			for jj in 0..8 {
				hasherinput[HASH_BLOCK_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii * HASH_BLOCK_SIZE + HASH_SIZE + jj] ^= temp[jj] ^ hasherinput[ii * HASH_BLOCK_SIZE + HASH_SIZE + jj];
			}
		}

		sha256_multi(&hasherinput, &mut check_hashoutput, 2*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM));

		let mut check_correction_vec_raw = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * SecpOrd::NBYTES];
		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			// check value
			check_vals0[ii] = SecpOrd::from_bytes(&check_hashoutput[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]);
			let check_val1 = SecpOrd::from_bytes(&check_hashoutput[(HASH_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + ii*HASH_SIZE)..(HASH_SIZE*(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) + (ii+1)*HASH_SIZE)]);
			check_val1.sub(&check_vals0[ii]).add(&check_alpha).to_bytes(&mut check_correction_vec_raw[(ii*SecpOrd::NBYTES)..((ii+1)*SecpOrd::NBYTES)]);
		}
		try!(send.write(&check_correction_vec_raw));

		let mut coef = [0u8;HASH_SIZE];
		let mut check_coef = [0u8;HASH_SIZE];
		hash(&mut coef, &correction_vec_raw);
		hash(&mut check_coef, &check_correction_vec_raw);
		let coef = SecpOrd::from_bytes(&coef);
		let check_coef = SecpOrd::from_bytes(&check_coef);
			
		let mut check_vec_raw = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * SecpOrd::NBYTES];
		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			vals0[ii].mul(&coef).add(&check_vals0[ii].mul(&check_coef)).to_bytes(&mut check_vec_raw[(ii*SecpOrd::NBYTES)..((ii+1)*SecpOrd::NBYTES)]);
		}
		try!(send.write(&check_vec_raw));

		let reference = input_alpha.mul(&coef).add(&check_alpha.mul(&check_coef));
		let mut reference_raw = [0u8;SecpOrd::NBYTES];
		reference.to_bytes(&mut reference_raw);
		try!(send.write(&reference_raw));
		Ok(result)
	}
}

impl OTERecver {
	pub fn new<T1:Read, T2:Write>(rng: &mut Rng, recv:&mut T1, send: &mut T2) -> Result<OTERecver,MPECDSAError> {
		//ROT sender goes first, so we let the OTExt recver choose the public random vector to reduce rounds.
		let mut publicrandomvec = [SecpOrd::ZERO;ENCODING_SEC_PARAM+SecpOrd::NBITS];
		let mut raw_nonce = [0u8;SecpOrd::NBYTES];
		let mut prv_element = [0u8;SecpOrd::NBYTES];
		let mut nonce = SecpOrd::rand(rng);
		nonce.to_bytes(&mut raw_nonce);
		try!(send.write(&raw_nonce));
		for ii in 0..ENCODING_SEC_PARAM+SecpOrd::NBITS {
			nonce = nonce.add(&SecpOrd::ONE);
			nonce.to_bytes(&mut raw_nonce);
			hash(&mut prv_element, &raw_nonce);
			publicrandomvec[ii] = SecpOrd::from_bytes(&prv_element);
		}

		Ok(OTERecver {
			publicrandomvec: publicrandomvec,
			seeds: try!(rot_send_batch(SecpOrd::NBITS, rng, recv, send)),
			//extindex: AtomicUsize::new(0),
			//transindex: AtomicUsize::new(0)
		})
	}

	pub fn mul_encode_and_extend<T:Write>(&self, extindex: usize, inputs_beta: &[SecpOrd], rng: &mut Rng, send: &mut T) 
										 -> Result<(Vec<[bool;2*SecpOrd::NBITS]>,[bool;ENCODING_SEC_PARAM],Vec<[u8;2*SecpOrd::NBITS*HASH_SIZE]>,[u8;ENCODING_SEC_PARAM*HASH_SIZE]),MPECDSAError> {
		debug_assert!(SecpOrd::NBYTES == HASH_SIZE);

		// Encode phase
		let mut encoding_private_bits = [false; ENCODING_SEC_PARAM];
		let mut encoding_private_offset = SecpOrd::ZERO;
		for ii in 0..ENCODING_SEC_PARAM {
			encoding_private_bits[ii] = (rng.next_u32() % 2) > 0;
			let potential_offset = encoding_private_offset.add(&self.publicrandomvec[SecpOrd::NBITS+ii]);
			if encoding_private_bits[ii] {
				encoding_private_offset = potential_offset;
			}
		}

		let mut encoding_private_element_bits = vec![[false; SecpOrd::NBITS]; inputs_beta.len()];
		let mut encoding_private_element_offsets = vec![SecpOrd::ZERO; inputs_beta.len()];
		for jj in 0..inputs_beta.len() {
			for ii in 0..SecpOrd::NBITS {
				encoding_private_element_bits[jj][ii] = (rng.next_u32() % 2) > 0;
				let potential_offset = encoding_private_element_offsets[jj].add(&self.publicrandomvec[ii]);
				if encoding_private_element_bits[jj][ii] {
					encoding_private_element_offsets[jj] = potential_offset;
				}
			}
		}

		let mut inputs_encoded: Vec<[bool;2*SecpOrd::NBITS]> = Vec::with_capacity(inputs_beta.len());
		let mut choice_bits: Vec<bool> = Vec::with_capacity(inputs_beta.len()*2*SecpOrd::NBITS + ENCODING_SEC_PARAM + OT_SEC_PARAM);
		for ii in 0..inputs_beta.len() {
			inputs_encoded.push([false;2*SecpOrd::NBITS]);
			let beta_aug = inputs_beta[ii].sub(&encoding_private_offset).sub(&encoding_private_element_offsets[ii]);
			for jj in 0..SecpOrd::NBYTES {
				inputs_encoded[ii][jj*8+0] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 0);
				inputs_encoded[ii][jj*8+1] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 1);
				inputs_encoded[ii][jj*8+2] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 2);
				inputs_encoded[ii][jj*8+3] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 3);
				inputs_encoded[ii][jj*8+4] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 4);
				inputs_encoded[ii][jj*8+5] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 5);
				inputs_encoded[ii][jj*8+6] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 6);
				inputs_encoded[ii][jj*8+7] = beta_aug.bit(SecpOrd::NBITS - ((jj+1)*8) + 7);
			}
			inputs_encoded[ii][SecpOrd::NBITS..].copy_from_slice(&encoding_private_element_bits[ii]);
			choice_bits.extend_from_slice(&inputs_encoded[ii]);
		}
		choice_bits.extend_from_slice(&encoding_private_bits);

		for _ in 0..OT_SEC_PARAM {
			choice_bits.push((rng.next_u32() % 2) > 0);
		}

		let mut compressed_choice_bits: Vec<u8> = Vec::with_capacity(choice_bits.len()/8);
		for ii in 0..(choice_bits.len()/8) {
			compressed_choice_bits.push(((choice_bits[ii*8+0] as u8) << 0)
									   |((choice_bits[ii*8+1] as u8) << 1)
									   |((choice_bits[ii*8+2] as u8) << 2)
									   |((choice_bits[ii*8+3] as u8) << 3)
									   |((choice_bits[ii*8+4] as u8) << 4)
									   |((choice_bits[ii*8+5] as u8) << 5)
									   |((choice_bits[ii*8+6] as u8) << 6)
									   |((choice_bits[ii*8+7] as u8) << 7));
		}

		// Extend phase
		//let extindex = self.extindex.fetch_add(1, Ordering::Relaxed);
		let prgoutputlen = inputs_beta.len()*2*SecpOrd::NBITS + ENCODING_SEC_PARAM + OT_SEC_PARAM;
		let mut expanded_seeds0: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
		let mut expanded_seeds1: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
		let prgiterations = ((prgoutputlen/8) + HASH_SIZE - 1) / HASH_SIZE;

		debug_assert!((SecpOrd::NBYTES * prgoutputlen)%HASH_SIZE ==0);

		let mut prgoutput = vec![0u8; 2*HASH_SIZE*prgiterations*SecpOrd::NBITS];
		let mut hasherinput = vec![0u8; 2*HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS];
		for ii in 0..SecpOrd::NBITS {
			for jj in 0..prgiterations {
				LittleEndian::write_u64(&mut hasherinput[((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE)..((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 8)], extindex as u64);
				LittleEndian::write_u64(&mut hasherinput[((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 8)..((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 16)], (jj*SecpOrd::NBITS + ii) as u64);
				LittleEndian::write_u64(&mut hasherinput[(HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS + (ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE)..(HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS + (ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 8)], extindex as u64);
				LittleEndian::write_u64(&mut hasherinput[(HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS + (ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 8)..(HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS + (ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE + 16)], (jj*SecpOrd::NBITS + ii) as u64);
				hasherinput[((ii*prgiterations+jj) * HASH_BLOCK_SIZE)..((ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE)].copy_from_slice(&self.seeds[ii].0);
				hasherinput[(HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS + (ii*prgiterations+jj) * HASH_BLOCK_SIZE)..(HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS + (ii*prgiterations+jj) * HASH_BLOCK_SIZE + HASH_SIZE)].copy_from_slice(&self.seeds[ii].1);
			}
		}

		sha256_multi(&hasherinput, &mut prgoutput, 2*SecpOrd::NBITS*prgiterations);

		for ii in 0..SecpOrd::NBITS {
			expanded_seeds0.extend_from_slice(&prgoutput[(ii*prgiterations*HASH_SIZE)..(ii*prgiterations*HASH_SIZE+prgoutputlen/8)]);
			expanded_seeds1.extend_from_slice(&prgoutput[(HASH_SIZE*prgiterations*SecpOrd::NBITS + ii*prgiterations*HASH_SIZE)..(HASH_SIZE*prgiterations*SecpOrd::NBITS + ii*prgiterations*HASH_SIZE+prgoutputlen/8)]);
		}

		let transposed_seed0 = transpose(&expanded_seeds0, prgoutputlen/8);

		debug_assert!(expanded_seeds0.len()/compressed_choice_bits.len() == SecpOrd::NBITS);

		let mut seeds_combined: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
		for ii in 0..expanded_seeds0.len() {
			seeds_combined.push(expanded_seeds0[ii] ^ expanded_seeds1[ii] ^ compressed_choice_bits[ii%compressed_choice_bits.len()]);
		}

		let mut random_samples = vec![0u8; HASH_SIZE * prgoutputlen];
		let mut seeds_shortened = [0u8;HASH_SIZE];
		let mut hash_input = vec![0u8;HASH_BLOCK_SIZE*prgoutputlen];
		hash(&mut seeds_shortened, &seeds_combined);
		for ii in 0..prgoutputlen {
			hash_input[(ii*HASH_BLOCK_SIZE)..(ii*HASH_BLOCK_SIZE+HASH_SIZE)].copy_from_slice(&seeds_shortened);
			LittleEndian::write_u64(&mut hash_input[(ii*HASH_BLOCK_SIZE+HASH_SIZE)..(ii*HASH_BLOCK_SIZE+HASH_SIZE+8)], ii as u64);
		}
		sha256_multi(&hash_input, &mut random_samples, prgoutputlen);

		debug_assert!(expanded_seeds0.len() == transposed_seed0.len());
		debug_assert!(transposed_seed0.len() == random_samples.len());

		let mut sampled_bits = [0u8; SecpOrd::NBYTES];
		let mut sampled_seeds = [0u8; SecpOrd::NBYTES];
		for ii in 0..prgoutputlen {
			if choice_bits[ii] {
				for jj in 0..SecpOrd::NBYTES {
					sampled_bits[jj] ^= random_samples[ii * SecpOrd::NBYTES + jj];
				}
			}
			for jj in 0..SecpOrd::NBYTES {
				sampled_seeds[jj] ^= transposed_seed0[ii * SecpOrd::NBYTES + jj] & random_samples[ii * SecpOrd::NBYTES + jj];
			}
		}

		let mut bufsend = BufWriter::new(send);
		try!(bufsend.write(&seeds_combined));
		try!(bufsend.write(&sampled_bits));
		try!(bufsend.write(&sampled_seeds));

		//finally, collate the output
		let mut transposed_seed_fragments:Vec<[u8;2*SecpOrd::NBITS*HASH_SIZE]> = Vec::with_capacity(inputs_beta.len());
		for ii in 0..inputs_beta.len() {
			let mut fragment = [0u8;2*SecpOrd::NBITS * HASH_SIZE];
			fragment.copy_from_slice(&transposed_seed0[(ii * 2*SecpOrd::NBITS * HASH_SIZE)..((ii+1) * 2*SecpOrd::NBITS * HASH_SIZE)]);
			transposed_seed_fragments.push(fragment);
		}
		let mut transposed_seed_encoding_fragment = [0u8;ENCODING_SEC_PARAM * HASH_SIZE];
		transposed_seed_encoding_fragment.copy_from_slice(&transposed_seed0[(inputs_beta.len() * 2*SecpOrd::NBITS * HASH_SIZE)..(inputs_beta.len() * 2*SecpOrd::NBITS * HASH_SIZE + ENCODING_SEC_PARAM * HASH_SIZE)]);

		Ok((inputs_encoded,
			encoding_private_bits,
			transposed_seed_fragments,
			transposed_seed_encoding_fragment))
	}

	pub fn  mul_transfer<T:Read>(&self, transindex: usize, input_beta_encoded: &[bool;2*SecpOrd::NBITS], encoding_private_bits: &[bool;ENCODING_SEC_PARAM], transposed_seed_fragment: &[u8;2*SecpOrd::NBITS*HASH_SIZE], transposed_seed_encoding_fragment: &[u8;ENCODING_SEC_PARAM*HASH_SIZE], recv: &mut T) -> Result<SecpOrd,MPECDSAError> {
		//let transindex = self.transindex.fetch_add(1, Ordering::Relaxed);

		let gadget_table = match SecpOrd::NBITS {
			256 => &precomp::GADGET_TABLE_256,
			_ => { return Err(MPECDSAError::General); }
		};

		let mut transposed_seed = [0u8;(2*SecpOrd::NBITS+ENCODING_SEC_PARAM)*HASH_SIZE];
		transposed_seed[0..(HASH_SIZE*2*SecpOrd::NBITS)].copy_from_slice(transposed_seed_fragment);
		transposed_seed[(HASH_SIZE*2*SecpOrd::NBITS)..(2*SecpOrd::NBITS+ENCODING_SEC_PARAM)*HASH_SIZE].copy_from_slice(transposed_seed_encoding_fragment);
		let mut choice_bits = [false;2*SecpOrd::NBITS + ENCODING_SEC_PARAM];
		choice_bits[0..2*SecpOrd::NBITS].copy_from_slice(input_beta_encoded);
		choice_bits[2*SecpOrd::NBITS..2*SecpOrd::NBITS + ENCODING_SEC_PARAM].copy_from_slice(encoding_private_bits);

		let mut hasherinput = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * HASH_BLOCK_SIZE];
		let mut hashoutput = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * HASH_SIZE];
		let mut check_hashoutput = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * HASH_SIZE];
		
		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			LittleEndian::write_u64(&mut hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)], (2*transindex) as u64);
			LittleEndian::write_u64(&mut hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 16)], ii as u64);
			hasherinput[(ii * HASH_BLOCK_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE)].copy_from_slice(&transposed_seed[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]);
		}

		sha256_multi(&hasherinput, &mut hashoutput, 2*SecpOrd::NBITS + ENCODING_SEC_PARAM);

		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			LittleEndian::write_u64(&mut hasherinput[(ii * HASH_BLOCK_SIZE + HASH_SIZE)..(ii * HASH_BLOCK_SIZE + HASH_SIZE + 8)], (2*transindex+1) as u64);
		}

		sha256_multi(&hasherinput, &mut check_hashoutput, 2*SecpOrd::NBITS + ENCODING_SEC_PARAM);

		let mut correction_vec_raw = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM)*SecpOrd::NBYTES];
		try!(recv.read_exact(&mut correction_vec_raw));
		let mut coef = [0u8;HASH_SIZE];
		hash(&mut coef, &correction_vec_raw);
		let coef = SecpOrd::from_bytes(&coef);
		let mut vals = [SecpOrd::ZERO; 2*SecpOrd::NBITS + ENCODING_SEC_PARAM];
		let mut result = SecpOrd::ZERO;
		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			let cv = SecpOrd::from_bytes(&correction_vec_raw[(ii*SecpOrd::NBYTES)..((ii+1)*SecpOrd::NBYTES)]);
			let val = SecpOrd::from_bytes(&hashoutput[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]).neg();
			let val_aug = val.add(&cv);
			vals[ii] = if choice_bits[ii] {
				val_aug
			} else {
				val
			};

			let offset = if ii < SecpOrd::NBITS {
				&gadget_table[SecpOrd::NBITS - (ii/8)*8 -8 + (ii%8)]
			} else {
				&self.publicrandomvec[(ii/8)*8-SecpOrd::NBITS+ii%8]
			};
			result = result.add(&vals[ii].mul(offset));
		}

		let mut check_correction_vec_raw = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM)*SecpOrd::NBYTES];
		try!(recv.read_exact(&mut check_correction_vec_raw));
		let mut check_coef = [0u8;HASH_SIZE];
		hash(&mut check_coef, &check_correction_vec_raw);
		let check_coef = SecpOrd::from_bytes(&check_coef);
		let mut check_vals = [SecpOrd::ZERO; 2*SecpOrd::NBITS + ENCODING_SEC_PARAM];
		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			let ccv = SecpOrd::from_bytes(&check_correction_vec_raw[(ii*SecpOrd::NBYTES)..((ii+1)*SecpOrd::NBYTES)]);
			let check_val = SecpOrd::from_bytes(&check_hashoutput[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)]).neg();
			let check_val_aug = check_val.add(&ccv);
			check_vals[ii] = if choice_bits[ii] {
				check_val_aug
			} else {
				check_val
			};
		}
			
		let mut check_vec_raw = [0u8; (2*SecpOrd::NBITS + ENCODING_SEC_PARAM) * SecpOrd::NBYTES];
		try!(recv.read_exact(&mut check_vec_raw));
		let mut reference_raw = [0u8;SecpOrd::NBYTES];
		try!(recv.read_exact(&mut reference_raw));
		let reference = SecpOrd::from_bytes(&reference_raw);

		for ii in 0..(2*SecpOrd::NBITS + ENCODING_SEC_PARAM) {
			let check_vec = SecpOrd::from_bytes(&check_vec_raw[(ii*SecpOrd::NBYTES)..((ii+1)*SecpOrd::NBYTES)]).neg();
			let check_vec_aug = check_vec.add(&reference);
			let check_vec_chosen = if choice_bits[ii] {
				check_vec_aug
			} else {
				check_vec
			};

			if vals[ii].mul(&coef).add(&check_vals[ii].mul(&check_coef)) != check_vec_chosen {
				return Err(MPECDSAError::Proof(ProofError::new("Verification Failed for OT-Mul (sender cheated)")))
			}
		}
		Ok(result)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{thread, time};
	use std::net::{TcpListener, TcpStream};
	use test::Bencher;

	#[test]
	fn test_transpose8x8() {

		let a = 0b0111101000011101000100010111010000001010000000010010111111111111;
		let at= 0b0000000110010001100100111111000111001011010100111000101101100111;
		let b = transpose8x8(a);
		assert!(b==at);

		let a = 0b1111001111001000110101111000000100111110000101011001110000011100;
		let at= 0b1111001011100000100010001010111101001011001011111010100010110100;
		let b = transpose8x8(a);
		assert!(b==at);
	}

	#[test]
	fn test_transpose() {
		let mut a: Vec<u8> = Vec::with_capacity(16);
		a.resize_default(16);
		let mut at: Vec<u8> = Vec::with_capacity(16);
		at.resize_default(16);
		LittleEndian::write_u64(&mut a[0..8], 0b0111101001111010000111010001110100010001000100010111010001110100);
		LittleEndian::write_u64(&mut a[8..16], 0b0000101000001010000000010000000100101111001011111111111111111111);

		LittleEndian::write_u64(&mut at[0..8], 0b0000100010011000100111001111100000111101101011000001110101101110u64.swap_bits().swap_bytes());
		LittleEndian::write_u64(&mut at[8..16], 0b0000100010011000100111001111100000111101101011000001110101101110u64.swap_bits().swap_bytes());
		
		let b = transpose(&a, 2);
		assert!(b == at);
	}

	#[test]
	fn test_ote_setup_net() {
		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4569").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			sender
		});

		thread::sleep(time::Duration::from_millis(50));

		let mut rng = rand::thread_rng();
		let mut streamrecv = TcpStream::connect("127.0.0.1:4569").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();

		let sender = child.join().unwrap();
		for ii in 0..recver.publicrandomvec.len() {
			assert_eq!(recver.publicrandomvec[ii], sender.publicrandomvec[ii]);
		}
		for ii in 0..sender.correlation.len() {
			assert_eq!(sender.seeds[ii], if sender.correlation[ii] {
				recver.seeds[ii].1
			} else {
				recver.seeds[ii].0
			});
		}
	}

	#[test]
	fn test_ote_mul_extend_net() {
		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4570").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			sender.mul_extend(0, 2, &mut streamrecv)
		});

		thread::sleep(time::Duration::from_millis(50));

		let mut rng = rand::thread_rng();
		let mut streamrecv = TcpStream::connect("127.0.0.1:4570").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
		let mut beta:Vec<SecpOrd> = Vec::with_capacity(2);
		for _ in 0..2 {
			beta.push(SecpOrd::rand(&mut rng));
		}
		let recver_result = recver.mul_encode_and_extend(0, &beta, &mut rng, &mut streamsend);
		assert!(recver_result.is_ok());
		let recver_result = recver_result.unwrap();

		let mut encoding_offset = SecpOrd::ZERO;
		for ii in 0..ENCODING_SEC_PARAM {
			if recver_result.1[ii] {
				encoding_offset = encoding_offset.add(&recver.publicrandomvec[SecpOrd::NBITS+ii]);
			}
		}

		for ii in 0..recver_result.0.len() {
			let el_bits = recver_result.0[ii];
			let mut compressed_temp = [0u8; SecpOrd::NBYTES];
			for jj in 0..SecpOrd::NBYTES {
				compressed_temp[jj] = ((el_bits[jj*8+0] as u8) << 0)
									| ((el_bits[jj*8+1] as u8) << 1)
									| ((el_bits[jj*8+2] as u8) << 2)
									| ((el_bits[jj*8+3] as u8) << 3)
									| ((el_bits[jj*8+4] as u8) << 4)
									| ((el_bits[jj*8+5] as u8) << 5)
									| ((el_bits[jj*8+6] as u8) << 6)
									| ((el_bits[jj*8+7] as u8) << 7);
			}
			let mut beta_temp = SecpOrd::from_bytes(&compressed_temp);
			for jj in SecpOrd::NBITS..2*SecpOrd::NBITS {
				if recver_result.0[ii][jj] {
					beta_temp = beta_temp.add(&recver.publicrandomvec[jj-SecpOrd::NBITS]);
				}
			}
			assert!(beta_temp.add(&encoding_offset)  == beta[ii]);
		}

		assert!(child.join().unwrap().is_ok());
	}

	#[test]
	fn test_ote_mul_net() {
		let mut rng = rand::thread_rng();
		let mut alpha:Vec<SecpOrd> = Vec::with_capacity(10);
		let mut alpha_child:Vec<SecpOrd> = Vec::with_capacity(10);
		for ii in 0..10 {
			alpha.push(SecpOrd::rand(&mut rng));
			alpha_child.push(alpha[ii].clone());
		}

		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4572").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			let extensions = sender.mul_extend(0, 10, &mut streamrecv).unwrap();
			let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
			for ii in 0..10 {
				results.push(sender.mul_transfer(ii, &alpha_child[ii], &extensions.0[ii], &extensions.1, &mut rng, &mut streamsend).unwrap());
			}
			results
		});

		thread::sleep(time::Duration::from_millis(50));
		let mut streamrecv = TcpStream::connect("127.0.0.1:4572").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
		let mut beta:Vec<SecpOrd> = Vec::with_capacity(10);
		for _ in 0..10 {
			beta.push(SecpOrd::rand(&mut rng));
		}

		let extensions = recver.mul_encode_and_extend(0, &beta, &mut rng, &mut streamsend).unwrap();
		let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
		for ii in 0..10 {
			results.push(recver.mul_transfer(ii, &extensions.0[ii], &extensions.1, &extensions.2[ii], &extensions.3, &mut streamrecv).unwrap());
		}

		let childresult: Vec<SecpOrd> = child.join().unwrap();
		for ii in 0..10 {
			assert_eq!(results[ii].add(&childresult[ii]), beta[ii].mul(&alpha[ii]));
		}
	}

	#[test]
	fn test_ote_multimul_net() {
		let mut rng = rand::thread_rng();
		let mut alpha:Vec<SecpOrd> = Vec::with_capacity(10);
		let mut alpha_child:Vec<SecpOrd> = Vec::with_capacity(10);
		for ii in 0..10 {
			alpha.push(SecpOrd::rand(&mut rng));
			alpha_child.push(alpha[ii].clone());
		}

		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4574").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			let extensions = sender.mul_extend(0, 1, &mut streamrecv).unwrap();
			let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
			for ii in 0..10 {
				results.push(sender.mul_transfer(ii, &alpha_child[ii], &extensions.0[0], &extensions.1, &mut rng, &mut streamsend).unwrap());
			}
			results
		});

		thread::sleep(time::Duration::from_millis(50));
		let mut streamrecv = TcpStream::connect("127.0.0.1:4574").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
		let mut beta:Vec<SecpOrd> = Vec::with_capacity(1);
		beta.push(SecpOrd::rand(&mut rng));

		let extensions = recver.mul_encode_and_extend(0, &beta, &mut rng, &mut streamsend).unwrap();
		let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
		for ii in 0..10 {
			results.push(recver.mul_transfer(ii, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, &mut streamrecv).unwrap());
		}

		let childresult: Vec<SecpOrd> = child.join().unwrap();
		for ii in 0..10 {
			assert_eq!(results[ii].add(&childresult[ii]), beta[0].mul(&alpha[ii]));
		}
	}

	#[bench]
	fn bench_ote_mul_extend_net(b: &mut Bencher) -> () {
		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4571").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			let mut keepgoing = [1u8; 1];
			streamrecv.read_exact(&mut keepgoing).unwrap();
			let mut ii:usize = 0;
			while keepgoing[0] > 0 {
				sender.mul_extend(ii, 2, &mut streamrecv).unwrap();
				streamrecv.read_exact(&mut keepgoing).unwrap();
				ii+=1;
			}
		});

		thread::sleep(time::Duration::from_millis(50));

		let mut rng = rand::thread_rng();
		let mut streamrecv = TcpStream::connect("127.0.0.1:4571").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
		let mut beta:Vec<SecpOrd> = Vec::with_capacity(2);
		for _ in 0..2 {
			beta.push(SecpOrd::rand(&mut rng));
		}

		let mut ii:usize = 0;
		b.iter(|| { 
			streamsend.write(&[1]).unwrap();
			streamsend.flush().unwrap();
			recver.mul_encode_and_extend(ii, &beta, &mut rng, &mut streamsend).unwrap();
			ii+=1;
		});

		streamsend.write(&[0]).unwrap();
		streamsend.flush().unwrap();
		child.join().unwrap();
	}

	#[bench]
	fn bench_ote_mul_2_and_2(b: &mut Bencher) -> () {
		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4573").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			let mut keepgoing = [1u8; 1];

			let mut alpha:Vec<SecpOrd> = Vec::with_capacity(2);
			for _ in 0..2 {
				alpha.push(SecpOrd::rand(&mut rng));
			}

			streamrecv.read_exact(&mut keepgoing).unwrap();
			let mut ii:usize = 0;
			while keepgoing[0] > 0 {
				let extensions = sender.mul_extend(ii, 2, &mut streamrecv).unwrap();
				sender.mul_transfer(ii*3+0, &alpha[0], &extensions.0[0], &extensions.1, &mut rng, &mut streamsend).unwrap();
				sender.mul_transfer(ii*3+1, &alpha[1], &extensions.0[0], &extensions.1, &mut rng, &mut streamsend).unwrap();
				streamsend.flush().unwrap();
				streamrecv.read_exact(&mut keepgoing).unwrap();
				ii += 1;
			}
		});

		thread::sleep(time::Duration::from_millis(50));

		let mut rng = rand::thread_rng();
		let mut streamrecv = TcpStream::connect("127.0.0.1:4573").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
		let mut beta:Vec<SecpOrd> = Vec::with_capacity(2);
		for _ in 0..2 {
			beta.push(SecpOrd::rand(&mut rng));
		}

		let mut ii:usize = 0;
		b.iter(|| { 
			streamsend.write(&[1]).unwrap();
			streamsend.flush().unwrap();
			let extensions = recver.mul_encode_and_extend(ii, &beta, &mut rng, &mut streamsend).unwrap();
			recver.mul_transfer(ii*3+0, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, &mut streamrecv).unwrap();
			recver.mul_transfer(ii*3+1, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, &mut streamrecv).unwrap();
			ii += 1;
		});

		streamsend.write(&[0]).unwrap();
		streamsend.flush().unwrap();
		child.join().unwrap();
	}

	#[bench]
	fn bench_ote_mul_2_and_3(b: &mut Bencher) -> () {
		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4583").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let sender = OTESender::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
			let mut keepgoing = [1u8; 1];

			let mut alpha:Vec<SecpOrd> = Vec::with_capacity(3);
			for _ in 0..3 {
				alpha.push(SecpOrd::rand(&mut rng));
			}

			streamrecv.read_exact(&mut keepgoing).unwrap();
			let mut ii:usize = 0;
			while keepgoing[0] > 0 {
				let extensions = sender.mul_extend(ii, 2, &mut streamrecv).unwrap();
				sender.mul_transfer(ii*3+0, &alpha[0], &extensions.0[0], &extensions.1, &mut rng, &mut streamsend).unwrap();
				sender.mul_transfer(ii*3+1, &alpha[1], &extensions.0[0], &extensions.1, &mut rng, &mut streamsend).unwrap();
				sender.mul_transfer(ii*3+2, &alpha[2], &extensions.0[1], &extensions.1, &mut rng, &mut streamsend).unwrap();
				streamsend.flush().unwrap();
				streamrecv.read_exact(&mut keepgoing).unwrap();
				ii += 1;
			}
		});

		thread::sleep(time::Duration::from_millis(50));

		let mut rng = rand::thread_rng();
		let mut streamrecv = TcpStream::connect("127.0.0.1:4583").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();

		let recver = OTERecver::new(&mut rng, &mut streamrecv, &mut streamsend).unwrap();
		let mut beta:Vec<SecpOrd> = Vec::with_capacity(2);
		for _ in 0..2 {
			beta.push(SecpOrd::rand(&mut rng));
		}

		let mut ii:usize = 0;
		b.iter(|| { 
			streamsend.write(&[1]).unwrap();
			streamsend.flush().unwrap();
			let extensions = recver.mul_encode_and_extend(ii, &beta, &mut rng, &mut streamsend).unwrap();
			recver.mul_transfer(ii*3+0, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, &mut streamrecv).unwrap();
			recver.mul_transfer(ii*3+1, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, &mut streamrecv).unwrap();
			recver.mul_transfer(ii*3+2, &extensions.0[1], &extensions.1, &extensions.2[1], &extensions.3, &mut streamrecv).unwrap();
			ii += 1;
		});

		streamsend.write(&[0]).unwrap();
		streamsend.flush().unwrap();
		child.join().unwrap();
	}
}