/***********
 * This module implements the KOS Oblivious Transfer Extension Protocol,
 * as described in the paper "Actively Secure OT Extension with Optimal Overhead"
 * by Keller, Orsini, and Scholl (https://eprint.iacr.org/2015/546)
 *
 * Base OTs for this protocol are provided by the VSOT protocol in rot.rs
 ***********/

use std::cmp::min;
use std::io::BufWriter;
use std::result::Result;

use rand::Rng;

use curves::{Ford, SecpOrd};

use bit_reverse::ParallelReverse;

use super::mpecdsa_error::*;
use super::ro::*;
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
    (w & 0x8040201008040201)
        | ((w & 0x4020100804020100) >> 7)
        | ((w & 0x2010080402010000) >> 14)
        | ((w & 0x1008040201000000) >> 21)
        | ((w & 0x0804020100000000) >> 28)
        | ((w & 0x0402010000000000) >> 35)
        | ((w & 0x0201000000000000) >> 42)
        | ((w & 0x0100000000000000) >> 49)
        | ((w & 0x0080402010080402) << 7)
        | ((w & 0x0000804020100804) << 14)
        | ((w & 0x0000008040201008) << 21)
        | ((w & 0x0000000080402010) << 28)
        | ((w & 0x0000000000804020) << 35)
        | ((w & 0x0000000000008040) << 42)
        | ((w & 0x0000000000000080) << 49)
}

//assumes rows and columns are both multiples of 8
fn transpose(data: &Vec<u8>, majtilelen: usize) -> Vec<u8> {
    let minlen = data.len() / majtilelen;
    let mintilelen = minlen / 8;
    let mut result: Vec<u8> = vec![0u8; data.len()];
    for jj in 0..mintilelen {
        for ii in 0..majtilelen {
            let chunk: u64 = ((data[(jj * 8 + 0) * majtilelen + ii] as u64) << 56)
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

//#[derive(Clone)]
pub struct OTESender {
    correlation: [bool; SecpOrd::NBITS],
    compressed_correlation: [u8; SecpOrd::NBYTES],
    seeds: Vec<[u8; HASH_SIZE]>,
}

//#[derive(Clone)]
pub struct OTERecver {
    seeds: Vec<([u8; HASH_SIZE], [u8; HASH_SIZE])>,
}

//#[derive(Clone)]
pub enum OTEPlayer {
    Sender(OTESender),
    Recver(OTERecver),
    Null,
}

impl OTESender {
    pub fn new<T1: Read, T2: Write>(
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        recv: &mut T1,
        send: &mut T2,
    ) -> Result<OTESender, MPECDSAError> {
        let mut correlation = [false; SecpOrd::NBITS];
        for ii in 0..SecpOrd::NBITS {
            correlation[ii] = (rng.next_u32() % 2) > 0;
        }

        let mut compressed_correlation = [0u8; SecpOrd::NBYTES];
        for ii in 0..SecpOrd::NBYTES {
            compressed_correlation[ii] = ((correlation[ii * 8 + 0] as u8) << 0)
                | ((correlation[ii * 8 + 1] as u8) << 1)
                | ((correlation[ii * 8 + 2] as u8) << 2)
                | ((correlation[ii * 8 + 3] as u8) << 3)
                | ((correlation[ii * 8 + 4] as u8) << 4)
                | ((correlation[ii * 8 + 5] as u8) << 5)
                | ((correlation[ii * 8 + 6] as u8) << 6)
                | ((correlation[ii * 8 + 7] as u8) << 7);
        }

        let seeds = rot_recv_batch(&correlation, &ro, rng, recv, send)?;

        Ok(OTESender {
            correlation: correlation,
            compressed_correlation,
            seeds: seeds,
        })
    }

    pub fn apply_refresh(&mut self, rand: &[u8], ro: &DyadicROTagger) -> Result<(), MPECDSAError> {
        if rand.len() < HASH_SIZE {
            return Err(MPECDSAError::General(GeneralError::new(
                "Insufficiently many random bits for safe refresh",
            )));
        }
        let mut expanded_rand = vec![0u8; 2 * HASH_SIZE * SecpOrd::NBITS + SecpOrd::NBITS / 8];
        let mut source_with_tag = vec![0u8; rand.len() + RO_TAG_SIZE];
        let mut hashout = [0u8; HASH_SIZE];
        source_with_tag[RO_TAG_SIZE..].copy_from_slice(&rand[..]);
        for ii in 0..((expanded_rand.len() + HASH_SIZE - 1) / HASH_SIZE) {
            let offset = ii * HASH_SIZE;
            let remain = min(expanded_rand.len() - offset, HASH_SIZE);
            source_with_tag[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag()[..]);
            hash(&mut hashout, &source_with_tag);
            expanded_rand[offset..(offset + remain)].copy_from_slice(&hashout[0..remain]);
        }

        for ii in 0..SecpOrd::NBITS {
            self.correlation[ii] ^=
                ((expanded_rand[2 * HASH_SIZE * SecpOrd::NBITS + ii / 8] >> (ii % 8)) & 1) > 0;
            for jj in 0..HASH_SIZE {
                self.seeds[ii][jj] ^=
                    expanded_rand[((self.correlation[ii] as usize) * HASH_SIZE * SecpOrd::NBITS)
                        + ii * HASH_SIZE
                        + jj];
            }
        }
        for ii in 0..SecpOrd::NBYTES {
            self.compressed_correlation[ii] ^= expanded_rand[2 * HASH_SIZE * SecpOrd::NBITS + ii];
        }
        return Ok(());
    }

    pub fn extend<T: Read>(
        &self,
        input_len: usize,
        ro: &DyadicROTagger,
        recv: &mut T,
    ) -> Result<Vec<u8>, MPECDSAError> {
        let prgoutputlen = input_len + OT_SEC_PARAM;
        let mut expanded_seeds: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
        let prgiterations = ((prgoutputlen / 8) + HASH_SIZE - 1) / HASH_SIZE;

        debug_assert!((SecpOrd::NBYTES * prgoutputlen) % HASH_SIZE == 0);

        let mut tagrange =
            ro.allocate_dyadic_range((SecpOrd::NBITS * prgiterations + prgoutputlen + 1) as u64);

        let mut prgoutput = vec![0u8; HASH_SIZE * prgiterations * SecpOrd::NBITS];
        let mut hasherinput = vec![0u8; HASH_BLOCK_SIZE * prgiterations * SecpOrd::NBITS];
        for ii in 0..SecpOrd::NBITS {
            for jj in 0..prgiterations {
                // Map for (ii,jj): [ 20B: RO index | 32B: seed[ii] ], total: 52B
                hasherinput[((ii * prgiterations + jj) * HASH_BLOCK_SIZE)
                    ..((ii * prgiterations + jj) * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tagrange.next()?[..]);
                hasherinput[((ii * prgiterations + jj) * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                    ..((ii * prgiterations + jj) * HASH_BLOCK_SIZE + RO_TAG_SIZE + HASH_SIZE)]
                    .copy_from_slice(&self.seeds[ii]);
            }
        }

        hash_multi(&hasherinput, &mut prgoutput, SecpOrd::NBITS * prgiterations);

        for ii in 0..SecpOrd::NBITS {
            expanded_seeds.extend_from_slice(
                &prgoutput[(ii * prgiterations * HASH_SIZE)
                    ..(ii * prgiterations * HASH_SIZE + prgoutputlen / 8)],
            );
        }

        let mut seeds_combined = vec![0u8; SecpOrd::NBYTES * prgoutputlen + RO_TAG_SIZE];
        let mut sampled_bits = [0u8; SecpOrd::NBYTES];
        let mut sampled_seeds = [0u8; SecpOrd::NBYTES];
        recv.read_exact(&mut seeds_combined[0..SecpOrd::NBYTES * prgoutputlen])?;
        recv.read_exact(&mut sampled_bits)?;
        recv.read_exact(&mut sampled_seeds)?;

        let mut random_samples = vec![0u8; HASH_SIZE * prgoutputlen];
        let mut seeds_shortened = [0u8; HASH_SIZE];
        let mut hash_input = vec![0u8; HASH_BLOCK_SIZE * prgoutputlen];
        seeds_combined[(SecpOrd::NBYTES * prgoutputlen)..].copy_from_slice(&tagrange.next()?[..]);
        hash(&mut seeds_shortened, &seeds_combined);
        for ii in 0..prgoutputlen {
            // Map for ii: [ 20B: RO tag | 32B: seeds_shortened ], total: 52B
            hash_input[(ii * HASH_BLOCK_SIZE)..(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                .copy_from_slice(&tagrange.next()?[..]);
            hash_input[(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                ..(ii * HASH_BLOCK_SIZE + HASH_SIZE + RO_TAG_SIZE)]
                .copy_from_slice(&seeds_shortened);
        }
        hash_multi(&hash_input, &mut random_samples, prgoutputlen);

        let mut check_vec: Vec<u8> = Vec::with_capacity(SecpOrd::NBITS * prgoutputlen / 8);
        for ii in 0..SecpOrd::NBITS {
            for jj in 0..(prgoutputlen / 8) {
                check_vec.push(
                    expanded_seeds[ii * (prgoutputlen / 8) + jj]
                        ^ ((self.correlation[ii] as u8)
                            * seeds_combined[ii * (prgoutputlen / 8) + jj]),
                );
            }
        }

        let transposed_check_vec = transpose(&check_vec, prgoutputlen / 8);

        let mut sampled_check = [0u8; SecpOrd::NBYTES];
        for ii in 0..prgoutputlen {
            for jj in 0..SecpOrd::NBYTES {
                sampled_check[jj] ^= transposed_check_vec[ii * SecpOrd::NBYTES + jj]
                    & random_samples[ii * SecpOrd::NBYTES + jj];
            }
        }

        let mut rhs = [0u8; SecpOrd::NBYTES];
        for ii in 0..SecpOrd::NBYTES {
            rhs[ii] = sampled_seeds[ii] ^ (self.compressed_correlation[ii] & sampled_bits[ii]);
        }

        if vec_eq(&sampled_check, &rhs) {
            Ok(transposed_check_vec)
        } else {
            Err(MPECDSAError::Proof(ProofError::new(
                "Verification Failed for OTE (receiver cheated)",
            )))
        }
    }

    pub fn transfer<T: Write>(
        &self,
        input_len: &[usize],
        input_correlation: &[&SecpOrd],
        transposed_seed: &[&[u8]],
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        send: &mut T,
    ) -> Result<Vec<Vec<SecpOrd>>, MPECDSAError> {
        let input_count: usize = input_len.len();
        let total_input_len: usize = input_len.iter().sum();
        let mut tagrange =
            ro.allocate_dyadic_range((2 * total_input_len + 2 * input_count + 2) as u64);

        let mut hasherinput = vec![0u8; 2 * HASH_BLOCK_SIZE * total_input_len];
        let mut hashoutput = vec![0u8; 2 * HASH_SIZE * total_input_len];
        let mut vals0: Vec<Vec<SecpOrd>> = Vec::with_capacity(input_count);
        let mut check_hashoutput = vec![0u8; 2 * HASH_SIZE * total_input_len];
        let mut check_vals0: Vec<Vec<SecpOrd>> = Vec::with_capacity(input_count);
        let mut check_alpha = vec![SecpOrd::ZERO; input_count];

        let mut input_len_offset = 0;
        for kk in 0..input_count {
            check_alpha[kk] = SecpOrd::rand(rng);
            let localhasherinput = &mut hasherinput[(input_len_offset * HASH_BLOCK_SIZE)
                ..((input_len_offset + 2 * input_len[kk]) * HASH_BLOCK_SIZE)];

            for ii in 0..input_len[kk] {
                // Map for ii: [ 20B: RO tag | 32B: transposed_seed[ii] ], total: 52B
                // Map for ii + 1: [  20B: RO tag | 32B: transposed_seed[ii]^compressed_correlation[jj] ], total: 52B
                let tag = tagrange.next()?;
                localhasherinput
                    [(2 * ii * HASH_BLOCK_SIZE)..(2 * ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tag[..]);
                localhasherinput[(2 * ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                    ..(2 * ii * HASH_BLOCK_SIZE + RO_TAG_SIZE + HASH_SIZE)]
                    .copy_from_slice(
                        &transposed_seed[kk][(ii * HASH_SIZE)..((ii + 1) * HASH_SIZE)],
                    );
                localhasherinput[((2 * ii + 1) * HASH_BLOCK_SIZE)
                    ..((2 * ii + 1) * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tag[..]);
                localhasherinput[((2 * ii + 1) * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                    ..((2 * ii + 1) * HASH_BLOCK_SIZE + RO_TAG_SIZE + HASH_SIZE)]
                    .copy_from_slice(
                        &transposed_seed[kk][(ii * HASH_SIZE)..((ii + 1) * HASH_SIZE)],
                    );
                for jj in 0..HASH_SIZE {
                    localhasherinput[(2 * ii + 1) * HASH_BLOCK_SIZE + RO_TAG_SIZE + jj] ^=
                        self.compressed_correlation[jj];
                }
            }

            input_len_offset = input_len_offset + 2 * input_len[kk];
        }

        hash_multi(&hasherinput, &mut hashoutput, 2 * total_input_len);

        let mut correction_vec_raw = vec![0u8; total_input_len * SecpOrd::NBYTES + RO_TAG_SIZE];
        let mut vals0_offset = 0;
        for kk in 0..input_count {
            let mut localvals0 = vec![SecpOrd::ZERO; input_len[kk]];
            let localhashoutput = &hashoutput
                [(2 * vals0_offset * HASH_SIZE)..(2 * (vals0_offset + input_len[kk]) * HASH_SIZE)];
            let localcorrectionvec = &mut correction_vec_raw[(vals0_offset * SecpOrd::NBYTES)
                ..((vals0_offset + input_len[kk]) * SecpOrd::NBYTES)];
            for ii in 0..input_len[kk] {
                // primary value; with space at the end for the RO tag (this is more convenient than putting it at the start)
                localvals0[ii] = SecpOrd::from_bytes(
                    &localhashoutput[(2 * ii * HASH_SIZE)..((2 * ii + 1) * HASH_SIZE)],
                );
                let val1 = SecpOrd::from_bytes(
                    &localhashoutput[((2 * ii + 1) * HASH_SIZE)..((2 * ii + 2) * HASH_SIZE)],
                );
                val1.sub(&localvals0[ii])
                    .add(input_correlation[kk])
                    .to_bytes(
                        &mut localcorrectionvec
                            [(ii * SecpOrd::NBYTES)..((ii + 1) * SecpOrd::NBYTES)],
                    );
            }
            vals0.push(localvals0);
            vals0_offset = vals0_offset + input_len[kk];
        }
        send.write(&correction_vec_raw[0..total_input_len * SecpOrd::NBYTES])?;

        input_len_offset = 0;
        for kk in 0..input_count {
            let localhasherinput = &mut hasherinput[(input_len_offset * HASH_BLOCK_SIZE)
                ..((input_len_offset + 2 * input_len[kk]) * HASH_BLOCK_SIZE)];
            for ii in 0..input_len[kk] {
                // Map for ii: [ 20B: RO tag | 32B: transposed_seed[ii] ], total: 52B
                // Map for input_len + ii: [ 20B: RO tag | 32B: transposed_seed[ii]^compressed_correlation[jj] ], total: 52B
                let tag = tagrange.next()?;
                localhasherinput
                    [(2 * ii * HASH_BLOCK_SIZE)..(2 * ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tag[..]);
                localhasherinput[((2 * ii + 1) * HASH_BLOCK_SIZE)
                    ..((2 * ii + 1) * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tag[..]);
            }
            input_len_offset = input_len_offset + 2 * input_len[kk];
        }

        hash_multi(&hasherinput, &mut check_hashoutput, 2 * total_input_len);

        let mut check_correction_vec_raw =
            vec![0u8; total_input_len * SecpOrd::NBYTES + RO_TAG_SIZE];
        vals0_offset = 0;
        for kk in 0..input_count {
            let mut localcheckvals0 = vec![SecpOrd::ZERO; input_len[kk]];
            let localcheckhashoutput = &check_hashoutput
                [(2 * vals0_offset * HASH_SIZE)..(2 * (vals0_offset + input_len[kk]) * HASH_SIZE)];
            let localcheckcorrectionvec = &mut check_correction_vec_raw[(vals0_offset
                * SecpOrd::NBYTES)
                ..((vals0_offset + input_len[kk]) * SecpOrd::NBYTES)];
            for ii in 0..input_len[kk] {
                // check value; with space at the end for the RO tag (this is more convenient than putting it at the start)
                localcheckvals0[ii] = SecpOrd::from_bytes(
                    &localcheckhashoutput[(2 * ii * HASH_SIZE)..((2 * ii + 1) * HASH_SIZE)],
                );
                let check_val1 = SecpOrd::from_bytes(
                    &localcheckhashoutput[((2 * ii + 1) * HASH_SIZE)..((2 * ii + 2) * HASH_SIZE)],
                );
                check_val1
                    .sub(&localcheckvals0[ii])
                    .add(&check_alpha[kk])
                    .to_bytes(
                        &mut localcheckcorrectionvec
                            [(ii * SecpOrd::NBYTES)..((ii + 1) * SecpOrd::NBYTES)],
                    );
            }
            check_vals0.push(localcheckvals0);
            vals0_offset = vals0_offset + input_len[kk];
        }
        send.write(&check_correction_vec_raw[0..total_input_len * SecpOrd::NBYTES])?;

        let mut coef_seed = [0u8; HASH_SIZE + RO_TAG_SIZE];
        let mut coef_raw = [0u8; HASH_SIZE];
        let mut coefs = vec![SecpOrd::ZERO; input_count];
        correction_vec_raw[total_input_len * SecpOrd::NBYTES..]
            .copy_from_slice(&tagrange.next()?[..]);
        hash(&mut coef_raw, &correction_vec_raw);
        coef_seed[0..HASH_SIZE].copy_from_slice(&coef_raw);

        for kk in 0..input_count {
            coef_seed[HASH_SIZE..].copy_from_slice(&tagrange.next()?[..]);
            hash(&mut coef_raw, &coef_seed);
            coefs[kk] = SecpOrd::from_bytes(&coef_raw);
        }

        let mut check_coef_seed = [0u8; HASH_SIZE + RO_TAG_SIZE];
        let mut check_coef_raw = [0u8; HASH_SIZE];
        let mut check_coefs = vec![SecpOrd::ZERO; input_count];
        check_correction_vec_raw[total_input_len * SecpOrd::NBYTES..]
            .copy_from_slice(&tagrange.next()?[..]);
        hash(&mut check_coef_raw, &check_correction_vec_raw);
        check_coef_seed[0..HASH_SIZE].copy_from_slice(&check_coef_raw);

        for kk in 0..input_count {
            check_coef_seed[HASH_SIZE..].copy_from_slice(&tagrange.next()?[..]);
            hash(&mut check_coef_raw, &check_coef_seed);
            check_coefs[kk] = SecpOrd::from_bytes(&check_coef_raw);
        }

        let mut check_vec = vec![SecpOrd::ZERO; *input_len.iter().max().unwrap()];
        for kk in 0..input_count {
            for ii in 0..input_len[kk] {
                check_vec[ii] = check_vec[ii].add(
                    &vals0[kk][ii]
                        .mul(&coefs[kk])
                        .add(&check_vals0[kk][ii].mul(&check_coefs[kk])),
                );
            }
        }

        let mut check_vec_raw = vec![0u8; input_len.iter().max().unwrap() * SecpOrd::NBYTES];
        for ii in 0..*input_len.iter().max().unwrap() {
            check_vec[ii]
                .to_bytes(&mut check_vec_raw[(ii * SecpOrd::NBYTES)..((ii + 1) * SecpOrd::NBYTES)]);
        }
        send.write(&check_vec_raw)?;

        let mut references_raw = vec![0u8; input_count * SecpOrd::NBYTES];
        for kk in 0..input_count {
            let reference = input_correlation[kk]
                .mul(&coefs[kk])
                .add(&check_alpha[kk].mul(&check_coefs[kk]));
            reference.to_bytes(
                &mut references_raw[(kk * SecpOrd::NBYTES)..((kk + 1) * SecpOrd::NBYTES)],
            );
        }
        send.write(&references_raw)?;

        Ok(vals0)
    }
}

impl OTERecver {
    pub fn new<T1: Read, T2: Write>(
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        recv: &mut T1,
        send: &mut T2,
    ) -> Result<OTERecver, MPECDSAError> {
        let seeds = rot_send_batch(SecpOrd::NBITS, &ro, rng, recv, send)?;
        Ok(OTERecver { seeds: seeds })
    }

    pub fn apply_refresh(&mut self, rand: &[u8], ro: &DyadicROTagger) -> Result<(), MPECDSAError> {
        if rand.len() < HASH_SIZE {
            return Err(MPECDSAError::General(GeneralError::new(
                "Insufficiently many random bits for safe refresh",
            )));
        }
        let mut expanded_rand = vec![0u8; 2 * HASH_SIZE * SecpOrd::NBITS + SecpOrd::NBITS / 8];
        let mut source_with_tag = vec![0u8; rand.len() + RO_TAG_SIZE];
        let mut hashout = [0u8; HASH_SIZE];
        source_with_tag[RO_TAG_SIZE..].copy_from_slice(&rand[..]);
        for ii in 0..((expanded_rand.len() + HASH_SIZE - 1) / HASH_SIZE) {
            let offset = ii * HASH_SIZE;
            let remain = min(expanded_rand.len() - offset, HASH_SIZE);
            source_with_tag[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag()[..]);
            hash(&mut hashout, &source_with_tag);
            expanded_rand[offset..(offset + remain)].copy_from_slice(&hashout[0..remain]);
        }

        for ii in 0..SecpOrd::NBITS {
            let correlation_modifier =
                (expanded_rand[2 * HASH_SIZE * SecpOrd::NBITS + ii / 8] >> (ii % 8)) & 1;
            let (seedb, seedinvb) = if correlation_modifier == 1 {
                (self.seeds[ii].1, self.seeds[ii].0)
            } else {
                (self.seeds[ii].0, self.seeds[ii].1)
            };
            for jj in 0..HASH_SIZE {
                expanded_rand[ii * HASH_SIZE + jj] ^= seedb[jj];
                expanded_rand[HASH_SIZE * SecpOrd::NBITS + ii * HASH_SIZE + jj] ^= seedinvb[jj];
            }
        }

        for ii in 0..SecpOrd::NBITS {
            self.seeds[ii].0[..]
                .copy_from_slice(&expanded_rand[ii * HASH_SIZE..(ii + 1) * HASH_SIZE]);
            self.seeds[ii].1[..].copy_from_slice(
                &expanded_rand[HASH_SIZE * SecpOrd::NBITS + ii * HASH_SIZE
                    ..HASH_SIZE * SecpOrd::NBITS + (ii + 1) * HASH_SIZE],
            );
        }
        return Ok(());
    }

    pub fn extend<T: Write>(
        &self,
        choice_bits_in: &[bool],
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        send: &mut T,
    ) -> Result<Vec<u8>, MPECDSAError> {
        let mut choice_bits: Vec<bool> = Vec::with_capacity(choice_bits_in.len() + OT_SEC_PARAM);
        choice_bits.extend_from_slice(&choice_bits_in);

        for _ in 0..OT_SEC_PARAM {
            choice_bits.push((rng.next_u32() % 2) > 0);
        }

        let mut compressed_choice_bits: Vec<u8> = Vec::with_capacity(choice_bits.len() / 8);
        for ii in 0..(choice_bits.len() / 8) {
            compressed_choice_bits.push(
                ((choice_bits[ii * 8 + 0] as u8) << 0)
                    | ((choice_bits[ii * 8 + 1] as u8) << 1)
                    | ((choice_bits[ii * 8 + 2] as u8) << 2)
                    | ((choice_bits[ii * 8 + 3] as u8) << 3)
                    | ((choice_bits[ii * 8 + 4] as u8) << 4)
                    | ((choice_bits[ii * 8 + 5] as u8) << 5)
                    | ((choice_bits[ii * 8 + 6] as u8) << 6)
                    | ((choice_bits[ii * 8 + 7] as u8) << 7),
            );
        }

        // Extend phase
        let prgoutputlen = choice_bits.len();
        let mut expanded_seeds0: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
        let mut expanded_seeds1: Vec<u8> = Vec::with_capacity(SecpOrd::NBYTES * prgoutputlen);
        let prgiterations = ((prgoutputlen / 8) + HASH_SIZE - 1) / HASH_SIZE;

        let mut tagrange =
            ro.allocate_dyadic_range((SecpOrd::NBITS * prgiterations + prgoutputlen + 1) as u64);

        debug_assert!((SecpOrd::NBYTES * prgoutputlen) % HASH_SIZE == 0);

        let mut prgoutput = vec![0u8; 2 * HASH_SIZE * prgiterations * SecpOrd::NBITS];
        let mut hasherinput = vec![0u8; 2 * HASH_BLOCK_SIZE * prgiterations * SecpOrd::NBITS];
        for ii in 0..SecpOrd::NBITS {
            for jj in 0..prgiterations {
                // Map for (ii,jj): [ 20B: RO tag | 32B: seed[ii].0 ], total: 52B
                // Map for (HASH_BLOCK_SIZE*prgiterations*SecpOrd::NBITS+ii,jj): [ 20B RO tag | 32B: seed[ii].1 ], total: 52B
                let tag = tagrange.next()?;
                hasherinput[((ii * prgiterations + jj) * HASH_BLOCK_SIZE)
                    ..((ii * prgiterations + jj) * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tag[..]);
                hasherinput[((ii * prgiterations + jj) * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                    ..((ii * prgiterations + jj) * HASH_BLOCK_SIZE + RO_TAG_SIZE + HASH_SIZE)]
                    .copy_from_slice(&self.seeds[ii].0);
                hasherinput[(HASH_BLOCK_SIZE * prgiterations * SecpOrd::NBITS
                    + (ii * prgiterations + jj) * HASH_BLOCK_SIZE)
                    ..(HASH_BLOCK_SIZE * prgiterations * SecpOrd::NBITS
                        + (ii * prgiterations + jj) * HASH_BLOCK_SIZE
                        + RO_TAG_SIZE)]
                    .copy_from_slice(&tag[..]);
                hasherinput[(HASH_BLOCK_SIZE * prgiterations * SecpOrd::NBITS
                    + (ii * prgiterations + jj) * HASH_BLOCK_SIZE
                    + RO_TAG_SIZE)
                    ..(HASH_BLOCK_SIZE * prgiterations * SecpOrd::NBITS
                        + (ii * prgiterations + jj) * HASH_BLOCK_SIZE
                        + RO_TAG_SIZE
                        + HASH_SIZE)]
                    .copy_from_slice(&self.seeds[ii].1);
            }
        }

        hash_multi(
            &hasherinput,
            &mut prgoutput,
            2 * SecpOrd::NBITS * prgiterations,
        );

        for ii in 0..SecpOrd::NBITS {
            expanded_seeds0.extend_from_slice(
                &prgoutput[(ii * prgiterations * HASH_SIZE)
                    ..(ii * prgiterations * HASH_SIZE + prgoutputlen / 8)],
            );
            expanded_seeds1.extend_from_slice(
                &prgoutput[(HASH_SIZE * prgiterations * SecpOrd::NBITS
                    + ii * prgiterations * HASH_SIZE)
                    ..(HASH_SIZE * prgiterations * SecpOrd::NBITS
                        + ii * prgiterations * HASH_SIZE
                        + prgoutputlen / 8)],
            );
        }

        let transposed_seed0 = transpose(&expanded_seeds0, prgoutputlen / 8);

        debug_assert!(expanded_seeds0.len() / compressed_choice_bits.len() == SecpOrd::NBITS);

        let mut seeds_combined = vec![0u8; SecpOrd::NBYTES * prgoutputlen + RO_TAG_SIZE];
        for ii in 0..expanded_seeds0.len() {
            seeds_combined[ii] = expanded_seeds0[ii]
                ^ expanded_seeds1[ii]
                ^ compressed_choice_bits[ii % compressed_choice_bits.len()];
        }

        let mut random_samples = vec![0u8; HASH_SIZE * prgoutputlen];
        let mut seeds_shortened = [0u8; HASH_SIZE];
        let mut hash_input = vec![0u8; HASH_BLOCK_SIZE * prgoutputlen];
        seeds_combined[(SecpOrd::NBYTES * prgoutputlen)..].copy_from_slice(&tagrange.next()?[..]);
        hash(&mut seeds_shortened, &seeds_combined);
        for ii in 0..prgoutputlen {
            // Map for ii: [ 20B RO tag | 32B: seeds_shortened ], total: 52B
            hash_input[(ii * HASH_BLOCK_SIZE)..(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                .copy_from_slice(&tagrange.next()?[..]);
            hash_input[(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                ..(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE + HASH_SIZE)]
                .copy_from_slice(&seeds_shortened);
        }
        hash_multi(&hash_input, &mut random_samples, prgoutputlen);

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
                sampled_seeds[jj] ^= transposed_seed0[ii * SecpOrd::NBYTES + jj]
                    & random_samples[ii * SecpOrd::NBYTES + jj];
            }
        }

        let mut bufsend = BufWriter::new(send);
        bufsend.write(&seeds_combined[0..SecpOrd::NBYTES * prgoutputlen])?;
        bufsend.write(&sampled_bits)?;
        bufsend.write(&sampled_seeds)?;

        Ok(transposed_seed0)
    }

    pub fn transfer<T: Read>(
        &self,
        choice_bits: &[&[bool]],
        transposed_seed: &[&[u8]],
        ro: &DyadicROTagger,
        recv: &mut T,
    ) -> Result<Vec<Vec<SecpOrd>>, MPECDSAError> {
        let input_count = choice_bits.len();
        let total_input_len = choice_bits.iter().map(|x| x.len()).sum();
        let mut tagrange =
            ro.allocate_dyadic_range((2 * total_input_len + 2 * input_count + 2) as u64);

        let mut hasherinput = vec![0u8; total_input_len * HASH_BLOCK_SIZE];
        let mut hashoutput = vec![0u8; total_input_len * HASH_SIZE];
        let mut check_hashoutput = vec![0u8; total_input_len * HASH_SIZE];

        let mut input_len_offset = 0;
        for kk in 0..input_count {
            let localhasherinput = &mut hasherinput[(input_len_offset * HASH_BLOCK_SIZE)
                ..((input_len_offset + choice_bits[kk].len()) * HASH_BLOCK_SIZE)];

            for ii in 0..choice_bits[kk].len() {
                // Map for ii: [ 20B RO tag | 32B: transposed_seed[ii] ], total: 52B
                localhasherinput[(ii * HASH_BLOCK_SIZE)..(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                    .copy_from_slice(&tagrange.next()?[..]);
                localhasherinput[(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)
                    ..(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE + HASH_SIZE)]
                    .copy_from_slice(
                        &transposed_seed[kk][(ii * HASH_SIZE)..((ii + 1) * HASH_SIZE)],
                    );
            }
            input_len_offset = input_len_offset + choice_bits[kk].len();
        }

        hash_multi(&hasherinput, &mut hashoutput, total_input_len);

        for ii in 0..total_input_len {
            // Map for ii: [ 20B RO tag | 32B: transposed_seed[ii] ], total: 52B
            hasherinput[(ii * HASH_BLOCK_SIZE)..(ii * HASH_BLOCK_SIZE + RO_TAG_SIZE)]
                .copy_from_slice(&tagrange.next()?[..]);
        }

        hash_multi(&hasherinput, &mut check_hashoutput, total_input_len);

        let mut correction_vec_raw = vec![0u8; total_input_len * SecpOrd::NBYTES + RO_TAG_SIZE];
        recv.read_exact(&mut correction_vec_raw[0..total_input_len * SecpOrd::NBYTES])?;
        correction_vec_raw[total_input_len * SecpOrd::NBYTES..]
            .copy_from_slice(&tagrange.next()?[..]);

        let mut coef_seed = [0u8; HASH_SIZE + RO_TAG_SIZE];
        let mut coef_raw = [0u8; HASH_SIZE];
        let mut coefs = vec![SecpOrd::ZERO; input_count];
        hash(&mut coef_raw, &correction_vec_raw);

        coef_seed[0..HASH_SIZE].copy_from_slice(&coef_raw);
        for kk in 0..input_count {
            coef_seed[HASH_SIZE..].copy_from_slice(&tagrange.next()?[..]);
            hash(&mut coef_raw, &coef_seed);
            coefs[kk] = SecpOrd::from_bytes(&coef_raw);
        }

        let mut vals: Vec<Vec<SecpOrd>> = Vec::with_capacity(input_count);
        let mut vals_offset = 0;
        for kk in 0..input_count {
            let mut localvals = vec![SecpOrd::ZERO; choice_bits[kk].len()];
            let localhashoutput = &hashoutput
                [(vals_offset * HASH_SIZE)..((vals_offset + choice_bits[kk].len()) * HASH_SIZE)];
            let localcorrectionvec = &mut correction_vec_raw[(vals_offset * SecpOrd::NBYTES)
                ..((vals_offset + choice_bits[kk].len()) * SecpOrd::NBYTES)];

            for ii in 0..choice_bits[kk].len() {
                let cv = SecpOrd::from_bytes(
                    &localcorrectionvec[(ii * SecpOrd::NBYTES)..((ii + 1) * SecpOrd::NBYTES)],
                );
                let val =
                    SecpOrd::from_bytes(&localhashoutput[(ii * HASH_SIZE)..((ii + 1) * HASH_SIZE)])
                        .neg();
                let val_aug = val.add(&cv);
                localvals[ii] = if choice_bits[kk][ii] { val_aug } else { val };
            }
            vals.push(localvals);
            vals_offset = vals_offset + choice_bits[kk].len();
        }

        let mut check_correction_vec_raw =
            vec![0u8; total_input_len * SecpOrd::NBYTES + RO_TAG_SIZE];
        check_correction_vec_raw[total_input_len * SecpOrd::NBYTES..]
            .copy_from_slice(&tagrange.next()?[..]);
        recv.read_exact(&mut check_correction_vec_raw[0..total_input_len * SecpOrd::NBYTES])?;

        let mut check_coef_seed = [0u8; HASH_SIZE + RO_TAG_SIZE];
        let mut check_coef_raw = [0u8; HASH_SIZE];
        let mut check_coefs = vec![SecpOrd::ZERO; input_count];
        hash(&mut check_coef_raw, &check_correction_vec_raw);
        check_coef_seed[0..HASH_SIZE].copy_from_slice(&check_coef_raw);

        for kk in 0..input_count {
            check_coef_seed[HASH_SIZE..].copy_from_slice(&tagrange.next()?[..]);
            hash(&mut check_coef_raw, &check_coef_seed);
            check_coefs[kk] = SecpOrd::from_bytes(&check_coef_raw);
        }

        let mut check_vals: Vec<Vec<SecpOrd>> = Vec::with_capacity(input_count);
        vals_offset = 0;
        for kk in 0..input_count {
            let mut localcheckvals = vec![SecpOrd::ZERO; choice_bits[kk].len()];
            let localcheckhashoutput = &check_hashoutput
                [(vals_offset * HASH_SIZE)..((vals_offset + choice_bits[kk].len()) * HASH_SIZE)];
            let localcheckcorrectionvec = &mut check_correction_vec_raw[(vals_offset
                * SecpOrd::NBYTES)
                ..((vals_offset + choice_bits[kk].len()) * SecpOrd::NBYTES)];

            for ii in 0..choice_bits[kk].len() {
                let ccv = SecpOrd::from_bytes(
                    &localcheckcorrectionvec[(ii * SecpOrd::NBYTES)..((ii + 1) * SecpOrd::NBYTES)],
                );
                let check_val = SecpOrd::from_bytes(
                    &localcheckhashoutput[(ii * HASH_SIZE)..((ii + 1) * HASH_SIZE)],
                )
                .neg();
                let check_val_aug = check_val.add(&ccv);
                localcheckvals[ii] = if choice_bits[kk][ii] {
                    check_val_aug
                } else {
                    check_val
                };
            }
            check_vals.push(localcheckvals);
            vals_offset = vals_offset + choice_bits[kk].len();
        }

        let mut check_vec_raw =
            vec![0u8; choice_bits.iter().map(|x| x.len()).max().unwrap() * SecpOrd::NBYTES];
        recv.read_exact(&mut check_vec_raw)?;
        let mut references: Vec<SecpOrd> = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut reference_raw = [0u8; SecpOrd::NBYTES];
            recv.read_exact(&mut reference_raw)?;
            references.push(SecpOrd::from_bytes(&reference_raw));
        }

        for ii in 0..choice_bits.iter().map(|x| x.len()).max().unwrap() {
            let mut rhs = SecpOrd::from_bytes(
                &check_vec_raw[(ii * SecpOrd::NBYTES)..((ii + 1) * SecpOrd::NBYTES)],
            )
            .neg();
            let mut lhs = SecpOrd::ZERO;
            for kk in 0..input_count {
                rhs = rhs.add(&if (ii < choice_bits[kk].len()) && (choice_bits[kk][ii]) {
                    references[kk]
                } else {
                    SecpOrd::ZERO
                });

                lhs = lhs.add(&if ii < choice_bits[kk].len() {
                    vals[kk][ii]
                        .mul(&coefs[kk])
                        .add(&check_vals[kk][ii].mul(&check_coefs[kk]))
                } else {
                    SecpOrd::ZERO
                });
            }

            if lhs != rhs {
                return Err(MPECDSAError::Proof(ProofError::new(
                    "Verification Failed for OTE (sender cheated)",
                )));
            }
        }
        Ok(vals)
    }
}

#[cfg(test)]
mod tests {
    use super::channelstream::*;
    use super::*;
    use byteorder::{ByteOrder, LittleEndian};
    use std::thread;

    #[test]
    fn test_transpose8x8() {
        let a = 0b0111101000011101000100010111010000001010000000010010111111111111;
        let at = 0b0000000110010001100100111111000111001011010100111000101101100111;
        let b = transpose8x8(a);
        assert!(b == at);

        let a = 0b1111001111001000110101111000000100111110000101011001110000011100;
        let at = 0b1111001011100000100010001010111101001011001011111010100010110100;
        let b = transpose8x8(a);
        assert!(b == at);
    }

    #[test]
    fn test_transpose() {
        let mut a: Vec<u8> = vec![0u8; 16];
        let mut at: Vec<u8> = vec![0u8; 16];
        LittleEndian::write_u64(
            &mut a[0..8],
            0b0111101001111010000111010001110100010001000100010111010001110100,
        );
        LittleEndian::write_u64(
            &mut a[8..16],
            0b0000101000001010000000010000000100101111001011111111111111111111,
        );

        LittleEndian::write_u64(
            &mut at[0..8],
            0b0000100010011000100111001111100000111101101011000001110101101110u64
                .swap_bits()
                .swap_bytes(),
        );
        LittleEndian::write_u64(
            &mut at[8..16],
            0b0000100010011000100111001111100000111101101011000001110101101110u64
                .swap_bits()
                .swap_bytes(),
        );

        let b = transpose(&a, 2);
        assert!(b == at);
    }

    #[test]
    fn test_ote_setup() {
        let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(2);

        let mut s1 = sendvec.remove(0);
        let mut r1 = recvvec.remove(0);

        let mut s2 = sendvec.remove(0);
        let mut r2 = recvvec.remove(0);

        let child = thread::spawn(move || {
            let mut rng = rand::thread_rng();

            let ro = {
                let mut r1ref = r1
                    .iter_mut()
                    .map(|x| if x.is_some() { x.as_mut() } else { None })
                    .collect::<Vec<Option<&mut _>>>();
                let mut s1ref = s1
                    .iter_mut()
                    .map(|x| if x.is_some() { x.as_mut() } else { None })
                    .collect::<Vec<Option<&mut _>>>();
                GroupROTagger::from_network_unverified(0, &mut rng, &mut r1ref[..], &mut s1ref[..])
                    .unwrap()
            };
            let sender = OTESender::new(
                &ro.get_dyadic_tagger(1).unwrap(),
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            sender
        });

        let mut rng = rand::thread_rng();

        let ro = {
            let mut r2ref = r2
                .iter_mut()
                .map(|x| if x.is_some() { x.as_mut() } else { None })
                .collect::<Vec<Option<&mut _>>>();
            let mut s2ref = s2
                .iter_mut()
                .map(|x| if x.is_some() { x.as_mut() } else { None })
                .collect::<Vec<Option<&mut _>>>();
            GroupROTagger::from_network_unverified(1, &mut rng, &mut r2ref[..], &mut s2ref[..])
                .unwrap()
        };
        let recver = OTERecver::new(
            &ro.get_dyadic_tagger(0).unwrap(),
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();

        let sender = child.join().unwrap();
        assert!(sender.correlation.len() > 0);
        for ii in 0..sender.correlation.len() {
            assert_eq!(
                sender.seeds[ii],
                if sender.correlation[ii] {
                    recver.seeds[ii].1
                } else {
                    recver.seeds[ii].0
                }
            );
        }
    }

    #[test]
    fn test_ote_refresh() {
        let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(2);

        let mut s1 = sendvec.remove(0);
        let mut r1 = recvvec.remove(0);

        let mut s2 = sendvec.remove(0);
        let mut r2 = recvvec.remove(0);

        let child = thread::spawn(move || {
            let mut rng = rand::thread_rng();

            let ro = {
                let mut r1ref = r1
                    .iter_mut()
                    .map(|x| if x.is_some() { x.as_mut() } else { None })
                    .collect::<Vec<Option<&mut _>>>();
                let mut s1ref = s1
                    .iter_mut()
                    .map(|x| if x.is_some() { x.as_mut() } else { None })
                    .collect::<Vec<Option<&mut _>>>();
                GroupROTagger::from_network_unverified(0, &mut rng, &mut r1ref[..], &mut s1ref[..])
                    .unwrap()
            };
            let sender = OTESender::new(
                &ro.get_dyadic_tagger(1).unwrap(),
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            (ro, sender)
        });

        let mut rng = rand::thread_rng();

        let ror = {
            let mut r2ref = r2
                .iter_mut()
                .map(|x| if x.is_some() { x.as_mut() } else { None })
                .collect::<Vec<Option<&mut _>>>();
            let mut s2ref = s2
                .iter_mut()
                .map(|x| if x.is_some() { x.as_mut() } else { None })
                .collect::<Vec<Option<&mut _>>>();
            GroupROTagger::from_network_unverified(1, &mut rng, &mut r2ref[..], &mut s2ref[..])
                .unwrap()
        };
        let mut recver = OTERecver::new(
            &ror.get_dyadic_tagger(0).unwrap(),
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();

        let (ros, mut sender) = child.join().unwrap();

        let mut refreshval = [0u8; HASH_SIZE];
        rng.fill_bytes(&mut refreshval);

        sender
            .apply_refresh(&refreshval[..], &ros.get_dyadic_tagger(1).unwrap())
            .unwrap();
        recver
            .apply_refresh(&refreshval[..], &ror.get_dyadic_tagger(0).unwrap())
            .unwrap();

        rng.fill_bytes(&mut refreshval);

        sender
            .apply_refresh(&refreshval[..], &ros.get_dyadic_tagger(1).unwrap())
            .unwrap();
        recver
            .apply_refresh(&refreshval[..], &ror.get_dyadic_tagger(0).unwrap())
            .unwrap();

        rng.fill_bytes(&mut refreshval);

        sender
            .apply_refresh(&refreshval[..], &ros.get_dyadic_tagger(1).unwrap())
            .unwrap();
        recver
            .apply_refresh(&refreshval[..], &ror.get_dyadic_tagger(0).unwrap())
            .unwrap();

        assert!(sender.correlation.len() > 0);
        for ii in 0..sender.correlation.len() {
            assert_eq!(
                sender.seeds[ii],
                if sender.correlation[ii] {
                    recver.seeds[ii].1
                } else {
                    recver.seeds[ii].0
                }
            );
        }

        rng.fill_bytes(&mut refreshval);
        sender
            .apply_refresh(&refreshval[..], &ros.get_dyadic_tagger(1).unwrap())
            .unwrap();

        rng.fill_bytes(&mut refreshval);
        recver
            .apply_refresh(&refreshval[..], &ror.get_dyadic_tagger(0).unwrap())
            .unwrap();

        for ii in 0..sender.correlation.len() {
            assert_ne!(
                sender.seeds[ii],
                if sender.correlation[ii] {
                    recver.seeds[ii].1
                } else {
                    recver.seeds[ii].0
                }
            );
        }
    }
}
