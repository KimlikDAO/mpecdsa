/***********
 * This module implements the two-party multiplication protocol
 * described in the paper "Secure Two-party Threshold ECDSA from ECDSA Assumptions"
 * by Doerner, Kondi, Lee, and shelat (https://eprint.iacr.org/2018/499)
 *
 * It also implements the two-party random multiplication protocol
 * described in the paper "Threshold ECDSA from ECDSA Assumptions"
 * by Doerner, Kondi, Lee, and shelat
 *
 * Both multipliers rely upon the KOS OT-extension protocol in ote.rs
 ***********/
use super::mpecdsa_error::*;
use super::ote::*;
use super::ro::*;
use super::*;
use curves::{precomp, Ford, SecpOrd};
use rand::Rng;
use std::cmp;
use std::result::Result;

extern crate test;

//#[derive(Clone)]
pub struct MulSender {
    publicrandomvec: Vec<SecpOrd>,
    ote: OTESender,
}

//#[derive(Clone)]
pub struct MulRecver {
    publicrandomvec: Vec<SecpOrd>,
    ote: OTERecver,
}

//#[derive(Clone)]
pub enum MulPlayer {
    Sender(MulSender),
    Recver(MulRecver),
    Null,
}

pub type MulSenderData = (
    Vec<[u8; HASH_SIZE * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)]>,
    [u8; ENCODING_EXTRA_BITS * HASH_SIZE],
);
pub type RmulSenderData = (
    Vec<[u8; HASH_SIZE * RAND_ENCODING_PER_ELEMENT_BITS]>,
    [u8; RAND_ENCODING_EXTRA_BITS * HASH_SIZE],
    Vec<SecpOrd>,
);
pub type MulRecverData = (
    Vec<[bool; SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS]>,
    [bool; ENCODING_EXTRA_BITS],
    Vec<[u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE]>,
    [u8; ENCODING_EXTRA_BITS * HASH_SIZE],
);
pub type RmulRecverData = (
    Vec<[bool; RAND_ENCODING_PER_ELEMENT_BITS]>,
    [bool; RAND_ENCODING_EXTRA_BITS],
    Vec<[u8; RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE]>,
    [u8; RAND_ENCODING_EXTRA_BITS * HASH_SIZE],
    Vec<SecpOrd>,
);

impl MulSender {
    pub fn new<T1: Read, T2: Write>(
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        recv: &mut T1,
        send: &mut T2,
    ) -> Result<MulSender, MPECDSAError> {
        let total_bits = cmp::max(
            SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS,
            RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS,
        );
        let mut publicrandomvec = vec![SecpOrd::ZERO; total_bits];
        let mut raw_nonce = [0u8; SecpOrd::NBYTES];
        recv.read_exact(&mut raw_nonce)?;
        let mut nonce = SecpOrd::from_bytes(&raw_nonce);
        let mut prv_element = [0u8; SecpOrd::NBYTES];
        for ii in 0..total_bits {
            nonce = nonce.add(&SecpOrd::ONE);
            nonce.to_bytes(&mut raw_nonce);
            hash(&mut prv_element, &raw_nonce);
            publicrandomvec[ii] = SecpOrd::from_bytes(&prv_element);
        }

        let ote = OTESender::new(ro, rng, recv, send)?;

        Ok(MulSender {
            publicrandomvec: publicrandomvec,
            ote: ote,
        })
    }

    pub fn apply_refresh(&mut self, rand: &[u8], ro: &DyadicROTagger) -> Result<(), MPECDSAError> {
        return self.ote.apply_refresh(rand, ro);
    }

    pub fn mul_extend<T: Read>(
        &self,
        input_count: usize,
        ro: &DyadicROTagger,
        recv: &mut T,
    ) -> Result<MulSenderData, MPECDSAError> {
        let transposed_seed = self.ote.extend(
            input_count * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) + ENCODING_EXTRA_BITS,
            ro,
            recv,
        )?;

        //finally, collate the output
        let mut transposed_seed_fragments: Vec<
            [u8; HASH_SIZE * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)],
        > = Vec::with_capacity(input_count);
        for ii in 0..input_count {
            let mut fragment = [0u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE];
            fragment.copy_from_slice(
                &transposed_seed[(ii * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE)
                    ..((ii + 1) * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE)],
            );
            transposed_seed_fragments.push(fragment);
        }
        let mut transposed_seed_encoding_fragment = [0u8; ENCODING_EXTRA_BITS * HASH_SIZE];
        transposed_seed_encoding_fragment.copy_from_slice(
            &transposed_seed[(input_count
                * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)
                * HASH_SIZE)
                ..(input_count * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE
                    + ENCODING_EXTRA_BITS * HASH_SIZE)],
        );

        Ok((transposed_seed_fragments, transposed_seed_encoding_fragment))
    }

    pub fn mul_transfer<T: Write>(
        &self,
        inputs_alpha: &[&SecpOrd],
        transposed_seed_fragment: &[&[u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)
               * HASH_SIZE]],
        transposed_seed_encoding_fragment: &[u8; ENCODING_EXTRA_BITS * HASH_SIZE],
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        send: &mut T,
    ) -> Result<Vec<SecpOrd>, MPECDSAError> {
        let gadget_table = match SecpOrd::NBITS {
            256 => &precomp::GADGET_TABLE_256,
            _ => {
                return Err(MPECDSAError::General(GeneralError::new(&format!(
                    "No gadget table defined for {} bit numbers",
                    SecpOrd::NBITS
                ))));
            }
        };

        let mut results = Vec::with_capacity(transposed_seed_fragment.len());
        let mut transposed_seeds = Vec::with_capacity(transposed_seed_fragment.len());
        let mut input_lengths = Vec::with_capacity(transposed_seed_fragment.len());

        for kk in 0..transposed_seed_fragment.len() {
            let mut transposed_seed =
                [0u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS)
                    * HASH_SIZE];
            transposed_seed[0..((SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE)]
                .copy_from_slice(transposed_seed_fragment[kk]);
            transposed_seed[((SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE)..]
                .copy_from_slice(transposed_seed_encoding_fragment);

            transposed_seeds.push(transposed_seed);

            input_lengths.push(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS);
        }

        let vals0 = self.ote.transfer(
            &input_lengths,
            inputs_alpha,
            &transposed_seeds
                .iter()
                .map(|x| x.as_slice())
                .collect::<Vec<&[u8]>>(),
            ro,
            rng,
            send,
        )?;

        for kk in 0..transposed_seed_fragment.len() {
            let mut result = SecpOrd::ZERO;

            for ii in 0..((SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) + ENCODING_EXTRA_BITS) {
                // primary value
                let offset = if ii < SecpOrd::NBITS {
                    &gadget_table[SecpOrd::NBITS - (ii / 8) * 8 - 8 + (ii % 8)]
                } else {
                    &self.publicrandomvec[(ii / 8) * 8 - SecpOrd::NBITS + ii % 8]
                };
                result = result.add(&vals0[kk][ii].mul(offset));
            }
            results.push(result);
        }

        Ok(results)
    }

    pub fn rmul_extend<T: Read>(
        &self,
        input_count: usize,
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        recv: &mut T,
    ) -> Result<RmulSenderData, MPECDSAError> {
        let transposed_seed = self.ote.extend(
            input_count * RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS,
            ro,
            recv,
        )?;

        //finally, collate the output
        let mut transposed_seed_fragments: Vec<[u8; HASH_SIZE * RAND_ENCODING_PER_ELEMENT_BITS]> =
            Vec::with_capacity(input_count);
        for ii in 0..input_count {
            let mut fragment = [0u8; RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE];
            fragment.copy_from_slice(
                &transposed_seed[(ii * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)
                    ..((ii + 1) * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)],
            );
            transposed_seed_fragments.push(fragment);
        }
        let mut transposed_seed_encoding_fragment = [0u8; RAND_ENCODING_EXTRA_BITS * HASH_SIZE];
        transposed_seed_encoding_fragment.copy_from_slice(
            &transposed_seed[(input_count * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)
                ..(input_count * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE
                    + RAND_ENCODING_EXTRA_BITS * HASH_SIZE)],
        );

        let mut inputs_alpha = Vec::with_capacity(transposed_seed_fragments.len());
        for _ in 0..transposed_seed_fragments.len() {
            inputs_alpha.push(SecpOrd::rand(rng));
        }

        Ok((
            transposed_seed_fragments,
            transposed_seed_encoding_fragment,
            inputs_alpha,
        ))
    }

    pub fn rmul_transfer<T: Write>(
        &self,
        inputs_alpha: &[&SecpOrd],
        transposed_seed_fragment: &[&[u8; RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE]],
        transposed_seed_encoding_fragment: &[u8; RAND_ENCODING_EXTRA_BITS * HASH_SIZE],
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        send: &mut T,
    ) -> Result<Vec<SecpOrd>, MPECDSAError> {
        let mut results = Vec::with_capacity(transposed_seed_fragment.len());
        let mut transposed_seeds = Vec::with_capacity(transposed_seed_fragment.len());
        let mut input_lengths = Vec::with_capacity(transposed_seed_fragment.len());

        for kk in 0..transposed_seed_fragment.len() {
            let mut transposed_seed =
                [0u8; (RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS) * HASH_SIZE];
            transposed_seed[0..(RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)]
                .copy_from_slice(transposed_seed_fragment[kk]);
            transposed_seed[(RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)..]
                .copy_from_slice(transposed_seed_encoding_fragment);

            transposed_seeds.push(transposed_seed);

            input_lengths.push(RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS);
        }

        let vals0 = &self.ote.transfer(
            &input_lengths,
            inputs_alpha,
            &transposed_seeds
                .iter()
                .map(|x| x.as_slice())
                .collect::<Vec<&[u8]>>(),
            ro,
            rng,
            send,
        )?;

        for kk in 0..transposed_seed_fragment.len() {
            let mut result = SecpOrd::ZERO;

            for ii in 0..(RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS) {
                // primary value
                let offset = self.publicrandomvec[(ii / 8) * 8 + ii % 8];
                result = result.add(&vals0[kk][ii].mul(&offset));
            }

            results.push(result);
        }

        Ok(results)
    }
}

impl MulRecver {
    pub fn new<T1: Read, T2: Write>(
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        recv: &mut T1,
        send: &mut T2,
    ) -> Result<MulRecver, MPECDSAError> {
        //ROT sender goes first, so we let the OTExt recver choose the public random vector to reduce rounds.
        let total_bits = cmp::max(
            SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS,
            RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS,
        );
        let mut publicrandomvec = vec![SecpOrd::ZERO; total_bits];
        let mut raw_nonce = [0u8; SecpOrd::NBYTES];
        let mut prv_element = [0u8; SecpOrd::NBYTES];
        let mut nonce = SecpOrd::rand(rng);
        nonce.to_bytes(&mut raw_nonce);
        send.write(&raw_nonce)?;
        send.flush()?;
        for ii in 0..total_bits {
            nonce = nonce.add(&SecpOrd::ONE);
            nonce.to_bytes(&mut raw_nonce);
            hash(&mut prv_element, &raw_nonce);
            publicrandomvec[ii] = SecpOrd::from_bytes(&prv_element);
        }

        let ote = OTERecver::new(ro, rng, recv, send)?;

        Ok(MulRecver {
            publicrandomvec: publicrandomvec,
            ote: ote,
        })
    }

    pub fn apply_refresh(&mut self, rand: &[u8], ro: &DyadicROTagger) -> Result<(), MPECDSAError> {
        return self.ote.apply_refresh(rand, ro);
    }

    pub fn mul_encode_and_extend<T: Write>(
        &self,
        inputs_beta: &[SecpOrd],
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        send: &mut T,
    ) -> Result<MulRecverData, MPECDSAError> {
        // Encode phase
        let mut encoding_private_bits = [false; ENCODING_EXTRA_BITS];
        let mut encoding_private_offset = SecpOrd::ZERO;
        for ii in 0..ENCODING_EXTRA_BITS {
            encoding_private_bits[ii] = (rng.next_u32() % 2) > 0;
            let potential_offset =
                encoding_private_offset.add(&self.publicrandomvec[ENCODING_PER_ELEMENT_BITS + ii]);
            if encoding_private_bits[ii] {
                encoding_private_offset = potential_offset;
            }
        }

        let mut encoding_private_element_bits =
            vec![[false; ENCODING_PER_ELEMENT_BITS]; inputs_beta.len()];
        let mut encoding_private_element_offsets = vec![SecpOrd::ZERO; inputs_beta.len()];
        for jj in 0..inputs_beta.len() {
            for ii in 0..ENCODING_PER_ELEMENT_BITS {
                encoding_private_element_bits[jj][ii] = (rng.next_u32() % 2) > 0;
                let potential_offset =
                    encoding_private_element_offsets[jj].add(&self.publicrandomvec[ii]);
                if encoding_private_element_bits[jj][ii] {
                    encoding_private_element_offsets[jj] = potential_offset;
                }
            }
        }

        let mut inputs_encoded: Vec<[bool; SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS]> =
            Vec::with_capacity(inputs_beta.len());
        let mut choice_bits: Vec<bool> = Vec::with_capacity(
            inputs_beta.len() * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)
                + ENCODING_EXTRA_BITS
                + OT_SEC_PARAM,
        );
        for ii in 0..inputs_beta.len() {
            inputs_encoded.push([false; SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS]);
            let beta_aug = inputs_beta[ii]
                .sub(&encoding_private_offset)
                .sub(&encoding_private_element_offsets[ii]);
            for jj in 0..SecpOrd::NBYTES {
                inputs_encoded[ii][jj * 8 + 0] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 0);
                inputs_encoded[ii][jj * 8 + 1] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 1);
                inputs_encoded[ii][jj * 8 + 2] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 2);
                inputs_encoded[ii][jj * 8 + 3] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 3);
                inputs_encoded[ii][jj * 8 + 4] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 4);
                inputs_encoded[ii][jj * 8 + 5] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 5);
                inputs_encoded[ii][jj * 8 + 6] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 6);
                inputs_encoded[ii][jj * 8 + 7] = beta_aug.bit(SecpOrd::NBITS - ((jj + 1) * 8) + 7);
            }
            inputs_encoded[ii][SecpOrd::NBITS..]
                .copy_from_slice(&encoding_private_element_bits[ii]);
            choice_bits.extend_from_slice(&inputs_encoded[ii]);
        }
        choice_bits.extend_from_slice(&encoding_private_bits);

        let transposed_seed0 = self.ote.extend(&choice_bits, ro, rng, send)?;

        //finally, collate the output
        let mut transposed_seed_fragments: Vec<
            [u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE],
        > = Vec::with_capacity(inputs_beta.len());
        for ii in 0..inputs_beta.len() {
            let mut fragment = [0u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE];
            fragment.copy_from_slice(
                &transposed_seed0[(ii * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE)
                    ..((ii + 1) * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE)],
            );
            transposed_seed_fragments.push(fragment);
        }
        let mut transposed_seed_encoding_fragment = [0u8; ENCODING_EXTRA_BITS * HASH_SIZE];
        transposed_seed_encoding_fragment.copy_from_slice(
            &transposed_seed0[(inputs_beta.len()
                * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)
                * HASH_SIZE)
                ..(inputs_beta.len() * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) * HASH_SIZE
                    + ENCODING_EXTRA_BITS * HASH_SIZE)],
        );

        Ok((
            inputs_encoded,
            encoding_private_bits,
            transposed_seed_fragments,
            transposed_seed_encoding_fragment,
        ))
    }

    pub fn mul_transfer<T: Read>(
        &self,
        inputs_beta_encoded: &[&[bool; SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS]],
        encoding_private_bits: &[bool; ENCODING_EXTRA_BITS],
        transposed_seed_fragment: &[&[u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)
               * HASH_SIZE]],
        transposed_seed_encoding_fragment: &[u8; ENCODING_EXTRA_BITS * HASH_SIZE],
        ro: &DyadicROTagger,
        recv: &mut T,
    ) -> Result<Vec<SecpOrd>, MPECDSAError> {
        let gadget_table = match SecpOrd::NBITS {
            256 => &precomp::GADGET_TABLE_256,
            _ => {
                return Err(MPECDSAError::General(GeneralError::new(&format!(
                    "No gadget table defined for {} bit numbers",
                    SecpOrd::NBITS
                ))));
            }
        };

        let mut results = Vec::with_capacity(inputs_beta_encoded.len());
        let mut transposed_seeds = Vec::with_capacity(inputs_beta_encoded.len());
        let mut choice_bitss = Vec::with_capacity(inputs_beta_encoded.len());

        for kk in 0..inputs_beta_encoded.len() {
            let mut transposed_seed =
                [0u8; (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS)
                    * HASH_SIZE];
            transposed_seed[0..(HASH_SIZE * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS))]
                .copy_from_slice(transposed_seed_fragment[kk]);
            transposed_seed[(HASH_SIZE * (SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS))
                ..(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS) * HASH_SIZE]
                .copy_from_slice(transposed_seed_encoding_fragment);
            let mut choice_bits =
                [false; SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS];
            choice_bits[0..(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)]
                .copy_from_slice(inputs_beta_encoded[kk]);
            choice_bits[(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS)
                ..(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) + ENCODING_EXTRA_BITS]
                .copy_from_slice(encoding_private_bits);

            transposed_seeds.push(transposed_seed);
            choice_bitss.push(choice_bits);
        }

        let vals = self.ote.transfer(
            &choice_bitss
                .iter()
                .map(|x| x.as_slice())
                .collect::<Vec<&[bool]>>(),
            &transposed_seeds
                .iter()
                .map(|x| x.as_slice())
                .collect::<Vec<&[u8]>>(),
            ro,
            recv,
        )?;

        for kk in 0..inputs_beta_encoded.len() {
            let mut result = SecpOrd::ZERO;
            for ii in 0..(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS + ENCODING_EXTRA_BITS) {
                let offset = if ii < SecpOrd::NBITS {
                    &gadget_table[SecpOrd::NBITS - (ii / 8) * 8 - 8 + (ii % 8)]
                } else {
                    &self.publicrandomvec[(ii / 8) * 8 - SecpOrd::NBITS + ii % 8]
                };
                result = result.add(&vals[kk][ii].mul(offset));
            }
            results.push(result);
        }

        Ok(results)
    }

    pub fn rmul_encode_and_extend<T: Write>(
        &self,
        input_count: usize,
        ro: &DyadicROTagger,
        rng: &mut dyn Rng,
        send: &mut T,
    ) -> Result<RmulRecverData, MPECDSAError> {
        // Encode phase
        let mut encoding_private_bits = [false; RAND_ENCODING_EXTRA_BITS];
        let mut encoding_private_joint = SecpOrd::ZERO;
        for ii in 0..RAND_ENCODING_EXTRA_BITS {
            encoding_private_bits[ii] = (rng.next_u32() % 2) > 0;
            let potential_offset = encoding_private_joint
                .add(&self.publicrandomvec[RAND_ENCODING_PER_ELEMENT_BITS + ii]);
            if encoding_private_bits[ii] {
                encoding_private_joint = potential_offset;
            }
        }

        let mut encoding_private_random_bits =
            vec![[false; RAND_ENCODING_PER_ELEMENT_BITS]; input_count];
        let mut encoding_private_random = vec![SecpOrd::ZERO; input_count];
        for jj in 0..input_count {
            for ii in 0..RAND_ENCODING_PER_ELEMENT_BITS {
                encoding_private_random_bits[jj][ii] = (rng.next_u32() % 2) > 0;
                let potential_offset = encoding_private_random[jj].add(&self.publicrandomvec[ii]);
                if encoding_private_random_bits[jj][ii] {
                    encoding_private_random[jj] = potential_offset;
                }
            }
        }

        let mut offsets: Vec<SecpOrd> = Vec::with_capacity(input_count);
        let mut choice_bits: Vec<bool> = Vec::with_capacity(
            input_count * RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS + OT_SEC_PARAM,
        );

        let mut inputs_encoded: Vec<[bool; RAND_ENCODING_PER_ELEMENT_BITS]> =
            Vec::with_capacity(input_count);
        for ii in 0..input_count {
            inputs_encoded.push([false; RAND_ENCODING_PER_ELEMENT_BITS]);
            inputs_encoded[ii].copy_from_slice(&encoding_private_random_bits[ii]);
            choice_bits.extend_from_slice(&inputs_encoded[ii]);
            offsets.push(encoding_private_joint.add(&encoding_private_random[ii]));
        }
        choice_bits.extend_from_slice(&encoding_private_bits);

        let transposed_seed0 = self.ote.extend(&choice_bits, ro, rng, send)?;

        //finally, collate the output
        let mut transposed_seed_fragments: Vec<[u8; RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE]> =
            Vec::with_capacity(input_count);
        for ii in 0..input_count {
            let mut fragment = [0u8; RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE];
            fragment.copy_from_slice(
                &transposed_seed0[(ii * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)
                    ..((ii + 1) * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)],
            );
            transposed_seed_fragments.push(fragment);
        }
        let mut transposed_seed_encoding_fragment = [0u8; RAND_ENCODING_EXTRA_BITS * HASH_SIZE];
        transposed_seed_encoding_fragment.copy_from_slice(
            &transposed_seed0[(input_count * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE)
                ..(input_count * RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE
                    + RAND_ENCODING_EXTRA_BITS * HASH_SIZE)],
        );

        Ok((
            inputs_encoded,
            encoding_private_bits,
            transposed_seed_fragments,
            transposed_seed_encoding_fragment,
            offsets,
        ))
    }

    pub fn rmul_transfer<T: Read>(
        &self,
        inputs_beta_encoded: &[&[bool; RAND_ENCODING_PER_ELEMENT_BITS]],
        encoding_private_bits: &[bool; RAND_ENCODING_EXTRA_BITS],
        transposed_seed_fragment: &[&[u8; RAND_ENCODING_PER_ELEMENT_BITS * HASH_SIZE]],
        transposed_seed_encoding_fragment: &[u8; RAND_ENCODING_EXTRA_BITS * HASH_SIZE],
        ro: &DyadicROTagger,
        recv: &mut T,
    ) -> Result<Vec<SecpOrd>, MPECDSAError> {
        let mut results = Vec::with_capacity(inputs_beta_encoded.len());
        let mut transposed_seeds = Vec::with_capacity(inputs_beta_encoded.len());
        let mut choice_bitss = Vec::with_capacity(inputs_beta_encoded.len());

        for kk in 0..inputs_beta_encoded.len() {
            let mut transposed_seed =
                [0u8; (RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS) * HASH_SIZE];
            transposed_seed[0..(HASH_SIZE * RAND_ENCODING_PER_ELEMENT_BITS)]
                .copy_from_slice(transposed_seed_fragment[kk]);
            transposed_seed[(HASH_SIZE * RAND_ENCODING_PER_ELEMENT_BITS)
                ..(RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS) * HASH_SIZE]
                .copy_from_slice(transposed_seed_encoding_fragment);
            let mut choice_bits =
                [false; RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS];
            choice_bits[0..RAND_ENCODING_PER_ELEMENT_BITS].copy_from_slice(inputs_beta_encoded[kk]);
            choice_bits[RAND_ENCODING_PER_ELEMENT_BITS
                ..RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS]
                .copy_from_slice(encoding_private_bits);

            transposed_seeds.push(transposed_seed);
            choice_bitss.push(choice_bits);
        }

        let vals = self.ote.transfer(
            &choice_bitss
                .iter()
                .map(|x| x.as_slice())
                .collect::<Vec<&[bool]>>(),
            &transposed_seeds
                .iter()
                .map(|x| x.as_slice())
                .collect::<Vec<&[u8]>>(),
            ro,
            recv,
        )?;

        for kk in 0..inputs_beta_encoded.len() {
            let mut result = SecpOrd::ZERO;
            for ii in 0..(RAND_ENCODING_PER_ELEMENT_BITS + RAND_ENCODING_EXTRA_BITS) {
                let offset = self.publicrandomvec[(ii / 8) * 8 + ii % 8];
                result = result.add(&vals[kk][ii].mul(&offset));
            }
            results.push(result);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::channelstream::*;
    use super::*;
    use std::thread;
    use test::Bencher;

    #[test]
    fn test_mul_mul_extend() {
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
            let sender = MulSender::new(
                &ro.get_dyadic_tagger(1).unwrap(),
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            sender.mul_extend(
                2,
                &ro.get_dyadic_tagger(1).unwrap(),
                r1[1].as_mut().unwrap(),
            )
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

        let recver = MulRecver::new(
            &ro.get_dyadic_tagger(0).unwrap(),
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();

        let mut beta: Vec<SecpOrd> = Vec::with_capacity(2);
        for _ in 0..2 {
            beta.push(SecpOrd::rand(&mut rng));
        }
        let recver_result = recver.mul_encode_and_extend(
            &beta,
            &ro.get_dyadic_tagger(0).unwrap(),
            &mut rng,
            s2[0].as_mut().unwrap(),
        );
        assert!(recver_result.is_ok());
        let recver_result = recver_result.unwrap();

        let mut encoding_offset = SecpOrd::ZERO;
        for ii in 0..ENCODING_EXTRA_BITS {
            if recver_result.1[ii] {
                encoding_offset =
                    encoding_offset.add(&recver.publicrandomvec[ENCODING_PER_ELEMENT_BITS + ii]);
            }
        }

        for ii in 0..recver_result.0.len() {
            let el_bits = recver_result.0[ii];
            let mut compressed_temp = [0u8; SecpOrd::NBYTES];
            for jj in 0..SecpOrd::NBYTES {
                compressed_temp[jj] = ((el_bits[jj * 8 + 0] as u8) << 0)
                    | ((el_bits[jj * 8 + 1] as u8) << 1)
                    | ((el_bits[jj * 8 + 2] as u8) << 2)
                    | ((el_bits[jj * 8 + 3] as u8) << 3)
                    | ((el_bits[jj * 8 + 4] as u8) << 4)
                    | ((el_bits[jj * 8 + 5] as u8) << 5)
                    | ((el_bits[jj * 8 + 6] as u8) << 6)
                    | ((el_bits[jj * 8 + 7] as u8) << 7);
            }
            let mut beta_temp = SecpOrd::from_bytes(&compressed_temp);
            for jj in SecpOrd::NBITS..(SecpOrd::NBITS + ENCODING_PER_ELEMENT_BITS) {
                if recver_result.0[ii][jj] {
                    beta_temp = beta_temp.add(&recver.publicrandomvec[jj - SecpOrd::NBITS]);
                }
            }
            assert!(beta_temp.add(&encoding_offset) == beta[ii]);
        }

        assert!(child.join().unwrap().is_ok());
    }

    #[test]
    fn test_mul_mul() {
        let mut rng = rand::thread_rng();
        let mut alpha: Vec<SecpOrd> = Vec::with_capacity(10);
        let mut alpha_child: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            alpha.push(SecpOrd::rand(&mut rng));
            alpha_child.push(alpha[ii].clone());
        }

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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &ro.get_dyadic_tagger(1).unwrap(),
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let extensions = sender
                .mul_extend(10, &dro, r1[1].as_mut().unwrap())
                .unwrap();
            let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
            for ii in 0..10 {
                results.push(
                    sender
                        .mul_transfer(
                            &[&alpha_child[ii]],
                            &[&extensions.0[ii]],
                            &extensions.1,
                            &dro,
                            &mut rng,
                            s1[1].as_mut().unwrap(),
                        )
                        .unwrap()[0],
                );
            }
            results
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(10);
        for _ in 0..10 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let extensions = recver
            .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
            .unwrap();
        let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            results.push(
                recver
                    .mul_transfer(
                        &[&extensions.0[ii]],
                        &extensions.1,
                        &[&extensions.2[ii]],
                        &extensions.3,
                        &dro,
                        r2[0].as_mut().unwrap(),
                    )
                    .unwrap()[0],
            );
        }

        let childresult: Vec<SecpOrd> = child.join().unwrap();
        for ii in 0..10 {
            assert_eq!(results[ii].add(&childresult[ii]), beta[ii].mul(&alpha[ii]));
        }
    }

    #[test]
    fn test_mul_refresh() {
        let mut rng = rand::thread_rng();
        let mut refresh_rand = [0u8; HASH_SIZE];
        rng.fill_bytes(&mut refresh_rand);
        let mut alpha: Vec<SecpOrd> = Vec::with_capacity(10);
        let mut alpha_child: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            alpha.push(SecpOrd::rand(&mut rng));
            alpha_child.push(alpha[ii].clone());
        }

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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let mut sender = MulSender::new(
                &ro.get_dyadic_tagger(1).unwrap(),
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            sender.apply_refresh(&refresh_rand, &dro).unwrap();
            let extensions = sender
                .mul_extend(10, &dro, r1[1].as_mut().unwrap())
                .unwrap();
            let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
            for ii in 0..10 {
                results.push(
                    sender
                        .mul_transfer(
                            &[&alpha_child[ii]],
                            &[&extensions.0[ii]],
                            &extensions.1,
                            &dro,
                            &mut rng,
                            s1[1].as_mut().unwrap(),
                        )
                        .unwrap()[0],
                );
            }
            results
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let mut recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        recver.apply_refresh(&refresh_rand, &dro).unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(10);
        for _ in 0..10 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let extensions = recver
            .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
            .unwrap();
        let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            results.push(
                recver
                    .mul_transfer(
                        &[&extensions.0[ii]],
                        &extensions.1,
                        &[&extensions.2[ii]],
                        &extensions.3,
                        &dro,
                        r2[0].as_mut().unwrap(),
                    )
                    .unwrap()[0],
            );
        }

        let childresult: Vec<SecpOrd> = child.join().unwrap();
        for ii in 0..10 {
            assert_eq!(results[ii].add(&childresult[ii]), beta[ii].mul(&alpha[ii]));
        }
    }

    #[test]
    fn test_mul_batchmul() {
        let mut rng = rand::thread_rng();
        let mut alpha: Vec<SecpOrd> = Vec::with_capacity(10);
        let mut alpha_child: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            alpha.push(SecpOrd::rand(&mut rng));
            alpha_child.push(alpha[ii].clone());
        }

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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &ro.get_dyadic_tagger(1).unwrap(),
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let extensions = sender
                .mul_extend(10, &dro, r1[1].as_mut().unwrap())
                .unwrap();
            let results = sender
                .mul_transfer(
                    &alpha_child.iter().collect::<Vec<_>>(),
                    &extensions.0.iter().collect::<Vec<_>>(),
                    &extensions.1,
                    &dro,
                    &mut rng,
                    s1[1].as_mut().unwrap(),
                )
                .unwrap();
            results
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(10);
        for _ in 0..10 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let extensions = recver
            .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
            .unwrap();
        let results = recver
            .mul_transfer(
                &extensions.0.iter().collect::<Vec<_>>(),
                &extensions.1,
                &extensions.2.iter().collect::<Vec<_>>(),
                &extensions.3,
                &dro,
                r2[0].as_mut().unwrap(),
            )
            .unwrap();

        let childresult: Vec<SecpOrd> = child.join().unwrap();
        for ii in 0..10 {
            assert_eq!(results[ii].add(&childresult[ii]), beta[ii].mul(&alpha[ii]));
        }
    }

    #[test]
    fn test_mul_rmul() {
        let mut rng = rand::thread_rng();

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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &dro,
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let extensions = sender
                .rmul_extend(10, &dro, &mut rng, r1[1].as_mut().unwrap())
                .unwrap();
            let mut results: Vec<(SecpOrd, SecpOrd)> = Vec::with_capacity(10);
            for ii in 0..10 {
                results.push((
                    extensions.2[ii],
                    sender
                        .rmul_transfer(
                            &[&extensions.2[ii]],
                            &[&extensions.0[ii]],
                            &extensions.1,
                            &dro,
                            &mut rng,
                            s1[1].as_mut().unwrap(),
                        )
                        .unwrap()[0],
                ));
            }
            results
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(10);
        for _ in 0..10 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let extensions = recver
            .rmul_encode_and_extend(10, &dro, &mut rng, s2[0].as_mut().unwrap())
            .unwrap();
        let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            results.push(
                recver
                    .rmul_transfer(
                        &[&extensions.0[ii]],
                        &extensions.1,
                        &[&extensions.2[ii]],
                        &extensions.3,
                        &dro,
                        r2[0].as_mut().unwrap(),
                    )
                    .unwrap()[0],
            );
        }

        let childresult: Vec<(SecpOrd, SecpOrd)> = child.join().unwrap();
        for ii in 0..10 {
            assert_eq!(
                results[ii].add(&childresult[ii].1),
                extensions.4[ii].mul(&childresult[ii].0)
            );
        }
    }

    #[test]
    fn test_mul_rbatchmul() {
        let mut rng = rand::thread_rng();

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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &dro,
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let extensions = sender
                .rmul_extend(10, &dro, &mut rng, r1[1].as_mut().unwrap())
                .unwrap();
            let results = sender
                .rmul_transfer(
                    &extensions.2.iter().collect::<Vec<_>>(),
                    &extensions.0.iter().collect::<Vec<_>>(),
                    &extensions.1,
                    &dro,
                    &mut rng,
                    s1[1].as_mut().unwrap(),
                )
                .unwrap();
            extensions.2.into_iter().zip(results.into_iter()).collect()
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(10);
        for _ in 0..10 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let extensions = recver
            .rmul_encode_and_extend(10, &dro, &mut rng, s2[0].as_mut().unwrap())
            .unwrap();
        let results = recver
            .rmul_transfer(
                &extensions.0.iter().collect::<Vec<_>>(),
                &extensions.1,
                &extensions.2.iter().collect::<Vec<_>>(),
                &extensions.3,
                &dro,
                r2[0].as_mut().unwrap(),
            )
            .unwrap();

        let childresult: Vec<(SecpOrd, SecpOrd)> = child.join().unwrap();
        for ii in 0..10 {
            assert_eq!(
                results[ii].add(&childresult[ii].1),
                extensions.4[ii].mul(&childresult[ii].0)
            );
        }
    }

    #[test]
    fn test_mul_multimul() {
        let mut rng = rand::thread_rng();
        let mut alpha: Vec<SecpOrd> = Vec::with_capacity(10);
        let mut alpha_child: Vec<SecpOrd> = Vec::with_capacity(10);
        for ii in 0..10 {
            alpha.push(SecpOrd::rand(&mut rng));
            alpha_child.push(alpha[ii].clone());
        }

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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &dro,
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let extensions = sender.mul_extend(1, &dro, r1[1].as_mut().unwrap()).unwrap();
            let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
            for ii in 0..10 {
                results.push(
                    sender
                        .mul_transfer(
                            &[&alpha_child[ii]],
                            &[&extensions.0[0]],
                            &extensions.1,
                            &dro,
                            &mut rng,
                            s1[1].as_mut().unwrap(),
                        )
                        .unwrap()[0],
                );
            }
            results
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(1);
        beta.push(SecpOrd::rand(&mut rng));

        let extensions = recver
            .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
            .unwrap();
        let mut results: Vec<SecpOrd> = Vec::with_capacity(10);
        for _ in 0..10 {
            results.push(
                recver
                    .mul_transfer(
                        &[&extensions.0[0]],
                        &extensions.1,
                        &[&extensions.2[0]],
                        &extensions.3,
                        &dro,
                        r2[0].as_mut().unwrap(),
                    )
                    .unwrap()[0],
            );
        }

        let childresult: Vec<SecpOrd> = child.join().unwrap();
        for ii in 0..10 {
            assert_eq!(results[ii].add(&childresult[ii]), beta[0].mul(&alpha[ii]));
        }
    }

    #[bench]
    fn bench_mul_mul_extend(b: &mut Bencher) -> () {
        let mut rng = rand::thread_rng();
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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &dro,
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let mut keepgoing = [1u8; 1];
            r1[1].as_mut().unwrap().read_exact(&mut keepgoing).unwrap();
            while keepgoing[0] > 0 {
                sender.mul_extend(2, &dro, r1[1].as_mut().unwrap()).unwrap();
                r1[1].as_mut().unwrap().read_exact(&mut keepgoing).unwrap();
            }
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(2);
        for _ in 0..2 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let mut ii: usize = 0;
        b.iter(|| {
            s2[0].as_mut().unwrap().write(&[1]).unwrap();
            s2[0].as_mut().unwrap().flush().unwrap();
            recver
                .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
                .unwrap();
            ii += 1;
        });

        s2[0].as_mut().unwrap().write(&[0]).unwrap();
        s2[0].as_mut().unwrap().flush().unwrap();
        child.join().unwrap();
    }

    #[bench]
    fn bench_mul_mul_2_and_2(b: &mut Bencher) -> () {
        let mut rng = rand::thread_rng();
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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &dro,
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let mut keepgoing = [1u8; 1];

            let mut alpha: Vec<SecpOrd> = Vec::with_capacity(2);
            for _ in 0..2 {
                alpha.push(SecpOrd::rand(&mut rng));
            }

            r1[1].as_mut().unwrap().read_exact(&mut keepgoing).unwrap();
            while keepgoing[0] > 0 {
                let extensions = sender.mul_extend(2, &dro, r1[1].as_mut().unwrap()).unwrap();
                sender
                    .mul_transfer(
                        &[&alpha[0]],
                        &[&extensions.0[0]],
                        &extensions.1,
                        &dro,
                        &mut rng,
                        s1[1].as_mut().unwrap(),
                    )
                    .unwrap();
                sender
                    .mul_transfer(
                        &[&alpha[1]],
                        &[&extensions.0[0]],
                        &extensions.1,
                        &dro,
                        &mut rng,
                        s1[1].as_mut().unwrap(),
                    )
                    .unwrap();
                s1[1].as_mut().unwrap().flush().unwrap();
                r1[1].as_mut().unwrap().read_exact(&mut keepgoing).unwrap();
            }
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(2);
        for _ in 0..2 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        b.iter(|| {
            s2[0].as_mut().unwrap().write(&[1]).unwrap();
            s2[0].as_mut().unwrap().flush().unwrap();
            let extensions = recver
                .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
                .unwrap();
            recver
                .mul_transfer(
                    &[&extensions.0[0]],
                    &extensions.1,
                    &[&extensions.2[0]],
                    &extensions.3,
                    &dro,
                    r2[0].as_mut().unwrap(),
                )
                .unwrap();
            recver
                .mul_transfer(
                    &[&extensions.0[0]],
                    &extensions.1,
                    &[&extensions.2[0]],
                    &extensions.3,
                    &dro,
                    r2[0].as_mut().unwrap(),
                )
                .unwrap();
        });

        s2[0].as_mut().unwrap().write(&[0]).unwrap();
        s2[0].as_mut().unwrap().flush().unwrap();
        child.join().unwrap();
    }

    #[bench]
    fn bench_mul_mul_2_and_3(b: &mut Bencher) -> () {
        let mut rng = rand::thread_rng();
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

            let dro = ro.get_dyadic_tagger(1).unwrap();
            let sender = MulSender::new(
                &dro,
                &mut rng,
                r1[1].as_mut().unwrap(),
                s1[1].as_mut().unwrap(),
            )
            .unwrap();
            let mut keepgoing = [1u8; 1];

            let mut alpha: Vec<SecpOrd> = Vec::with_capacity(3);
            for _ in 0..3 {
                alpha.push(SecpOrd::rand(&mut rng));
            }

            r1[1].as_mut().unwrap().read_exact(&mut keepgoing).unwrap();
            while keepgoing[0] > 0 {
                let extensions = sender.mul_extend(2, &dro, r1[1].as_mut().unwrap()).unwrap();
                sender
                    .mul_transfer(
                        &[&alpha[0]],
                        &[&extensions.0[0]],
                        &extensions.1,
                        &dro,
                        &mut rng,
                        s1[1].as_mut().unwrap(),
                    )
                    .unwrap();
                sender
                    .mul_transfer(
                        &[&alpha[1]],
                        &[&extensions.0[0]],
                        &extensions.1,
                        &dro,
                        &mut rng,
                        s1[1].as_mut().unwrap(),
                    )
                    .unwrap();
                sender
                    .mul_transfer(
                        &[&alpha[2]],
                        &[&extensions.0[1]],
                        &extensions.1,
                        &dro,
                        &mut rng,
                        s1[1].as_mut().unwrap(),
                    )
                    .unwrap();
                s1[1].as_mut().unwrap().flush().unwrap();
                r1[1].as_mut().unwrap().read_exact(&mut keepgoing).unwrap();
            }
        });

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

        let dro = ro.get_dyadic_tagger(0).unwrap();
        let recver = MulRecver::new(
            &dro,
            &mut rng,
            r2[0].as_mut().unwrap(),
            s2[0].as_mut().unwrap(),
        )
        .unwrap();
        let mut beta: Vec<SecpOrd> = Vec::with_capacity(2);
        for _ in 0..2 {
            beta.push(SecpOrd::rand(&mut rng));
        }

        let mut ii: usize = 0;
        b.iter(|| {
            s2[0].as_mut().unwrap().write(&[1]).unwrap();
            s2[0].as_mut().unwrap().flush().unwrap();
            let extensions = recver
                .mul_encode_and_extend(&beta, &dro, &mut rng, s2[0].as_mut().unwrap())
                .unwrap();
            recver
                .mul_transfer(
                    &[&extensions.0[0]],
                    &extensions.1,
                    &[&extensions.2[0]],
                    &extensions.3,
                    &dro,
                    r2[0].as_mut().unwrap(),
                )
                .unwrap();
            recver
                .mul_transfer(
                    &[&extensions.0[0]],
                    &extensions.1,
                    &[&extensions.2[0]],
                    &extensions.3,
                    &dro,
                    r2[0].as_mut().unwrap(),
                )
                .unwrap();
            recver
                .mul_transfer(
                    &[&extensions.0[1]],
                    &extensions.1,
                    &[&extensions.2[1]],
                    &extensions.3,
                    &dro,
                    r2[0].as_mut().unwrap(),
                )
                .unwrap();
            ii += 1;
        });

        s2[0].as_mut().unwrap().write(&[0]).unwrap();
        s2[0].as_mut().unwrap().flush().unwrap();
        child.join().unwrap();
    }
}
