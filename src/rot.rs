/***********
 * This module implements the VSOT Random Oblivious Transfer Protocol,
 * as described in the paper "Secure Two-party Threshold ECDSA from ECDSA Assumptions"
 * by Doerner, Kondi, Lee, and shelat (https://eprint.iacr.org/2018/499)
 * 
 * VSOT is based upon the Simplest Protocol for Oblivious Transfer
 * as described in the paper "The Simplest Protocol For Oblivious Transfer"
 * by Chou and Orlandi (https://eprint.iacr.org/2015/267)
 ***********/

use std::io::prelude::*;

use rand::{Rng};

//use byteorder::{ByteOrder, LittleEndian};

use curves::{Ford, ECGroup, Secp, SecpOrd, precomp};

use super::mpecdsa_error::*;
use super::ro::*;
use super::zkpok::*;
use super::*;



#[derive(Clone)]
pub struct ROTSender {
	sk: SecpOrd,
	pk: Secp,
	pk_negsquared:	Secp
}

impl ROTSender {
	pub fn new<T: Write>(ro: &DyadicROTagger, rng: &mut dyn Rng, send: &mut T) -> Result<ROTSender,MPECDSAError> {
		let (sk, pk) : (SecpOrd, Secp) = Secp::rand(rng);
		
		let mut buf = [0u8; Secp::NBYTES];
		pk.to_bytes(&mut buf);
		send.write(&buf)?;
		let mro = ModelessDyadicROTagger::new(&ro, true);
		zkpok::prove_dl_fs(&sk, &pk, &mro, rng, send)?;

		Ok(ROTSender {
			sk: sk,
			pk: pk,
			pk_negsquared: Secp::scalar_gen(&sk.sqr()).neg()
		})
	}

	pub fn decode<T: Read>(&mut self, ro: &DyadicROTagger, recv:&mut T) -> io::Result<([u8;HASH_SIZE],[u8;HASH_SIZE])> {
		// read ga1 array from receiver
		let mut buf = [0u8; Secp::NBYTES];
		recv.read_exact(&mut buf)?;

		let ga_select = Secp::from_bytes(&buf[..]);
		let msg_0 = ga_select.scalar_table(&self.sk).affine();
		let msg_1 = Secp::op(&msg_0, &self.pk_negsquared).affine();

		let mut msgbuf_0 = [0u8; RO_TAG_SIZE + Secp::NBYTES];
		let mut msgbuf_1 = [0u8; RO_TAG_SIZE + Secp::NBYTES];
		let mut outbuf_0 = [0u8; HASH_SIZE];
		let mut outbuf_1 = [0u8; HASH_SIZE];

		msg_0.to_bytes(&mut msgbuf_0[RO_TAG_SIZE..]);
		msgbuf_0[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag()[..]);
		hash(&mut outbuf_0, &msgbuf_0);

		msg_1.to_bytes(&mut msgbuf_1[RO_TAG_SIZE..]);
		msgbuf_1[0..RO_TAG_SIZE].copy_from_slice(&msgbuf_0[0..RO_TAG_SIZE]);
		hash(&mut outbuf_1, &msgbuf_1);

		Ok((outbuf_0, outbuf_1))
	}
}

#[derive(Clone)]
pub struct ROTRecver {
	pk: Secp,
	pk_table: Vec<Secp>
}

impl ROTRecver {
	pub fn new<T:Read>(ro: &DyadicROTagger, recv: &mut T) -> Result<ROTRecver,MPECDSAError> {
		let mut buf = [0u8; Secp::NBYTES];
		recv.read_exact(&mut buf[..])?;

		let pk = Secp::from_bytes(&buf);
		let mro = ModelessDyadicROTagger::new(&ro, true);
		let prover_honest = verify_dl_fs(&pk, &mro, recv)?;
		if prover_honest {
			Ok(ROTRecver {
				pk: pk,
				pk_table: Secp::precomp_table(&pk)
			})
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ROT secret key (sender cheated)")))
		}
	}

	pub fn choose<T:Write>(&mut self, choice_bit: bool, ro: &DyadicROTagger, rng: &mut dyn Rng, send: &mut T) -> io::Result<[u8; HASH_SIZE]> {
		let a = SecpOrd::rand(rng);
		let ga_choice0 = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &a).affine();
		let ga_choice1 = Secp::op(&ga_choice0, &self.pk).affine(); //always do this to avoid timing channel
		let pka = Secp::scalar_table_multi(&self.pk_table[..], &a).affine();
		let mut buf = [0u8; RO_TAG_SIZE + Secp::NBYTES];
		let mut outbuf = [0u8; HASH_SIZE];
		
		if choice_bit {
			ga_choice1.to_bytes(&mut buf[RO_TAG_SIZE..]);
		} else {
			ga_choice0.to_bytes(&mut buf[RO_TAG_SIZE..]);
		}
		send.write(&buf[RO_TAG_SIZE..])?;

		pka.to_bytes(&mut buf[RO_TAG_SIZE..]);
		buf[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag()[..]);
		hash(&mut outbuf, &buf);
		Ok(outbuf)
	}
}



#[derive(Clone)]
pub struct ROTSendVerifier {
	msg_0_com: [u8; HASH_SIZE],
	msg_1_com: [u8; HASH_SIZE],
	exp_chal: [u8; HASH_SIZE]
}

impl ROTSendVerifier {
	pub fn new<T:Write>(msg_0: [u8; HASH_SIZE], msg_1: [u8; HASH_SIZE], ro: &DyadicROTagger, send: &mut T) -> Result<ROTSendVerifier,MPECDSAError> {
		let mut s =  ROTSendVerifier {
			msg_0_com: [0u8; HASH_SIZE],
			msg_1_com: [0u8; HASH_SIZE],
			exp_chal: [0u8; HASH_SIZE]
		};
		let mut com_msg = [0u8;HASH_SIZE];
		let mut hashin = [0u8; HASH_SIZE+RO_TAG_SIZE];

		hashin[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag());
		hashin[RO_TAG_SIZE..].copy_from_slice(&msg_0);
		hash(&mut s.msg_0_com, &hashin);

		hashin[RO_TAG_SIZE..].copy_from_slice(&msg_1);
		hash(&mut s.msg_1_com, &hashin);

		hashin[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag());
		hashin[RO_TAG_SIZE..].copy_from_slice(&s.msg_0_com);
		hash(&mut s.exp_chal, &hashin);

		//hashin[0..RO_TAG_SIZE].copy_from_slice(&try!(tagrange.next())[..]);
		hashin[RO_TAG_SIZE..].copy_from_slice(&s.msg_1_com);
		hash(&mut com_msg, &hashin);

		for ii in 0..com_msg.len() {
			com_msg[ii] ^= s.exp_chal[ii];
		}
		send.write(&com_msg)?;

		Ok(s)
	}

	pub fn open<T1:Read, T2:Write>(&self, recv: &mut T1, send: &mut T2) -> Result<(),MPECDSAError> {
		let mut chal_msg = [0u8; HASH_SIZE];
		recv.read_exact(&mut chal_msg)?;

		if vec_eq(&chal_msg[..], &self.exp_chal[..]) {
			send.write(&self.msg_0_com)?;
			send.write(&self.msg_1_com)?;
			Ok(())
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Verification Failed for ROT (receiver cheated)")))
		}
	}
}

#[derive(Clone)]
pub struct ROTRecvVerifier {
	choice_bit: bool,
	hashed_chosen_msg: [u8; HASH_SIZE],
	com_msg: [u8; HASH_SIZE],
	tag2: [u8; RO_TAG_SIZE]
}

impl ROTRecvVerifier {
	pub fn new<T1:Read, T2:Write>(msg: [u8; HASH_SIZE], choice_bit: bool, ro: &DyadicROTagger, recv: &mut T1, send: &mut T2) -> Result<ROTRecvVerifier,MPECDSAError> {
		let mut s =  ROTRecvVerifier {
			choice_bit: choice_bit,
			hashed_chosen_msg: [0u8; HASH_SIZE],
			com_msg: [0u8; HASH_SIZE],
			tag2: [0u8; RO_TAG_SIZE]
		};

		let mut hashin = [0u8;HASH_SIZE+RO_TAG_SIZE];

		hashin[0..RO_TAG_SIZE].copy_from_slice(&ro.next_dyadic_tag());
		hashin[RO_TAG_SIZE..].copy_from_slice(&msg);
		hash(&mut s.hashed_chosen_msg, &hashin);

		let mut chal_msg = [0u8; HASH_SIZE];
		s.tag2.copy_from_slice(&ro.next_dyadic_tag());
		hashin[0..RO_TAG_SIZE].copy_from_slice(&s.tag2[..]);
		hashin[RO_TAG_SIZE..].copy_from_slice(&s.hashed_chosen_msg);
		hash(&mut chal_msg, &hashin);
		recv.read_exact(&mut s.com_msg)?;

		if choice_bit {
			for ii in 0..chal_msg.len() {
				chal_msg[ii] ^= s.com_msg[ii];
			}
		}
		send.write(&chal_msg)?;
		Ok(s)
	}

	pub fn open<T:Read>(&mut self, recv: &mut T) -> Result<(),MPECDSAError> {
		let mut msg_0_com = [0u8; HASH_SIZE];
		let mut msg_1_com = [0u8; HASH_SIZE];
		let mut exp_com_msg = [0u8; HASH_SIZE];
		recv.read_exact(&mut msg_0_com)?;
		recv.read_exact(&mut msg_1_com)?;
		let chosen_msg_com  = if self.choice_bit { 
			msg_1_com
		} else {
			msg_0_com
		};

		let mut hashin = [0u8; HASH_SIZE+RO_TAG_SIZE];
		hashin[0..RO_TAG_SIZE].copy_from_slice(&self.tag2[..]);
		hashin[RO_TAG_SIZE..].copy_from_slice(&msg_0_com);
		hash(&mut exp_com_msg, &hashin);
		for ii in 0..exp_com_msg.len() {
			self.com_msg[ii] ^= exp_com_msg[ii];
		}

		hashin[0..RO_TAG_SIZE].copy_from_slice(&self.tag2[..]);
		hashin[RO_TAG_SIZE..].copy_from_slice(&msg_1_com);
		hash(&mut exp_com_msg, &hashin);

		if vec_eq(&exp_com_msg, &self.com_msg) && vec_eq(&chosen_msg_com, &self.hashed_chosen_msg) {
			Ok(())
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Verification Failed for ROT (sender cheated)")))
		}
	}
}


// for convenience:
pub fn rot_send_batch<T1:Read, T2:Write>(count: usize, ro: &DyadicROTagger, rng: &mut dyn Rng, recv:&mut T1, send: &mut T2) -> Result<Vec<([u8;HASH_SIZE],[u8;HASH_SIZE])>,MPECDSAError> {
	let mut rotsender = ROTSender::new(ro, rng, send)?;
	send.flush()?;

	let mut sender_msgs: Vec<([u8;HASH_SIZE],[u8;HASH_SIZE])> = Vec::with_capacity(count);
	let mut sverifiers: Vec<ROTSendVerifier> = Vec::with_capacity(count);
	for _ in 0..count {
		let (sender_msg_0, sender_msg_1) = rotsender.decode(ro, recv)?;
		sender_msgs.push((sender_msg_0,sender_msg_1));
	}
	for ii in 0..count{
		sverifiers.push(ROTSendVerifier::new(sender_msgs[ii].0, sender_msgs[ii].1, ro, send)?);
	}
	send.flush()?;

	for ii in 0..count {
		sverifiers[ii].open(recv, send)?;
	}
	send.flush()?;

	Ok(sender_msgs)
}

pub fn rot_recv_batch<T1:Read, T2:Write>(choice_bits: &[bool], ro: &DyadicROTagger, rng: &mut dyn Rng, recv:&mut T1, send: &mut T2) -> Result<Vec<[u8;HASH_SIZE]>,MPECDSAError> {
	let mut rotrecver = ROTRecver::new(ro, recv)?;

	let mut recver_msgs: Vec<[u8;HASH_SIZE]> = Vec::with_capacity(choice_bits.len());
	for ii in 0..choice_bits.len() {
		recver_msgs.push(rotrecver.choose(choice_bits[ii], ro, rng, send)?);
	}
	send.flush()?;

	let mut rverifiers: Vec<ROTRecvVerifier> = Vec::with_capacity(choice_bits.len());
	for ii in 0..choice_bits.len() {
		rverifiers.push(ROTRecvVerifier::new(recver_msgs[ii], choice_bits[ii], ro, recv, send)?);
	}
	send.flush()?;

	for ii in 0..choice_bits.len() {
		rverifiers[ii].open(recv)?;
	}

	Ok(recver_msgs)
}



#[cfg(test)]
mod tests {
	use super::*;
	use super::channelstream::*;
	use std::thread;
	use test::Bencher;
	
	const N: usize = 128;

	#[test]
	fn test_rot() {

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(2);

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);

		let mut rng = rand::thread_rng();

		let mut choice_bits: [bool;N] = [false;N];
		for ii in 0..choice_bits.len() {
			choice_bits[ii] = rng.gen();
		}

		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			
			let ro = {
				let mut r1ref = r1.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
				let mut s1ref = s1.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
				GroupROTagger::from_network_unverified(0, &mut rng, &mut r1ref[..], &mut s1ref[..]).unwrap()
			};
			rot_send_batch(N, &mut ro.get_dyadic_tagger(1).unwrap(), &mut rng, r1[1].as_mut().unwrap(), s1[1].as_mut().unwrap()).unwrap();
		});

		let ro = {
			let mut r2ref = r2.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
			let mut s2ref = s2.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
			GroupROTagger::from_network_unverified(1, &mut rng, &mut r2ref[..], &mut s2ref[..]).unwrap()
		};
		rot_recv_batch(&choice_bits, &mut ro.get_dyadic_tagger(0).unwrap(), &mut rng, r2[0].as_mut().unwrap(), s2[0].as_mut().unwrap()).unwrap();

		child.join().unwrap();
	}

	#[bench]
	fn bench_rot_batch(b: &mut Bencher) {
		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(2);

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);

		let mut rng = rand::thread_rng();

		let mut choice_bits: [bool;N] = [false;N];
		for ii in 0..choice_bits.len() {
			choice_bits[ii] = rng.gen();
		}

		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			
			let ro = {
				let mut r1ref = r1.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
				let mut s1ref = s1.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
				GroupROTagger::from_network_unverified(0, &mut rng, &mut r1ref[..], &mut s1ref[..]).unwrap()
			};

			let mut keepgoing = [1u8; 1];
			r1[1].as_mut().unwrap().read_exact(&mut keepgoing).expect("Sender failed to read (1)");
			while keepgoing[0] > 0 {
				rot_send_batch(N, &mut ro.get_dyadic_tagger(1).unwrap(), &mut rng, r1[1].as_mut().unwrap(), s1[1].as_mut().unwrap()).unwrap();
				r1[1].as_mut().unwrap().read_exact(&mut keepgoing).expect("Sender failed to read (2)");
			}
		});

		let ro = {
			let mut r2ref = r2.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
			let mut s2ref = s2.iter_mut().map(|x| if x.is_some() { x.as_mut() } else { None }).collect::<Vec<Option<&mut _>>>();
			GroupROTagger::from_network_unverified(1, &mut rng, &mut r2ref[..], &mut s2ref[..]).unwrap()
		};

		b.iter(|| { 
			s2[0].as_mut().unwrap().write(&[1]).expect("Recver failed to write (1)");
			s2[0].as_mut().unwrap().flush().expect("Recver failed to flush");
			rot_recv_batch(&choice_bits, &mut ro.get_dyadic_tagger(0).unwrap(), &mut rng, r2[0].as_mut().unwrap(), s2[0].as_mut().unwrap()).unwrap();
		});

		s2[0].as_mut().unwrap().write(&[0]).expect("Recver failed to write (2)");
		s2[0].as_mut().unwrap().flush().expect("Recver failed to flush");
		child.join().unwrap();
	}
}