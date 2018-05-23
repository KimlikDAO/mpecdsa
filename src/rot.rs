use std::io::{BufWriter};
use std::io::prelude::*;

use rand::{Rng};

//use byteorder::{ByteOrder, LittleEndian};

use curves::{Ford, ECGroup, Secp, SecpOrd, precomp};

use super::zkpok::*;
use super::mpecdsa_error::*;
use super::*;



#[derive(Clone)]
pub struct ROTSender {
	sk: SecpOrd,
	pk: Secp,
	pk_negsquared:	Secp
}

impl ROTSender {
	pub fn new<T: Write>(rng: &mut Rng, send: &mut T) -> io::Result<ROTSender> {
		let (sk, pk) : (SecpOrd, Secp) = Secp::rand(rng);
		
		let mut buf = [0u8; Secp::NBYTES];
		pk.to_bytes(&mut buf);
		try!(send.write(&buf));
		try!(zkpok::prove_dl_fs(&sk, &pk, rng, send));

		Ok(ROTSender {
			sk: sk,
			pk: pk,
			pk_negsquared: Secp::scalar_gen(&sk.sqr()).neg()
		})
	}

	pub fn decode<T: Read>(&mut self, recv:&mut T) -> io::Result<([u8;HASH_SIZE],[u8;HASH_SIZE])> {
		// read ga1 array from receiver
		let mut buf = [0u8; Secp::NBYTES];
		try!(recv.read_exact(&mut buf));

		let ga_select = Secp::from_bytes(&buf[..]);
		let msg_0 = ga_select.scalar_table(&self.sk).affine();
		let msg_1 = Secp::op(&msg_0, &self.pk_negsquared).affine();

		let mut msgbuf_0 = [0u8; Secp::NBYTES];
		let mut msgbuf_1 = [0u8; Secp::NBYTES];
		let mut outbuf_0 = [0u8; HASH_SIZE];
		let mut outbuf_1 = [0u8; HASH_SIZE];

		msg_0.to_bytes(&mut msgbuf_0);
		hash(&mut outbuf_0, &msgbuf_0);

		msg_1.to_bytes(&mut msgbuf_1);
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
	pub fn new<T:Read>(recv: &mut T) -> Result<ROTRecver,MPECDSAError> {
		let mut buf = [0u8; Secp::NBYTES];
		try!(recv.read_exact(&mut buf[..]));

		let pk = Secp::from_bytes(&buf);
		let prover_honest = try!(verify_dl_fs(&pk, recv));
		if prover_honest {
			Ok(ROTRecver {
				pk: pk,
				pk_table: Secp::precomp_table(&pk)
			})
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ROT secret key (sender cheated)")))
		}
	}

	pub fn choose<T:Write>(&mut self, choice_bit: bool, rng: &mut Rng, send: &mut T) -> io::Result<[u8; HASH_SIZE]> {
		let a = SecpOrd::rand(rng);
		let ga_choice0 = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &a).affine();
		let ga_choice1 = Secp::op(&ga_choice0, &self.pk).affine(); //always do this to avoid timing channel
		let pka = Secp::scalar_table_multi(&self.pk_table[..], &a).affine();
		let mut buf = [0u8; Secp::NBYTES];
		let mut outbuf = [0u8; HASH_SIZE];
		
		if choice_bit {
			ga_choice1.to_bytes(&mut buf[..]);
		} else {
			ga_choice0.to_bytes(&mut buf[..]);
		}
		try!(send.write(&buf));

		pka.to_bytes(&mut buf[..]);
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
	pub fn new<T:Write>(msg_0: [u8; HASH_SIZE], msg_1: [u8; HASH_SIZE], send: &mut T) -> io::Result<ROTSendVerifier> {
		let mut s =  ROTSendVerifier {
			msg_0_com: [0u8; HASH_SIZE],
			msg_1_com: [0u8; HASH_SIZE],
			exp_chal: [0u8; HASH_SIZE]
		};
		let mut com_msg = [0u8;HASH_SIZE];

		hash(&mut s.msg_0_com, &msg_0);
		hash(&mut s.msg_1_com, &msg_1);
		hash(&mut s.exp_chal, &s.msg_0_com);
		hash(&mut com_msg, &s.msg_1_com);

		for ii in 0..com_msg.len() {
			com_msg[ii] ^= s.exp_chal[ii];
		}
		try!(send.write(&com_msg));

		Ok(s)
	}

	pub fn open<T1:Read, T2:Write>(&self, recv: &mut T1, send: &mut T2) -> Result<(),MPECDSAError> {
		let mut chal_msg = [0u8; HASH_SIZE];
		try!(recv.read_exact(&mut chal_msg));

		if vec_eq(&chal_msg[..], &self.exp_chal[..]) {
			try!(send.write(&self.msg_0_com));
			try!(send.write(&self.msg_1_com));
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
	com_msg: [u8; HASH_SIZE]
}

impl ROTRecvVerifier {
	pub fn new<T1:Read, T2:Write>(msg: [u8; HASH_SIZE], choice_bit: bool, recv: &mut T1, send: &mut T2) -> io::Result<ROTRecvVerifier> {
		let mut s =  ROTRecvVerifier {
			choice_bit: choice_bit,
			hashed_chosen_msg: [0u8; HASH_SIZE],
			com_msg: [0u8; HASH_SIZE]
		};
		hash(&mut s.hashed_chosen_msg, &msg);
		let mut chal_msg = [0u8; HASH_SIZE];
		hash(&mut chal_msg, &s.hashed_chosen_msg);
		try!(recv.read_exact(&mut s.com_msg));

		if choice_bit {
			for ii in 0..chal_msg.len() {
				chal_msg[ii] ^= s.com_msg[ii];
			}
		}
		try!(send.write(&chal_msg));
		Ok(s)
	}

	pub fn open<T:Read>(&mut self, recv: &mut T) -> Result<(),MPECDSAError> {
		let mut msg_0_com = [0u8; HASH_SIZE];
		let mut msg_1_com = [0u8; HASH_SIZE];
		let mut exp_com_msg = [0u8; HASH_SIZE];
		try!(recv.read_exact(&mut msg_0_com));
		try!(recv.read_exact(&mut msg_1_com));
		let chosen_msg_com  = if self.choice_bit { 
			msg_1_com
		} else {
			msg_0_com
		};

		hash(&mut exp_com_msg, &msg_0_com);
		for ii in 0..exp_com_msg.len() {
			self.com_msg[ii] ^= exp_com_msg[ii];
		}
		hash(&mut exp_com_msg, &msg_1_com);

		if vec_eq(&exp_com_msg, &self.com_msg) && vec_eq(&chosen_msg_com, &self.hashed_chosen_msg) {
			Ok(())
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Verification Failed for ROT (sender cheated)")))
		}
	}
}


// for convenience:
pub fn rot_send_batch<T1:Read, T2:Write>(count: usize, rng: &mut Rng, recv:&mut T1, send: &mut T2) -> Result<Vec<([u8;HASH_SIZE],[u8;HASH_SIZE])>,MPECDSAError> {
	let mut bufsend = BufWriter::new(send);
	let mut rotsender = try!(ROTSender::new(rng, &mut bufsend));
	try!(bufsend.flush());

	let mut sender_msgs: Vec<([u8;HASH_SIZE],[u8;HASH_SIZE])> = Vec::with_capacity(count);
	let mut sverifiers: Vec<ROTSendVerifier> = Vec::with_capacity(count);
	for _ in 0..count {
		let (sender_msg_0, sender_msg_1) = try!(rotsender.decode(recv));
		sverifiers.push(try!(ROTSendVerifier::new(sender_msg_0, sender_msg_1, &mut bufsend)));
		sender_msgs.push((sender_msg_0,sender_msg_1));
	}
	try!(bufsend.flush());

	for ii in 0..count {
		try!(sverifiers[ii].open(recv, &mut bufsend));
	}
	try!(bufsend.flush());

	Ok(sender_msgs)
}

pub fn rot_recv_batch<T1:Read, T2:Write>(choice_bits: &[bool], rng: &mut Rng, recv:&mut T1, send: &mut T2) -> Result<Vec<[u8;HASH_SIZE]>,MPECDSAError> {
	let mut bufsend = BufWriter::new(send);
	let mut rotrecver = try!(ROTRecver::new(recv));

	let mut recver_msgs: Vec<[u8;HASH_SIZE]> = Vec::with_capacity(choice_bits.len());
	for ii in 0..choice_bits.len() {
		recver_msgs.push(try!(rotrecver.choose(choice_bits[ii], rng, &mut bufsend)));
	}
	try!(bufsend.flush());

	let mut rverifiers: Vec<ROTRecvVerifier> = Vec::with_capacity(choice_bits.len());
	for ii in 0..choice_bits.len() {
		rverifiers.push(try!(ROTRecvVerifier::new(recver_msgs[ii], choice_bits[ii], recv, &mut bufsend)));
	}
	try!(bufsend.flush());

	for ii in 0..choice_bits.len() {
		try!(rverifiers[ii].open(recv));
	}

	Ok(recver_msgs)
}



#[cfg(test)]
mod tests {
	use super::*;
	use std::io::{Cursor,SeekFrom};
	use std::{thread, time};
	use std::net::{TcpListener, TcpStream};
	use test::Bencher;
	
	const N: usize = 128;

	#[test]
	fn test_rot() {
		let mut comm: Cursor<Vec<u8>> = Cursor::new(Vec::new());
		let mut comm2: Cursor<Vec<u8>> = Cursor::new(Vec::new());
		let mut rng = rand::os::OsRng::new().unwrap();

		let mut rotsender = ROTSender::new(&mut rng, &mut comm).unwrap();
		comm.seek(SeekFrom::Start(0)).unwrap();
		let mut rotrecver = ROTRecver::new(&mut comm).unwrap();
		comm.seek(SeekFrom::Start(0)).unwrap();

		let mut recver_msgs = [[0u8; HASH_SIZE]; N];
		let mut sender_msgs_0 = [[0u8; HASH_SIZE]; N];
		let mut sender_msgs_1 = [[0u8; HASH_SIZE]; N];

		for ii in 0..N {
			recver_msgs[ii] = rotrecver.choose((ii % 2) > 0, &mut rng, &mut comm).unwrap();
		}

		comm.seek(SeekFrom::Start(0)).unwrap();

		for ii in 0..N {
			let (sender_msg_0, sender_msg_1) = rotsender.decode(&mut comm).unwrap();
			sender_msgs_0[ii] = sender_msg_0;
			sender_msgs_1[ii] = sender_msg_1;
			assert!(recver_msgs[ii].eq(if (ii % 2) > 0 {
				&sender_msgs_1[ii][..]
			} else {
				&sender_msgs_0[ii][..]
			}));
			assert!(recver_msgs[ii].ne(if (ii % 2) > 0 {
				&sender_msgs_0[ii][..]
			} else {
				&sender_msgs_1[ii][..]
			}));
		}

		comm.seek(SeekFrom::Start(0)).unwrap();

		let mut sverifiers: Vec<ROTSendVerifier> = Vec::with_capacity(N);
		let mut rverifiers: Vec<ROTRecvVerifier> = Vec::with_capacity(N);

		for ii in 0..N {
			sverifiers.push(ROTSendVerifier::new(sender_msgs_0[ii], sender_msgs_1[ii], &mut comm).unwrap());
			comm.seek(SeekFrom::Start(0)).unwrap();

			rverifiers.push(ROTRecvVerifier::new(recver_msgs[ii], (ii % 2) > 0, &mut comm, &mut comm2).unwrap());
			comm.seek(SeekFrom::Start(0)).unwrap();
			comm2.seek(SeekFrom::Start(0)).unwrap();

			assert!(sverifiers[ii].open(&mut comm2, &mut comm).is_ok());
			comm.seek(SeekFrom::Start(0)).unwrap();
			comm2.seek(SeekFrom::Start(0)).unwrap();

			assert!(rverifiers[ii].open(&mut comm).is_ok());
			comm.seek(SeekFrom::Start(0)).unwrap();
		}
	}

	#[test]
	fn test_rot_net() {
		let child = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let listener = TcpListener::bind("127.0.0.1:4568").unwrap_or_else(|e| { panic!(e) });

			let mut streamrecv = match listener.accept() {
				Ok((stream, _)) => {
					stream
				},
				Err(e) => panic!("couldn't get client: {:?}", e),
			};

			let mut streamsend = streamrecv.try_clone().unwrap();
			let _ = rot_send_batch(N, &mut rng, &mut streamrecv, &mut streamsend).unwrap();
		});

		thread::sleep(time::Duration::from_millis(50));

		let mut rng = rand::thread_rng();
		let mut streamrecv = TcpStream::connect("127.0.0.1:4568").unwrap();
		let mut streamsend = streamrecv.try_clone().unwrap();
		let mut choice_bits: [bool;N] = [false;N];
		for ii in 0..choice_bits.len() {
			choice_bits[ii] = rng.gen();
		}

		let _ = rot_recv_batch(&choice_bits, &mut rng, &mut streamrecv, &mut streamsend).unwrap();

		child.join().unwrap();
	}

	#[bench]
	fn bench_batchrot(b: &mut Bencher) {
		let mut comm: Cursor<Vec<u8>> = Cursor::new(Vec::new());
		let mut comm2: Cursor<Vec<u8>> = Cursor::new(Vec::new());
		let mut rng = rand::os::OsRng::new().unwrap();

		b.iter(|| { 
			let mut rotsender = ROTSender::new(&mut rng, &mut comm).unwrap();
			comm.seek(SeekFrom::Start(0)).unwrap();
			let mut rotrecver = ROTRecver::new(&mut comm).unwrap();
			comm.seek(SeekFrom::Start(0)).unwrap();

			let mut recver_msgs = [[0u8; HASH_SIZE]; N];
			let mut sender_msgs_0 = [[0u8; HASH_SIZE]; N];
			let mut sender_msgs_1 = [[0u8; HASH_SIZE]; N];

			for ii in 0..N {
				recver_msgs[ii] = rotrecver.choose((ii % 2) > 0, &mut rng, &mut comm).unwrap();
			}

			comm.seek(SeekFrom::Start(0)).unwrap();

			for ii in 0..N {
				let (sender_msg_0, sender_msg_1) = rotsender.decode(&mut comm).unwrap();
				sender_msgs_0[ii] = sender_msg_0;
				sender_msgs_1[ii] = sender_msg_1;
			}

			comm.seek(SeekFrom::Start(0)).unwrap();

			let mut sverifiers: Vec<ROTSendVerifier> = Vec::with_capacity(N);
			let mut rverifiers: Vec<ROTRecvVerifier> = Vec::with_capacity(N);

			for ii in 0..N {
				sverifiers.push(ROTSendVerifier::new(sender_msgs_0[ii], sender_msgs_1[ii], &mut comm).unwrap());
				comm.seek(SeekFrom::Start(0)).unwrap();

				rverifiers.push(ROTRecvVerifier::new(recver_msgs[ii], (ii % 2) > 0, &mut comm, &mut comm2).unwrap());
				comm.seek(SeekFrom::Start(0)).unwrap();
				comm2.seek(SeekFrom::Start(0)).unwrap();

				sverifiers[ii].open(&mut comm2, &mut comm).is_ok();
				comm.seek(SeekFrom::Start(0)).unwrap();
				comm2.seek(SeekFrom::Start(0)).unwrap();

				rverifiers[ii].open(&mut comm).is_ok();
				comm.seek(SeekFrom::Start(0)).unwrap();
			}
		});
	}
}