use std::io::prelude::*;
use std::io::{BufWriter};
use std::sync::atomic::{AtomicUsize,Ordering};
use std::env;

use rand::{Rng};

use rayon::prelude::*;

use curves::{ECGroup, Ford, Fq, Secp, SecpOrd, ecdsa, precomp};

use super::mpecdsa_error::*;
use super::zkpok::*;
use super::ote::*;
use super::*;

//#[derive(Clone)]
pub struct Alice2P {
	ote: ote::OTESender,
	ska: SecpOrd,
	pk: Secp,
	pktable: Vec<Secp>,
	sigid: AtomicUsize,
}

//#[derive(Clone)]
pub struct Bob2P {
	ote: ote::OTERecver,
	skb: SecpOrd,
	pk: Secp,
	pktable: Vec<Secp>,
	sigid: AtomicUsize,
}

pub struct ThresholdSigner {
	playerindex: usize,
	threshold: usize,
	ote: Vec<ote::OTEPlayer>,
	poly_point: SecpOrd,
	pk: Secp,
	pktable: Vec<Secp>,
	sigids: Vec<AtomicUsize>,
}

impl Alice2P {
	pub fn new<TR:Read, TW:Write>(ska:&SecpOrd, rng:&mut Rng, recv:&mut TR, send:&mut TW) -> Result<Alice2P, MPECDSAError> {
		
		// commit to PoK-DL for pk_a
		let pka = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &ska).affine();
		let (proofcommitment, proof) = prove_dl_fs_to_com(ska, &pka, rng);
		try!(send.write(&proofcommitment));
		try!(send.flush());

		// recv pk_b
		let mut buf = [0u8; Secp::NBYTES];
		try!(recv.read_exact(&mut buf));
		let pkb: Secp = Secp::from_bytes(&buf);

		// verify PoK-DL for pk_b
		match verify_dl_fs(&pkb, recv) {
			Ok(f) => { if !f { return Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA secret key (bob cheated)"))); } },
			Err(e) => return Err(MPECDSAError::Io(e)),
		};

		// send pk_a
		// open commitment to PoK-DL
		pka.to_bytes(&mut buf);
		try!(send.write(&buf));
		try!(send.write(&proof));
		try!(send.flush());
			
		// calc pk, setup OT exts
		let pk = pkb.scalar_table(&ska).affine();
		let pktable = Secp::precomp_table(&pk);
		let res = Alice2P {
			ote: try!(ote::OTESender::new(rng, recv, send)),
			ska: ska.clone(),
			pk: pk,
			pktable: pktable,
			sigid: AtomicUsize::new(0)
		};

		Ok(res)
	}

	pub fn sign<TR:Read, TW:Write+std::marker::Send>(&self, msg:&[u8], rng:&mut Rng, recv:&mut TR, send:&mut TW) -> Result<(),MPECDSAError> {
		let sigid = self.sigid.fetch_add(1, Ordering::Relaxed);
		let mut bufsend = BufWriter::new(send);

		// precompute things you won't need till later

		// alice's instance key is of a special form for the two round version:
		// k_a = H(k'_a*G)+k'_a
		// this prevents her from choosing the value conveniently
		let kaprime = SecpOrd::rand(rng);
		let kapad = SecpOrd::rand(rng);

		// hash the message
		let mut z = [0; HASH_SIZE];
		hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// online phase

		// recv D_b from bob
		let mut dbraw = [0u8; Secp::NBYTES];
		try!(recv.read_exact(&mut dbraw));
		let db = Secp::from_bytes(&dbraw);
		let dbtable = Secp::precomp_table(&db);

		let rprime = Secp::scalar_table_multi(&dbtable[..],&kaprime).affine();
		let mut rprimeraw = [0u8;Secp::NBYTES];
		rprime.to_bytes(&mut rprimeraw);
		let mut kaoffsetraw = [0u8;HASH_SIZE];
		hash(&mut kaoffsetraw, &rprimeraw);
		let kaoffset = SecpOrd::from_bytes(&kaoffsetraw);
		let ka = kaoffset.add(&kaprime);

		let kai = ka.inv();
		let skai = kai.mul(&self.ska);

		// compute R = k_a*k_b*G, and get the x coordinate
		// do this early to save time later and give bob a chance to start the extensions
		let r = Secp::scalar_table_multi(&dbtable[..],&ka).affine();
		let mut rxb = [0u8; SecpOrd::NBYTES];
		r.x.to_bytes(&mut rxb);
		let rx = SecpOrd::from_bytes(&rxb);
		let r_table = Secp::precomp_table(&r);
		let kapadda = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &ka.mul(&kapad));

		// Prove knowledge of ka for R; hardcoded fiat-shamir so we can do preprocessing
		let kaproof_randcommitted = SecpOrd::rand(rng);
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES];
		let kaproof_randcommitment = Secp::scalar_table_multi(&dbtable[..], &kaproof_randcommitted);
		kaproof_randcommitment.to_bytes(&mut kaproof_buf[Secp::NBYTES..2*Secp::NBYTES]);
		r.to_bytes(&mut kaproof_buf[0..Secp::NBYTES]);
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..2*Secp::NBYTES]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_z = ka.mul(&kaproof_challenge).add(&kaproof_randcommitted);
		kaproof_z.to_bytes(&mut kaproof_buf[2*Secp::NBYTES..]);

		// generate OT extensions for two multiplications (input independent for alice)
		let extensions = try!(self.ote.mul_extend(sigid, 2, recv));

		// end first message (bob to alice)

		// alice sends D'_a = k'_a*G rather than D_a so that bob can check her work
		// she also sends her proof of knowledge for k_a
		try!(bufsend.write(&rprimeraw));
		try!(bufsend.write(&kaproof_buf[Secp::NBYTES..]));
		try!(bufsend.flush());

		// perform two multiplications with 1/k_a and sk_a/k_a.
		let t1a = try!(self.ote.mul_transfer(sigid*2+0, &kai.add(&kapad), &extensions.0[0], &extensions.1, rng, &mut bufsend));
		try!(bufsend.flush());
		let t2a = try!(self.ote.mul_transfer(sigid*2+1, &skai, &extensions.0[1], &extensions.1, rng, &mut bufsend));
		try!(bufsend.flush());

		// compute check value Gamma_1 for alice
		let gamma1 = Secp::op( &Secp::op( &Secp::scalar_table_multi(&r_table[..], &t1a.neg()), &kapadda ), &Secp::gen()).affine();
		let mut gamma1raw = [0u8;Secp::NBYTES];
		gamma1.to_bytes(&mut gamma1raw);
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		kapad.to_bytes(&mut kapadraw);
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		try!(bufsend.write(&kapadraw));
		try!(bufsend.flush());

		// compute signature share m_a for alice
		let mut ma = [0u8;SecpOrd::NBYTES];
		let m_a = t1a.mul(&z).add( &t2a.mul(&rx) );
		m_a.to_bytes(&mut ma);

		// compute check value Gamma_2, and encrypt m_a with H(Gamma_2)
		let t2ag = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2a.neg());
		let t1apk = Secp::scalar_table_multi(&self.pktable[..], &t1a);
		let gamma2 = Secp::op(&t2ag, &t1apk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES];
		gamma2.to_bytes(&mut gamma2raw);
		hash(&mut enckey, &gamma2raw);
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}

		// send encrypted signature share
		try!(bufsend.write(&ma));
		try!(bufsend.flush());

		// end second message (alice to bob)

		Ok(())
	}
}

impl Bob2P {
	pub fn new<TR:Read, TW:Write>(skb:&SecpOrd, rng:&mut Rng, recv:&mut TR, send:&mut TW) -> Result<Bob2P, MPECDSAError> {
		// recv PoK commitment
		let mut proofcommitment = [0u8; 32];
		try!(recv.read_exact( &mut proofcommitment ));

		// send pk_b
		let pkb = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &skb).affine();
		let mut buf = [0u8; Secp::NBYTES];
		pkb.to_bytes(&mut buf);
		try!(send.write(&buf));
		try!(send.flush());
		
		// prove dl for pk_b
		try!(prove_dl_fs(&skb, &pkb, rng, send));

		// recv pk_a
		try!(recv.read_exact(&mut buf));
		let pka: Secp = Secp::from_bytes(&buf);

		// verify PoK to which alice previously committed, then calc pk, setup OT exts
		match verify_dl_fs_with_com(&pka, &proofcommitment, recv) {
			Ok(true) => {
				let pk = pka.scalar_table(&skb).affine();
				let pktable = Secp::precomp_table(&pk);
				let res = Bob2P {
					ote: try!(OTERecver::new(rng, recv, send)),
					skb: skb.clone(),
					pk: pk,
					pktable: pktable,
					sigid: AtomicUsize::new(0)
				};

				Ok(res)            
			},
			Ok(false) => Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA secret key (alice cheated)"))),
			Err(e) =>  Err(MPECDSAError::Io(e)) 
		}
	}

	pub fn sign<TR: Read, TW: Write>(&self, msg:&[u8], rng:&mut Rng, recv: &mut TR, send: &mut TW) -> Result<(SecpOrd, SecpOrd),MPECDSAError> {
		let sigid = self.sigid.fetch_add(1, Ordering::Relaxed);
		let mut bufsend = BufWriter::new(send);

		// no precomputation - we want to begin writing as soon as possible

		// choose k_b, calc D_b = k_b*G, send D_b
		let kb = SecpOrd::rand(rng);
		let db = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kb);
		let mut dbraw = [0u8; Secp::NBYTES];
		db.to_bytes(&mut dbraw);
		try!(bufsend.write(&dbraw));
		try!(bufsend.flush());

		// generate OT extensions for multiplications with 1/k_b and sk_b/k_b
		let kbi  = kb.inv();
		let skbi = kbi.mul(&self.skb);
		let betas = [kbi.clone(), skbi.clone()];
		let extensions = try!(self.ote.mul_encode_and_extend(sigid, &betas, rng, &mut bufsend));
		try!(bufsend.flush());

		// end first message (bob to alice)

		// receive D'_a from alice, calculate D_a as D_a = H(D'_a)*G + D'_a
		let mut rprimeraw = [0u8;Secp::NBYTES];
		try!(recv.read_exact(&mut rprimeraw));
		let rprime = Secp::from_bytes(&rprimeraw);
		let mut kaoffsetraw = [0u8;HASH_SIZE];
		hash(&mut kaoffsetraw, &rprimeraw);
		let kaoffset = SecpOrd::from_bytes(&kaoffsetraw);
		let kbkaoffsetg = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kb.mul(&kaoffset));

		// compute R = k_a*k_b*G, and get the x coordinate
		let r = Secp::op(&kbkaoffsetg, &rprime).affine();
		let mut rxb = [0u8; SecpOrd::NBYTES];
		r.x.to_bytes(&mut rxb);
		let rx = SecpOrd::from_bytes(&rxb);
		let r_table = Secp::precomp_table(&r);

		// verify alice's PoK of k_a for R
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES];
		r.to_bytes(&mut kaproof_buf[0..Secp::NBYTES]);
		try!(recv.read_exact(&mut kaproof_buf[Secp::NBYTES..]));
		let kaproof_randcommitment = Secp::from_bytes(&kaproof_buf[Secp::NBYTES..2*Secp::NBYTES]);
		let kaproof_z = SecpOrd::from_bytes(&kaproof_buf[2*Secp::NBYTES..]);
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..2*Secp::NBYTES]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_lhs = Secp::op(&Secp::scalar_table_multi(&r_table[..], &kaproof_challenge), &kaproof_randcommitment).affine();
		let kaproof_rhs = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kaproof_z.mul(&kb)).affine();
		if kaproof_lhs != kaproof_rhs {
			return Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA signing (alice cheated)")))
		}

		// hash message
		let mut z = [0u8; HASH_SIZE];
		hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// perform multiplications using the extensions we just generated
		let t1b = try!(self.ote.mul_transfer(sigid*2+0, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, recv));
		let gamma1 = Secp::scalar_table_multi(&r_table[..], &t1b).affine(); // start calculating gamma_b early, to give the sender extra time
		let mut gamma1raw = [0u8;Secp::NBYTES];
		gamma1.to_bytes(&mut gamma1raw);
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let t2b = try!(self.ote.mul_transfer(sigid*2+1, &extensions.0[1], &extensions.1, &extensions.2[1], &extensions.3, recv));

		// compute the first check messages Gamma_1, and decrypt the pad
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		try!(recv.read_exact(&mut kapadraw));
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		let kapad = SecpOrd::from_bytes(&kapadraw);

		let t1baug = t1b.sub(&kbi.mul(&kapad));
		let t2bg = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2b);
		let t1bpk = Secp::scalar_table_multi(&self.pktable[..], &t1baug.neg());
		let gamma2 = Secp::op(&t2bg, &t1bpk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES];
		gamma2.to_bytes(&mut gamma2raw);
		hash(&mut enckey, &gamma2raw);

		// compute bob's signature share m_b
		let m_b = t1baug.mul(&z).add( &t2b.mul(&rx));

		// receive alice's signature share m_a, and decrypt using expected key
		let mut ma = [0u8; SecpOrd::NBYTES];
		try!(recv.read_exact(&mut ma));
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}
		let m_a = SecpOrd::from_bytes(&ma);

		// reconstruct signature
		let s = m_a.add( &m_b );

		// end second message (alice to bob)

		// verify signature. Abort if it's incorrect.
		if ecdsa::ecdsa_verify_with_tables(msg, (&rx, &s), &precomp::P256_TABLE, &self.pktable[..]) {
			Ok((rx, s))
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Signature verification failed for ECDSA signing (alice cheated)")))
		}
	}
}

impl ThresholdSigner {
	pub fn new<TR:Read+std::marker::Send+std::marker::Sync, TW:Write+std::marker::Send+std::marker::Sync>(playerindex:usize, threshold:usize, sk_frag:&SecpOrd, rng:&mut Rng, recv:&mut [Option<TR>], send:&mut [Option<TW>]) -> Result<ThresholdSigner, MPECDSAError> {
		if recv.len() != send.len() {
			return Err(MPECDSAError::General);
		}
		let playercount = recv.len();

		// first compute a single public key fragment, and commit to a proof that the secret key is known
		let pk_frag = Secp::scalar_table_multi(&precomp::P256_TABLE, sk_frag);
		let (proofcommitment, proof) = prove_dl_fs_to_com(sk_frag, &pk_frag, rng);
		for ii in 0..playercount {
			if ii != playerindex {
				try!(send[ii].as_mut().unwrap().write(&proofcommitment));
				try!(send[ii].as_mut().unwrap().flush());
			}
		}
		// now collect everyone else's commitments
		let mut othercommitments = vec![[0u8;32];playercount];
		for ii in 0..playercount {
			if ii != playerindex {
				try!(recv[ii].as_mut().unwrap().read_exact(&mut othercommitments[ii]));
			}
		}
		// when all commitments are in, release the proof
		let mut pk_frag_raw = [0u8; Secp::NBYTES];
		pk_frag.to_bytes(&mut pk_frag_raw);
		for ii in 0..playercount {
			if ii != playerindex {
				try!(send[ii].as_mut().unwrap().write(&pk_frag_raw));
				try!(send[ii].as_mut().unwrap().write(&proof));
				try!(send[ii].as_mut().unwrap().flush());
			}
		}
		// and finally verify that the proofs are valid
		let mut pk_frags:Vec<Secp> = Vec::with_capacity(playercount);
		let mut pk = Secp::INF;
		for ii in 0..playercount {
			if ii == playerindex {
				pk_frags.push(pk_frag.clone());
			} else {
				try!(recv[ii].as_mut().unwrap().read_exact(&mut pk_frag_raw));
				let this_pk_frag = Secp::from_bytes(&pk_frag_raw);
				if try!(verify_dl_fs_with_com(&this_pk_frag, &othercommitments[ii], &mut recv[ii].as_mut().unwrap())) {
					pk_frags.push(this_pk_frag);	
				} else {
					return Err(MPECDSAError::Proof(ProofError::new(&format!("Proof of Knowledge failed for player {}'s public key fragment", ii))));
				}
			}
			pk = Secp::op(&pk, &pk_frags[ii]);
		}
		pk = pk.affine();
		

		// Random polynomial for shamir secret sharing.
		// This polynomial represents my secret; we will sum all the polynomials later to sum the secret.
		// Note that we generate k-1 coefficients; the last is the secret
		let mut coefficients:Vec<SecpOrd> = Vec::with_capacity(threshold);
		for _ in 1..threshold {
			coefficients.push(SecpOrd::rand(rng));
		}

		// poly_point will later be our my point on the shared/summed polynomial. Create it early
		// so that the component from my own individual polynomial can be added.
		let mut poly_point = SecpOrd::ZERO;
		// evaluate my polynomial once for each player, and send everyone else their fragment
		for ii in 0..playercount {
			let mut poly_frag = sk_frag.clone();
			for jj in 0..coefficients.len() {
				poly_frag = poly_frag.add(&SecpOrd::from_native((ii+1).pow((jj+1) as u32) as u64).mul(&coefficients[jj]));
			}
			if ii == playerindex {
				poly_point = poly_frag;
			} else {
				let mut poly_frag_raw = [0u8;SecpOrd::NBYTES];
				poly_frag.to_bytes(&mut poly_frag_raw);
				try!(send[ii].as_mut().unwrap().write(&poly_frag_raw));
				try!(send[ii].as_mut().unwrap().flush());
			}
		}

		// recieve polynomial fragments from each player, and sum them to find my point on the shared/summed polynomial
		for ii in 0..playercount {
			if ii != playerindex {
				let mut poly_frag_raw = [0u8;SecpOrd::NBYTES];
				try!(recv[ii].as_mut().unwrap().read(&mut poly_frag_raw));
				let poly_frag = SecpOrd::from_bytes(&poly_frag_raw);
				poly_point = poly_point.add(&poly_frag);
			}
		}

		// calculate p(playerindex)*G, an EC point with my polynomial point in the exponent, and broadcast it to everyone
		let point_com = Secp::scalar_table_multi(&precomp::P256_TABLE, &poly_point);
		let mut point_com_raw = [0u8; Secp::NBYTES];
		point_com.to_bytes(&mut point_com_raw);
		for ii in 0..playercount {
			if ii != playerindex {
				try!(send[ii].as_mut().unwrap().write(&point_com_raw));
				try!(send[ii].as_mut().unwrap().flush());
			}
		}

		// receive commitments to everyone's polynomial points
		let mut points_com:Vec<Secp> = Vec::with_capacity(playercount);
		for ii in 0..playercount {
			if ii == playerindex {
				points_com.push(point_com);
			} else {
				try!(recv[ii].as_mut().unwrap().read_exact(&mut point_com_raw));
				points_com.push(Secp::from_bytes(&point_com_raw));
			}
		}

		// for each contiguous set of parties, perform shamir reconsruction in the exponent and check the result against the known pk
		for ii in 0..(playercount-threshold) {
			let mut recon_sum = Secp::INF;
			for jj in 0..threshold {
				let mut coef = SecpOrd::ONE;
				// calculate lagrange coefficient
				for kk in 0..threshold {
					if kk != jj {
						coef = coef.mul(&SecpOrd::from_native((ii+kk+1) as u64));
						coef = coef.mul(&(SecpOrd::from_native((ii+kk+1) as u64).sub(&SecpOrd::from_native((ii+jj+1) as u64))).inv());
					}
				}
				let recon_frag = points_com[ii+jj].scalar_table(&coef);
				recon_sum = Secp::op(&recon_sum, &recon_frag);
			}
			recon_sum = recon_sum.affine();
			if recon_sum != pk {
				return Err(MPECDSAError::Proof(ProofError::new("Verification failed for public key reconstruction")));
			}
		}

		// finally, each pair of parties must have OTE setup between them. The player with the higher index is always Bob.
		let mut rngs = Vec::with_capacity(playercount);
		for _ in 0..playercount {
			let mut newrng = rand::ChaChaRng::new_unseeded();
			newrng.set_counter(rng.next_u64(), rng.next_u64());
			rngs.push(newrng);
		}

		let threadcount = match env::var_os("RAYON_NUM_THREADS") {
		    Some(val) => val.into_string().unwrap().parse().unwrap(),
    		None => playercount
		};

		let rayonpool = rayon::ThreadPoolBuilder::new().num_threads(threadcount).build().unwrap();
		let otevec = rayonpool.install(|| { send.par_iter_mut().zip(recv.par_iter_mut()).zip(rngs.par_iter_mut()).enumerate().map(|(ii, ((sendi, recvi), rngi))| {
			if ii > playerindex {
				OTEPlayer::Sender(ote::OTESender::new(rngi, recvi.as_mut().unwrap(), sendi.as_mut().unwrap()).unwrap())
			} else if ii < playerindex {
				OTEPlayer::Recver(ote::OTERecver::new(rngi, recvi.as_mut().unwrap(), sendi.as_mut().unwrap()).unwrap())
			} else {
				OTEPlayer::Null
			}
		}).collect() });

		let mut sigids = Vec::with_capacity(playercount);
		for _ in 0..playercount {
			sigids.push(AtomicUsize::new(0));
		}
 
 		let pktable = Secp::precomp_table(&pk);
		Ok(ThresholdSigner {
			playerindex: playerindex,
			threshold: threshold,
			ote: otevec,
			poly_point: poly_point,
			pk: pk,
			pktable: pktable,
			sigids: sigids,
		})
	}

	pub fn sign<TR:Read, TW:Write+std::marker::Send>(&self, counterparties: &[usize], msg:&[u8], rng:&mut Rng, recv:&mut TR, send:&mut TW) -> Result<Option<(SecpOrd, SecpOrd)>,MPECDSAError> {
		if counterparties.len() != (self.threshold-1) {
			return Err(MPECDSAError::General);
		}

		if self.threshold == 2 {
			let counterparty = counterparties[0];
			if self.playerindex > counterparty {
				return Ok(Some(try!(self.sign2t_bob(counterparty, msg, rng, recv, send))));
			} else if self.playerindex < counterparty {
				try!(self.sign2t_alice(counterparty, msg, rng, recv, send));
				return Ok(None);
			} else {
				return Err(MPECDSAError::General);
			}
		} else {
			return Err(MPECDSAError::General);
		}
	}

	fn sign2t_alice<TR:Read, TW:Write+std::marker::Send>(&self, counterparty: usize, msg:&[u8], rng:&mut Rng, recv:&mut TR, send:&mut TW) -> Result<(),MPECDSAError> {
		let sigid = self.sigids[counterparty].fetch_add(1, Ordering::Relaxed);
		let mut bufsend = BufWriter::new(send);

		// precompute things you won't need till later

		// alice's instance key is of a special form for the two round version:
		// k_a = H(k'_a*G)+k'_a
		// this prevents her from choosing the value conveniently
		let kaprime = SecpOrd::rand(rng);
		let kapad = SecpOrd::rand(rng);

		// hash the message
		let mut z = [0; HASH_SIZE];
		hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// calculate lagrange coefficient
		let mut coef = SecpOrd::from_native((counterparty+1) as u64);
		coef = coef.mul(&(SecpOrd::from_native((counterparty+1) as u64).sub(&SecpOrd::from_native((self.playerindex+1) as u64))).inv());
		let t0a = coef.mul(&self.poly_point);

		let ote = match self.ote[counterparty] {
			OTEPlayer::Sender(ref ote) => ote,
			_ => return Err(MPECDSAError::General)
		};

		// online phase

		// recv D_b from bob
		let mut dbraw = [0u8; Secp::NBYTES];
		try!(recv.read_exact(&mut dbraw));
		let db = Secp::from_bytes(&dbraw);
		let dbtable = Secp::precomp_table(&db);

		let rprime = Secp::scalar_table_multi(&dbtable[..],&kaprime).affine();
		let mut rprimeraw = [0u8;Secp::NBYTES];
		rprime.to_bytes(&mut rprimeraw);
		let mut kaoffsetraw = [0u8;HASH_SIZE];
		hash(&mut kaoffsetraw, &rprimeraw);
		let kaoffset = SecpOrd::from_bytes(&kaoffsetraw);
		let ka = kaoffset.add(&kaprime);

		let kai = ka.inv();
		let t0ai = kai.mul(&t0a);

		// compute R = k_a*k_b*G, and get the x coordinate
		// do this early to save time later and give bob a chance to start the extensions
		let r = Secp::scalar_table_multi(&dbtable[..],&ka).affine();
		let mut rxb = [0u8; SecpOrd::NBYTES];
		r.x.to_bytes(&mut rxb);
		let rx = SecpOrd::from_bytes(&rxb);
		let r_table = Secp::precomp_table(&r);
		let kapadda = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &ka.mul(&kapad));

		// Prove knowledge of ka for R; hardcoded fiat-shamir so we can do preprocessing
		let kaproof_randcommitted = SecpOrd::rand(rng);
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES];
		let kaproof_randcommitment = Secp::scalar_table_multi(&dbtable[..], &kaproof_randcommitted);
		kaproof_randcommitment.to_bytes(&mut kaproof_buf[Secp::NBYTES..2*Secp::NBYTES]);
		r.to_bytes(&mut kaproof_buf[0..Secp::NBYTES]);
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..2*Secp::NBYTES]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_z = ka.mul(&kaproof_challenge).add(&kaproof_randcommitted);
		kaproof_z.to_bytes(&mut kaproof_buf[2*Secp::NBYTES..]);

		// generate OT extensions for two multiplications (input independent for alice)
		let extensions = try!(ote.mul_extend(sigid, 2, recv));

		// end first message (bob to alice)

		// alice sends D'_a = k'_a*G rather than D_a so that bob can check her work
		try!(bufsend.write(&rprimeraw));
		try!(bufsend.write(&kaproof_buf[Secp::NBYTES..]));
		try!(bufsend.flush());

		// perform two multiplications with 1/k_a and sk_a/k_a.
		// perform two multiplications with 1/k_a and sk_a/k_a.
		let t1a = try!(ote.mul_transfer(sigid*3+0, &kai.add(&kapad), &extensions.0[0], &extensions.1, rng, &mut bufsend));
		try!(bufsend.flush());
		let t2aa = try!(ote.mul_transfer(sigid*3+1, &t0ai, &extensions.0[0], &extensions.1, rng, &mut bufsend));
		try!(bufsend.flush());
		let t2ba = try!(ote.mul_transfer(sigid*3+2, &kai, &extensions.0[1], &extensions.1, rng, &mut bufsend));
		try!(bufsend.flush());
		let t2a = t2aa.add(&t2ba);

		// compute check value Gamma_1 for alice
		let gamma1 = Secp::op( &Secp::op( &Secp::scalar_table_multi(&r_table[..], &t1a.neg()), &kapadda ), &Secp::gen()).affine();
		let mut gamma1raw = [0u8;Secp::NBYTES];
		gamma1.to_bytes(&mut gamma1raw);
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		kapad.to_bytes(&mut kapadraw);
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		try!(bufsend.write(&kapadraw));
		try!(bufsend.flush());

		// compute signature share m_a for alice
		let mut ma = [0u8;SecpOrd::NBYTES];
		let m_a = t1a.mul(&z).add( &t2a.mul(&rx) );
		m_a.to_bytes(&mut ma);

		// compute check value Gamma_2, and encrypt m_a with H(Gamma_2)
		let t2ag = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2a.neg());
		let t1apk = Secp::scalar_table_multi(&self.pktable[..], &t1a);
		let gamma2 = Secp::op(&t2ag, &t1apk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES];
		gamma2.to_bytes(&mut gamma2raw);
		hash(&mut enckey, &gamma2raw);
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}

		// send encrypted signature share
		try!(bufsend.write(&ma));
		try!(bufsend.flush());

		// end second message (alice to bob)

		Ok(())
	}

	fn sign2t_bob <TR: Read, TW: Write>(&self, counterparty: usize, msg:&[u8], rng:&mut Rng, recv: &mut TR, send: &mut TW) -> Result<(SecpOrd, SecpOrd),MPECDSAError> {
		let sigid = self.sigids[counterparty].fetch_add(1, Ordering::Relaxed);
		let mut bufsend = BufWriter::new(send);

		let ote = match self.ote[counterparty] {
			OTEPlayer::Recver(ref ote) => ote,
			_ => return Err(MPECDSAError::General)
		};
		// no precomputation - we want to begin writing as soon as possible

		// choose k_b, calc D_b = k_b*G, send D_b
		let kb = SecpOrd::rand(rng);
		let db = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kb);
		let mut dbraw = [0u8; Secp::NBYTES];
		db.to_bytes(&mut dbraw);
		try!(bufsend.write(&dbraw));
		try!(bufsend.flush());

		// calculate lagrange coefficient
		let mut coef = SecpOrd::from_native((counterparty+1) as u64);
		coef = coef.mul(&(SecpOrd::from_native((counterparty+1) as u64).sub(&SecpOrd::from_native((self.playerindex+1) as u64))).inv());
		let t0b = coef.mul(&self.poly_point);

		// generate OT extensions for multiplications with 1/k_b and sk_b/k_b
		let kbi  = kb.inv();
		let t0bi = kbi.mul(&t0b);
		let betas = [kbi.clone(), t0bi.clone()];
		let extensions = try!(ote.mul_encode_and_extend(sigid, &betas, rng, &mut bufsend));
		try!(bufsend.flush());

		// end first message (bob to alice)

		// receive D'_a from alice, calculate D_a as D_a = H(D'_a)*G + D'_a
		let mut rprimeraw = [0u8;Secp::NBYTES];
		try!(recv.read_exact(&mut rprimeraw));
		let rprime = Secp::from_bytes(&rprimeraw);
		let mut kaoffsetraw = [0u8;HASH_SIZE];
		hash(&mut kaoffsetraw, &rprimeraw);
		let kaoffset = SecpOrd::from_bytes(&kaoffsetraw);
		let kbkaoffsetg = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kb.mul(&kaoffset));

		// compute R = k_a*k_b*G, and get the x coordinate
		let r = Secp::op(&kbkaoffsetg, &rprime).affine();
		let mut rxb = [0u8; SecpOrd::NBYTES];
		r.x.to_bytes(&mut rxb);
		let rx = SecpOrd::from_bytes(&rxb);
		let r_table = Secp::precomp_table(&r);

		// verify alice's PoK of k_a for R
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES];
		r.to_bytes(&mut kaproof_buf[0..Secp::NBYTES]);
		try!(recv.read_exact(&mut kaproof_buf[Secp::NBYTES..]));
		let kaproof_randcommitment = Secp::from_bytes(&kaproof_buf[Secp::NBYTES..2*Secp::NBYTES]);
		let kaproof_z = SecpOrd::from_bytes(&kaproof_buf[2*Secp::NBYTES..]);
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..2*Secp::NBYTES]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_lhs = Secp::op(&Secp::scalar_table_multi(&r_table[..], &kaproof_challenge), &kaproof_randcommitment).affine();
		let kaproof_rhs = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kaproof_z.mul(&kb)).affine();
		if kaproof_lhs != kaproof_rhs {
			return Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA signing (alice cheated)")))
		}

		// hash message
		let mut z = [0u8; HASH_SIZE];
		hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// perform multiplications using the extensions we just generated
		let t1b = try!(ote.mul_transfer(sigid*3+0, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, recv));
		let gamma1 = Secp::scalar_table_multi(&r_table[..], &t1b).affine(); // start calculating gamma_b early, to give the sender extra time
		let mut gamma1raw = [0u8;Secp::NBYTES];
		gamma1.to_bytes(&mut gamma1raw);
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let t2ab = try!(ote.mul_transfer(sigid*3+1, &extensions.0[0], &extensions.1, &extensions.2[0], &extensions.3, recv));
		let t2bb = try!(ote.mul_transfer(sigid*3+2, &extensions.0[1], &extensions.1, &extensions.2[1], &extensions.3, recv));
		let t2b = t2ab.add(&t2bb);

		// compute the first check messages Gamma_1, and decrypt the pad
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		try!(recv.read_exact(&mut kapadraw));
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		let kapad = SecpOrd::from_bytes(&kapadraw);

		let t1baug = t1b.sub(&kbi.mul(&kapad));
		let t2bg = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2b);
		let t1bpk = Secp::scalar_table_multi(&self.pktable[..], &t1baug.neg());
		let gamma2 = Secp::op(&t2bg, &t1bpk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES];
		gamma2.to_bytes(&mut gamma2raw);
		hash(&mut enckey, &gamma2raw);

		// compute bob's signature share m_b
		let m_b = t1baug.mul(&z).add( &t2b.mul(&rx));

		// receive alice's signature share m_a, and decrypt using expected key
		let mut ma = [0u8; SecpOrd::NBYTES];
		try!(recv.read_exact(&mut ma));
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}
		let m_a = SecpOrd::from_bytes(&ma);

		// reconstruct signature
		let s = m_a.add( &m_b );

		// end second message (alice to bob)

		// verify signature. Abort if it's incorrect.
		if ecdsa::ecdsa_verify_with_tables(msg, (&rx, &s), &precomp::P256_TABLE, &self.pktable[..]) {
			Ok((rx, s))
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Signature verification failed for ECDSA signing (alice cheated)")))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{thread, time};
	use std::net::{TcpListener, TcpStream};
	use test::Bencher;

	#[test]
	fn test_ecdsa_2psign() {
		let msg = "The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);

		let thandle = thread::spawn(move || {
			let listener = match TcpListener::bind("127.0.0.1:12347") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}",e),
			};
			let (mut streamrecv, _) = listener.accept().unwrap();
			let mut streamsend = streamrecv.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let bob = Bob2P::new(&skb,&mut rng, &mut streamrecv, &mut streamsend);
			if bob.is_err() {
				return Err(bob.err().unwrap());
			}
			let bob = bob.unwrap();
			

			let mut results = Vec::with_capacity(10);
			for _ in 0..10 {
				results.push(bob.sign(&msg, &mut rng, &mut streamrecv, &mut streamsend));
			}

			Ok(results)
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(50)); 

		let mut streamsend = match TcpStream::connect("127.0.0.1:12347") {
			Ok(l) => l,
			Err(e) => panic!("Alice err: {:?}", e),
		};
		let mut streamrecv = streamsend.try_clone().unwrap();

		let alice = Alice2P::new(&ska, &mut rng, &mut streamrecv, &mut streamsend);
		assert!(alice.is_ok());
		let alice = alice.unwrap();
		let mut aliceresults = Vec::with_capacity(10);
		for _ in 0..10 {
			aliceresults.push(alice.sign(&msg, &mut rng, &mut streamrecv, &mut streamsend));
		}

		let bobresults = thandle.join().unwrap();
		assert!(bobresults.is_ok());
		let bobresults = bobresults.unwrap();
		for ii in 0..10 {
			assert!(aliceresults[ii].is_ok());
			assert!(bobresults[ii].is_ok());
		}
	}

	#[test]
	fn test_ecdsa_3p2tsetup() {
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);
		let skc = SecpOrd::rand(&mut rng);

		let pk = Secp::gen().scalar_table(&ska.add(&skb).add(&skc));

		let thandlec = thread::spawn(move || {
			let alicelistener = match TcpListener::bind("127.0.0.1:12456") {
				Ok(l) => l,
				Err(e) => panic!("Charlie err: {:?}",e),
			};
			let (mut alicerecv, _) = alicelistener.accept().unwrap();
			let mut alicesend = alicerecv.try_clone().unwrap();
			let boblistener = match TcpListener::bind("127.0.0.1:12457") {
				Ok(l) => l,
				Err(e) => panic!("Charlie err: {:?}",e),
			};
			let (mut bobrecv, _) = boblistener.accept().unwrap();
			let mut bobsend = bobrecv.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let charlie = ThresholdSigner::new(2, 2, &skc, &mut rng, &mut [Some(&mut alicerecv),Some(&mut bobrecv),None], &mut [Some(&mut alicesend),Some(&mut bobsend),None]);
			charlie
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let thandleb = thread::spawn(move || {
			let alicelistener = match TcpListener::bind("127.0.0.1:12458") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}",e),
			};
			let (mut alicerecv, _) = alicelistener.accept().unwrap();
			let mut alicesend = alicerecv.try_clone().unwrap();
			let mut charliesend = match TcpStream::connect("127.0.0.1:12457") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}", e),
			};
			let mut charlierecv = charliesend.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let bob = ThresholdSigner::new(1, 2, &skb, &mut rng, &mut [Some(&mut alicerecv),None,Some(&mut charlierecv)], &mut [Some(&mut alicesend),None,Some(&mut charliesend)]);
			bob
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let thandlea = thread::spawn(move || {
			let mut charliesend = match TcpStream::connect("127.0.0.1:12456") {
				Ok(l) => l,
				Err(e) => panic!("Alice err: {:?}", e),
			};
			let mut charlierecv = charliesend.try_clone().unwrap();

			let mut bobsend = match TcpStream::connect("127.0.0.1:12458") {
				Ok(l) => l,
				Err(e) => panic!("Alice err: {:?}", e),
			};
			let mut bobrecv = bobsend.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let alice = ThresholdSigner::new(0, 2, &ska, &mut rng, &mut [None,Some(&mut bobrecv),Some(&mut charlierecv)], &mut [None,Some(&mut bobsend),Some(&mut charliesend)]);
			alice
		});

		let alice = thandlea.join().unwrap();
		assert!(alice.is_ok());
		let bob = thandleb.join().unwrap();
		assert!(bob.is_ok());
		let charlie = thandlec.join().unwrap();
		assert!(charlie.is_ok());
		assert_eq!(alice.unwrap().pk, pk);
		assert_eq!(bob.unwrap().pk, pk);
		assert_eq!(charlie.unwrap().pk, pk);
	}

	#[test]
	fn test_ecdsa_3p2tsign() {
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);
		let skc = SecpOrd::rand(&mut rng);

		let thandlec = thread::spawn(move || {
			let alicelistener = match TcpListener::bind("127.0.0.1:12756") {
				Ok(l) => l,
				Err(e) => panic!("Charlie err: {:?}",e),
			};
			let (mut alicerecv, _) = alicelistener.accept().unwrap();
			let mut alicesend = alicerecv.try_clone().unwrap();
			let boblistener = match TcpListener::bind("127.0.0.1:12757") {
				Ok(l) => l,
				Err(e) => panic!("Charlie err: {:?}",e),
			};
			let (mut bobrecv, _) = boblistener.accept().unwrap();
			let mut bobsend = bobrecv.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let charlie = ThresholdSigner::new(2, 2, &skc, &mut rng, &mut [Some(&mut alicerecv),Some(&mut bobrecv),None], &mut [Some(&mut alicesend),Some(&mut bobsend),None]).unwrap();
			let result1 = charlie.sign(&[0], &"etaoin shrdlu".as_bytes(), &mut rng, &mut alicerecv, &mut alicesend);
			let result2 = charlie.sign(&[1], &"Lorem ipsum dolor sit amet".as_bytes(), &mut rng, &mut bobrecv, &mut bobsend);
			(result1, result2)
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let thandleb = thread::spawn(move || {
			let alicelistener = match TcpListener::bind("127.0.0.1:12758") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}",e),
			};
			let (mut alicerecv, _) = alicelistener.accept().unwrap();
			let mut alicesend = alicerecv.try_clone().unwrap();
			let mut charliesend = match TcpStream::connect("127.0.0.1:12757") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}", e),
			};
			let mut charlierecv = charliesend.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let bob = ThresholdSigner::new(1, 2, &skb, &mut rng, &mut [Some(&mut alicerecv),None,Some(&mut charlierecv)], &mut [Some(&mut alicesend),None,Some(&mut charliesend)]).unwrap();
			let result1 = bob.sign(&[0], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &mut rng, &mut alicerecv, &mut alicesend);
			let result2 = bob.sign(&[2], &"Lorem ipsum dolor sit amet".as_bytes(), &mut rng, &mut charlierecv, &mut charliesend);
			(result1, result2)
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let thandlea = thread::spawn(move || {
			let mut charliesend = match TcpStream::connect("127.0.0.1:12756") {
				Ok(l) => l,
				Err(e) => panic!("Alice err: {:?}", e),
			};
			let mut charlierecv = charliesend.try_clone().unwrap();

			let mut bobsend = match TcpStream::connect("127.0.0.1:12758") {
				Ok(l) => l,
				Err(e) => panic!("Alice err: {:?}", e),
			};
			let mut bobrecv = bobsend.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let alice = ThresholdSigner::new(0, 2, &ska, &mut rng, &mut [None,Some(&mut bobrecv),Some(&mut charlierecv)], &mut [None,Some(&mut bobsend),Some(&mut charliesend)]).unwrap();
			let result1 = alice.sign(&[1], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &mut rng, &mut bobrecv, &mut bobsend);
			let result2 = alice.sign(&[2], &"etaoin shrdlu".as_bytes(), &mut rng, &mut charlierecv, &mut charliesend);
			(result1, result2)
		});

		let alice = thandlea.join().unwrap();
		assert!(alice.0.is_ok());
		assert!(alice.1.is_ok());
		let bob = thandleb.join().unwrap();
		assert!(bob.0.is_ok());
		assert!(bob.1.is_ok());
		let charlie = thandlec.join().unwrap();
		assert!(charlie.0.is_ok());
		assert!(charlie.1.is_ok());
	}

	#[test]
	fn test_ecdsa_7p4tsetup() {
		let mut rng = rand::thread_rng();
		let threshold = 4;
		let parties = 7;
		let mut skvec: Vec<SecpOrd> = Vec::with_capacity(parties);
		let mut sksum = SecpOrd::ZERO;
		for ii in 0..parties {
			skvec.push(SecpOrd::rand(&mut rng));
			sksum = sksum.add(&skvec[ii]);
		}
		let pk = Secp::scalar_gen(&sksum).affine();

		let mut thandles = Vec::with_capacity(parties);
		for ii in (0..parties).rev() {
			thread::sleep(time::Duration::from_millis(100)); 
			let ski = skvec[ii].clone();
			thandles.push(thread::spawn(move || {
				let mut sendvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
				let mut recvvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
				for jj in (0..parties).rev() {
					if jj < ii {
						let listener = TcpListener::bind(format!("127.0.0.1:4{:02}{:02}", ii, jj)).unwrap();
						let (mut recv, _) = listener.accept().unwrap();
						let mut send = recv.try_clone().unwrap();
						sendvec.push(Some(send));
						recvvec.push(Some(recv));
					} else if jj > ii {
						let mut send = TcpStream::connect(format!("127.0.0.1:4{:02}{:02}", jj, ii)).unwrap();
						let mut recv = send.try_clone().unwrap();
						sendvec.push(Some(send));
						recvvec.push(Some(recv));
					} else {
						sendvec.push(None);
						recvvec.push(None);
					}
				}
				let mut rng = rand::thread_rng();
				sendvec.reverse();
				recvvec.reverse();
				ThresholdSigner::new(ii, threshold, &ski, &mut rng, sendvec.as_mut_slice(), recvvec.as_mut_slice())
			}));
		}

		for handle in thandles {
			let signer = handle.join().unwrap();
			assert!(signer.is_ok());
			assert_eq!(signer.unwrap().pk, pk);
		}
	}

	#[bench]
	fn bench_ecdsa_2psign(b: &mut Bencher) -> () {
		let msg = "The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);

		let thandle = thread::spawn(move || {
			let listener = TcpListener::bind("127.0.0.1:12348").expect("Bob failed to bind");
			let (mut streamrecv, _) = listener.accept().expect("Bob failed to listen");
			let mut streamsend = streamrecv.try_clone().expect("Bob failed to clone stream");
			streamsend.set_nodelay(true).expect("Bob failed to set nodelay");
			streamrecv.set_nodelay(true).expect("Bob failed to set nodelay");

			let mut rng = rand::thread_rng();
			let bob = Bob2P::new(&skb,&mut rng, &mut streamrecv, &mut streamsend).expect("Failed to instantiate Bob");
			
			let mut keepgoing = [1u8; 1];

			streamrecv.read_exact(&mut keepgoing).expect("Bob failed to read (1)");
			while keepgoing[0] > 0 {
				bob.sign(&msg, &mut rng, &mut streamrecv, &mut streamsend).expect("Bob failed to sign");
				streamrecv.read_exact(&mut keepgoing).expect("Bob failed to read (2)");
			}
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let mut streamsend = TcpStream::connect("127.0.0.1:12348").expect("Alice failed to connect");
		let mut streamrecv = streamsend.try_clone().expect("Alice failed to clone stream");
		streamsend.set_nodelay(true).expect("Alice failed to set nodelay");
		streamrecv.set_nodelay(true).expect("Alice failed to set nodelay");

		let alice = Alice2P::new(&ska,&mut rng, &mut streamrecv, &mut streamsend).expect("Failed to instantiate Alice");
		b.iter(|| { 
			streamsend.write(&[1]).expect("Alice failed to write (1)");
			streamsend.flush().expect("Alice failed to flush");
			alice.sign(&msg, &mut rng, &mut streamrecv, &mut streamsend).expect("Bob failed to sign");
		});
		streamsend.write(&[0]).expect("Alice failed to write (2)");
		streamsend.flush().expect("Alice failed to flush");

		thandle.join().unwrap();
	}

	#[bench]
	fn bench_ecdsa_3p2tsetup(b: &mut Bencher) -> () {
		let mut rng = rand::thread_rng();
		let threshold = 2;
		let parties = 3;
		let mut skvec: Vec<SecpOrd> = Vec::with_capacity(parties);
		for _ in 0..parties {
			skvec.push(SecpOrd::rand(&mut rng));
		}

		let mut thandles = Vec::with_capacity(parties);
		for ii in (1..parties).rev() {
			thread::sleep(time::Duration::from_millis(100)); 
			let ski = skvec[ii].clone();
			thandles.push(thread::spawn(move || {
				let mut sendvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
				let mut recvvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
				for jj in (0..parties).rev() {
					if jj < ii {
						let listener = TcpListener::bind(format!("127.0.0.1:3{:02}{:02}", ii, jj)).unwrap();
						let (mut recv, _) = listener.accept().unwrap();
						let mut send = recv.try_clone().unwrap();
						sendvec.push(Some(send));
						recvvec.push(Some(recv));
					} else if jj > ii {
						let mut send = TcpStream::connect(format!("127.0.0.1:3{:02}{:02}", jj, ii)).unwrap();
						let mut recv = send.try_clone().unwrap();
						sendvec.push(Some(send));
						recvvec.push(Some(recv));
					} else {
						sendvec.push(None);
						recvvec.push(None);
					}
				}
				let mut rng = rand::thread_rng();
				sendvec.reverse();
				recvvec.reverse();

				let mut keepgoing = [1u8; 1];
				recvvec[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (1)", ii));
				while keepgoing[0] > 0 {
					ThresholdSigner::new(ii, threshold, &ski, &mut rng, sendvec.as_mut_slice(), recvvec.as_mut_slice()).expect(&format!("Party {} failed to setup", ii));
					recvvec[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (2)", ii));
				}
			}));
		}

		thread::sleep(time::Duration::from_millis(100)); 

		let ski = skvec[0].clone();
		let mut sendvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
		let mut recvvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
		for jj in (1..parties).rev() {
			let mut send = TcpStream::connect(format!("127.0.0.1:3{:02}00", jj)).unwrap();
			let mut recv = send.try_clone().unwrap();
			sendvec.push(Some(send));
			recvvec.push(Some(recv));
		}
		sendvec.push(None);
		recvvec.push(None);
		sendvec.reverse();
		recvvec.reverse();
		b.iter(|| { 
			for ii in 1..parties {
				sendvec[ii].as_mut().unwrap().write(&[1]).expect("Party 0 failed to write (1)");
				sendvec[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
			}
			ThresholdSigner::new(0, threshold, &ski, &mut rng, sendvec.as_mut_slice(), recvvec.as_mut_slice()).expect("Party 0 failed to setup");
		});
		for ii in 1..parties {
			sendvec[ii].as_mut().unwrap().write(&[0]).expect("Party 0 failed to write (2)");
			sendvec[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
		}
		for handle in thandles {
			handle.join().unwrap();
		}	
	}

	#[bench]
	fn bench_ecdsa_3p2tsign(b: &mut Bencher) -> () {
		let msg = "The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);
		let skc = SecpOrd::rand(&mut rng);

		let thandlec = thread::spawn(move || {
			let alicelistener = match TcpListener::bind("127.0.0.1:12856") {
				Ok(l) => l,
				Err(e) => panic!("Charlie err: {:?}",e),
			};
			let (mut alicerecv, _) = alicelistener.accept().unwrap();
			let mut alicesend = alicerecv.try_clone().unwrap();
			let boblistener = match TcpListener::bind("127.0.0.1:12857") {
				Ok(l) => l,
				Err(e) => panic!("Charlie err: {:?}",e),
			};
			let (mut bobrecv, _) = boblistener.accept().unwrap();
			let mut bobsend = bobrecv.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let charlie = ThresholdSigner::new(2, 2, &skc, &mut rng, &mut [Some(&mut alicerecv),Some(&mut bobrecv),None], &mut [Some(&mut alicesend),Some(&mut bobsend),None]).unwrap();
			charlie.sign(&[0], &"etaoin shrdlu".as_bytes(), &mut rng, &mut alicerecv, &mut alicesend).unwrap();
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let thandleb = thread::spawn(move || {
			let alicelistener = match TcpListener::bind("127.0.0.1:12858") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}",e),
			};
			let (mut alicerecv, _) = alicelistener.accept().unwrap();
			let mut alicesend = alicerecv.try_clone().unwrap();
			let mut charliesend = match TcpStream::connect("127.0.0.1:12857") {
				Ok(l) => l,
				Err(e) => panic!("Bob err: {:?}", e),
			};
			let mut charlierecv = charliesend.try_clone().unwrap();
			let mut rng = rand::thread_rng();
			let bob = ThresholdSigner::new(1, 2, &skb, &mut rng, &mut [Some(&mut alicerecv),None,Some(&mut charlierecv)], &mut [Some(&mut alicesend),None,Some(&mut charliesend)]).unwrap();
			let mut keepgoing = [1u8; 1];
			alicerecv.read_exact(&mut keepgoing).expect("Bob failed to read (1)");
			while keepgoing[0] > 0 {
				bob.sign(&[0], &msg, &mut rng, &mut alicerecv, &mut alicesend).expect("Bob failed to sign");
				alicerecv.read_exact(&mut keepgoing).expect("Bob failed to read (2)");
			}
		});

		// wait a little time for the listener to start
		thread::sleep(time::Duration::from_millis(100)); 

		let mut charliesend = match TcpStream::connect("127.0.0.1:12856") {
			Ok(l) => l,
			Err(e) => panic!("Alice err: {:?}", e),
		};
		let mut charlierecv = charliesend.try_clone().unwrap();

		let mut bobsend = match TcpStream::connect("127.0.0.1:12858") {
			Ok(l) => l,
			Err(e) => panic!("Alice err: {:?}", e),
		};
		let mut bobrecv = bobsend.try_clone().unwrap();
		let alice = ThresholdSigner::new(0, 2, &ska, &mut rng, &mut [None,Some(&mut bobrecv),Some(&mut charlierecv)], &mut [None,Some(&mut bobsend),Some(&mut charliesend)]).unwrap();
		alice.sign(&[2], &"etaoin shrdlu".as_bytes(), &mut rng, &mut charlierecv, &mut charliesend).unwrap();
		thandlec.join().unwrap();
			
		b.iter(|| { 
			bobsend.write(&[1]).expect("Alice failed to write (1)");
			bobsend.flush().expect("Alice failed to flush");
			alice.sign(&[1], &msg, &mut rng, &mut bobrecv, &mut bobsend).expect("Alice failed to sign");
		});
		bobsend.write(&[0]).expect("Alice failed to write (2)");
		bobsend.flush().expect("Alice failed to flush");
		thandleb.join().unwrap();
	}
}