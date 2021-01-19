/***********
 * This module implements the two-party ECDSA protocols
 * described in the paper "Secure Two-party Threshold ECDSA from ECDSA Assumptions"
 * by Doerner, Kondi, Lee, and shelat (https://eprint.iacr.org/2018/499)
 * 
 * It also implements the multi-party ECDSA protocols
 * described in the paper "Threshold ECDSA from ECDSA Assumptions"
 * by Doerner, Kondi, Lee, and shelat
 ***********/

use std::io::prelude::*;
use std::io::{BufWriter,Cursor};

use byteorder::{ByteOrder, LittleEndian};

use rand::{Rng};

use rayon::prelude::*;

use curves::{ECGroup, Ford, Fq, Secp, SecpOrd, ecdsa, precomp};

use super::mpecdsa_error::*;
use super::ro::*;
use super::zkpok::*;
use super::mul::*;
use super::mpmul::*;
use super::*;

//#[derive(Clone)]
pub struct Alice2P {
	ro: GroupROTagger,
	multiplier: mul::MulSender,
	ska: SecpOrd,
	#[allow(dead_code)]
	pk: Secp,
	pktable: Vec<Secp>
}

//#[derive(Clone)]
pub struct Bob2P {
	ro: GroupROTagger,
	multiplier: mul::MulRecver,
	skb: SecpOrd,
	#[allow(dead_code)]
	pk: Secp,
	pktable: Vec<Secp>
}

pub struct ThresholdSigner {
	playerindex: usize,
	threshold: usize,
	ro: GroupROTagger,
	multiplier: Vec<mul::MulPlayer>,
	poly_point: SecpOrd,
	#[allow(dead_code)]
	pk: Secp,
	pktable: Vec<Secp>
}

pub type ProactiveRefreshPackage = (Secp, Vec<u8>, SecpOrd, Secp, SecpOrd);

impl Alice2P {
	pub fn new<TR:Read, TW:Write>(ska:&SecpOrd, rng:&mut dyn Rng, recv:&mut TR, send:&mut TW) -> Result<Alice2P, MPECDSAError> {
		let ro = GroupROTagger::from_network_unverified(0, rng, &mut [None, Some(recv)], &mut [None, Some(send)])?;
		
		// commit to PoK-DL for pk_a
		let pka = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &ska).affine();
		let (proofcommitment, proof) = prove_dl_fs_to_com(ska, &pka, &ModelessGroupROTagger::new(&ro, false), rng)?;
		send.write(&proofcommitment)?;
		send.flush()?;

		// recv pk_b
		let mut buf = [0u8; Secp::NBYTES];
		recv.read_exact(&mut buf)?;
		let pkb: Secp = Secp::from_bytes(&buf);

		// verify PoK-DL for pk_b
		match verify_dl_fs(&pkb, &ModelessDyadicROTagger::new(&ro.get_dyadic_tagger(1).unwrap(), false), recv) {
			Ok(f) => { if !f { return Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA secret key (bob cheated)"))); } },
			Err(e) => return Err(e),
		};

		// send pk_a
		// open commitment to PoK-DL
		pka.to_bytes(&mut buf);
		send.write(&buf)?;
		send.write(&proof)?;
		send.flush()?;

		// initialize multiplication
		let mul = mul::MulSender::new(&ro.get_dyadic_tagger(1).unwrap(), rng, recv, send)?;
			
		// calc pk, setup OT exts
		let pk = pkb.scalar_table(&ska).affine();
		let pktable = Secp::precomp_table(&pk);
		let res = Alice2P {
			ro: ro,
			multiplier: mul,
			ska: ska.clone(),
			pk: pk,
			pktable: pktable
		};

		Ok(res)
	}

	pub fn sign<TR:Read, TW:Write+Send>(&self, msg:&[u8], rng:&mut dyn Rng, recv:&mut TR, send:&mut TW) -> Result<(),MPECDSAError> {
		let mut bufsend = BufWriter::new(send);

		// precompute things you won't need till later

		// alice's instance key is of a special form for the two round version:
		// k_a = H(k'_a*G)+k'_a
		// this prevents her from choosing the value conveniently
		let kaprime = SecpOrd::rand(rng);
		let kapad = SecpOrd::rand(rng);

		// hash the message
		let mut z = [0; HASH_SIZE];
		ecdsa_hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// online phase
		let dro = self.ro.get_dyadic_tagger(1).unwrap();

		// recv D_b from bob
		let mut dbraw = [0u8; Secp::NBYTES];
		recv.read_exact(&mut dbraw)?;
		let db = Secp::from_bytes(&dbraw);
		let dbtable = Secp::precomp_table(&db);

		let rprime = Secp::scalar_table_multi(&dbtable[..],&kaprime).affine();
		let mut rprimeraw = [0u8;Secp::NBYTES + RO_TAG_SIZE];
		rprime.to_bytes(&mut rprimeraw[RO_TAG_SIZE..]);
		rprimeraw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
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
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE];
		let kaproof_randcommitment = Secp::scalar_table_multi(&dbtable[..], &kaproof_randcommitted);
		kaproof_randcommitment.to_bytes(&mut kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..(2*Secp::NBYTES + RO_TAG_SIZE)]);
		r.to_bytes(&mut kaproof_buf[RO_TAG_SIZE..(Secp::NBYTES + RO_TAG_SIZE)]);
		kaproof_buf[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..(2*Secp::NBYTES + RO_TAG_SIZE)]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_z = ka.mul(&kaproof_challenge).add(&kaproof_randcommitted);
		kaproof_z.to_bytes(&mut kaproof_buf[(2*Secp::NBYTES + RO_TAG_SIZE)..]);

		// generate OT extensions for two multiplications (input independent for alice)
		let extensions = self.multiplier.mul_extend(2, &dro, recv)?;

		// end first message (bob to alice)

		// alice sends D'_a = k'_a*G rather than D_a so that bob can check her work
		// she also sends her proof of knowledge for k_a
		bufsend.write(&rprimeraw[RO_TAG_SIZE..])?;
		bufsend.write(&kaproof_buf[(Secp::NBYTES + RO_TAG_SIZE)..])?;
		bufsend.flush()?;

		// perform two multiplications with 1/k_a and sk_a/k_a.
		let t1a = self.multiplier.mul_transfer(&[&kai.add(&kapad)], &[&extensions.0[0]], &extensions.1, &dro, rng, &mut bufsend)?[0];
		bufsend.flush()?;
		let mut gamma1raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma1raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		let t2a = self.multiplier.mul_transfer(&[&skai], &[&extensions.0[1]], &extensions.1, &dro, rng, &mut bufsend)?[0];
		bufsend.flush()?;

		// compute check value Gamma_1 for alice
		let gamma1 = Secp::op( &Secp::op( &Secp::scalar_table_multi(&r_table[..], &t1a.neg()), &kapadda ), &Secp::gen()).affine();		
		gamma1.to_bytes(&mut gamma1raw[RO_TAG_SIZE..]);
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		kapad.to_bytes(&mut kapadraw);
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		bufsend.write(&kapadraw)?;
		bufsend.flush()?;

		// compute signature share m_a for alice
		let mut ma = [0u8;SecpOrd::NBYTES];
		let m_a = t1a.mul(&z).add( &t2a.mul(&rx) );
		m_a.to_bytes(&mut ma);

		// compute check value Gamma_2, and encrypt m_a with H(Gamma_2)
		let t2ag = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2a.neg());
		let t1apk = Secp::scalar_table_multi(&self.pktable[..], &t1a);
		let gamma2 = Secp::op(&t2ag, &t1apk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma2.to_bytes(&mut gamma2raw[RO_TAG_SIZE..]);
		gamma2raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		hash(&mut enckey, &gamma2raw);
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}

		// send encrypted signature share
		bufsend.write(&ma)?;
		bufsend.flush()?;

		// end second message (alice to bob)

		Ok(())
	}
}

impl Bob2P {
	pub fn new<TR:Read, TW:Write>(skb:&SecpOrd, rng:&mut dyn Rng, recv:&mut TR, send:&mut TW) -> Result<Bob2P, MPECDSAError> {
		let ro = GroupROTagger::from_network_unverified(1, rng, &mut [Some(recv), None], &mut [Some(send), None])?;

		// recv PoK commitment
		let mut proofcommitment = [0u8; 32];
		recv.read_exact( &mut proofcommitment )?;

		// send pk_b
		let pkb = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &skb).affine();
		let mut buf = [0u8; Secp::NBYTES];
		pkb.to_bytes(&mut buf);
		send.write(&buf)?;
		send.flush()?;
		
		// prove dl for pk_b
		prove_dl_fs(&skb, &pkb, &ModelessGroupROTagger::new(&ro,false), rng, send)?;

		// recv pk_a
		recv.read_exact(&mut buf)?;
		let pka: Secp = Secp::from_bytes(&buf);

		let proofresult = verify_dl_fs_with_com(&pka, &proofcommitment, &ModelessDyadicROTagger::new(&ro.get_dyadic_tagger(0).unwrap(),false), recv);

		// initialize multiplication
		let mul = mul::MulRecver::new(&ro.get_dyadic_tagger(0).unwrap(), rng, recv, send)?;

		// verify PoK to which alice previously committed, then calc pk, setup OT exts
		match proofresult {
			Ok(true) => {
				let pk = pka.scalar_table(&skb).affine();
				let pktable = Secp::precomp_table(&pk);
				let res = Bob2P {
					ro: ro,
					multiplier: mul,
					skb: skb.clone(),
					pk: pk,
					pktable: pktable
				};

				Ok(res)            
			},
			Ok(false) => Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA secret key (alice cheated)"))),
			Err(e) =>  Err(e) 
		}
	}

	pub fn sign<TR: Read, TW: Write>(&self, msg:&[u8], rng:&mut dyn Rng, recv: &mut TR, send: &mut TW) -> Result<(SecpOrd, SecpOrd),MPECDSAError> {
		let mut bufsend = BufWriter::new(send);

		// no precomputation - we want to begin writing as soon as possible

		// choose k_b, calc D_b = k_b*G, send D_b
		let kb = SecpOrd::rand(rng);
		let db = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kb);
		let mut dbraw = [0u8; Secp::NBYTES];
		db.to_bytes(&mut dbraw);
		bufsend.write(&dbraw)?;
		bufsend.flush()?;

		let dro = self.ro.get_dyadic_tagger(0).unwrap();
		let rprime_tag = dro.next_dyadic_tag();
		let kaproof_tag = dro.next_dyadic_tag();

		// generate OT extensions for multiplications with 1/k_b and sk_b/k_b
		let kbi  = kb.inv();
		let skbi = kbi.mul(&self.skb);
		let betas = [kbi.clone(), skbi.clone()];
		let extensions = self.multiplier.mul_encode_and_extend( &betas, &dro, rng, &mut bufsend)?;
		bufsend.flush()?;

		// end first message (bob to alice)

		// receive D'_a from alice, calculate D_a as D_a = H(D'_a)*G + D'_a
		let mut rprimeraw = [0u8;Secp::NBYTES + RO_TAG_SIZE];
		recv.read_exact(&mut rprimeraw[RO_TAG_SIZE..])?;
		let rprime = Secp::from_bytes(&rprimeraw[RO_TAG_SIZE..]);
		rprimeraw[0..RO_TAG_SIZE].copy_from_slice(&rprime_tag);
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
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE];
		r.to_bytes(&mut kaproof_buf[RO_TAG_SIZE..(Secp::NBYTES + RO_TAG_SIZE)]);
		recv.read_exact(&mut kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..])?;
		let kaproof_randcommitment = Secp::from_bytes(&kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..(2*Secp::NBYTES + RO_TAG_SIZE)]);
		let kaproof_z = SecpOrd::from_bytes(&kaproof_buf[(RO_TAG_SIZE + 2*Secp::NBYTES)..]);
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		kaproof_buf[0..RO_TAG_SIZE].copy_from_slice(&kaproof_tag);
		hash(&mut kaproof_challenge, &kaproof_buf[0..(2*Secp::NBYTES+RO_TAG_SIZE)]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_lhs = Secp::op(&Secp::scalar_table_multi(&r_table[..], &kaproof_challenge), &kaproof_randcommitment).affine();
		let kaproof_rhs = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kaproof_z.mul(&kb)).affine();
		if kaproof_lhs != kaproof_rhs {
			return Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA signing (alice cheated)")))
		}

		// hash message
		let mut z = [0u8; HASH_SIZE];
		ecdsa_hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// perform multiplications using the extensions we just generated
		let t1b = self.multiplier.mul_transfer(&[&extensions.0[0]], &extensions.1, &[&extensions.2[0]], &extensions.3, &dro, recv)?[0];
		let gamma1 = Secp::scalar_table_multi(&r_table[..], &t1b).affine(); // start calculating gamma_b early, to give the sender extra time
		let mut gamma1raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma1.to_bytes(&mut gamma1raw[RO_TAG_SIZE..]);
		gamma1raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let t2b = self.multiplier.mul_transfer(&[&extensions.0[1]], &extensions.1, &[&extensions.2[1]], &extensions.3, &dro, recv)?[0];

		// compute the first check messages Gamma_1, and decrypt the pad
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		recv.read_exact(&mut kapadraw)?;
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		let kapad = SecpOrd::from_bytes(&kapadraw);

		let t1baug = t1b.sub(&kbi.mul(&kapad));
		let t2bg = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2b);
		let t1bpk = Secp::scalar_table_multi(&self.pktable[..], &t1baug.neg());
		let gamma2 = Secp::op(&t2bg, &t1bpk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma2.to_bytes(&mut gamma2raw[RO_TAG_SIZE..]);
		gamma2raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		hash(&mut enckey, &gamma2raw);

		// compute bob's signature share m_b
		let m_b = t1baug.mul(&z).add( &t2b.mul(&rx));

		// receive alice's signature share m_a, and decrypt using expected key
		let mut ma = [0u8; SecpOrd::NBYTES];
		recv.read_exact(&mut ma)?;
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
	pub fn new<TR:Read+Send, TW:Write+Send>(playerindex:usize, threshold:usize, rng:&mut dyn Rng, recv:&mut [Option<TR>], send:&mut [Option<TW>]) -> Result<ThresholdSigner, MPECDSAError> {
		if recv.len() != send.len() {
			return Err(MPECDSAError::General(GeneralError::new("Number of Send streams does not match number of Recv streams")));
		}
		let playercount = recv.len();

		let ro = {
			let mut prunedrecv : Vec<Option<&mut TR>> = recv.iter_mut().map(|val| val.as_mut()).collect();
			let mut prunedsend : Vec<Option<&mut TW>> = send.iter_mut().map(|val| val.as_mut()).collect();
			GroupROTagger::from_network_unverified(playerindex, rng, &mut prunedrecv[..], &mut prunedsend[..])?
		};

		let sk_frag = SecpOrd::rand(rng);	

		// Random polynomial for shamir secret sharing.
		// This polynomial represents my secret; we will sum all the polynomials later to sum the secret.
		// Note that we generate k-1 coefficients; the last is the secret
		let mut coefficients:Vec<SecpOrd> = Vec::with_capacity(threshold);
		coefficients.push(sk_frag.clone());
		for _ in 1..threshold {
			coefficients.push(SecpOrd::rand(rng));
		}

		// poly_point will later be my point on the shared/summed polynomial. Create it early
		// so that the component from my own individual polynomial can be added.
		let mut poly_point = SecpOrd::ZERO;
		// evaluate my polynomial once for each player, and send everyone else their fragment
		for ii in 0..playercount {
			let mut poly_frag = coefficients[coefficients.len()-1];
			for jj in (0..(coefficients.len()-1)).rev() {
				poly_frag = poly_frag.mul(&SecpOrd::from_native((ii+1) as u64)).add(&coefficients[jj]);
			}
			if ii == playerindex {
				poly_point = poly_frag;
			} else {
				let mut poly_frag_raw = [0u8;SecpOrd::NBYTES];
				poly_frag.to_bytes(&mut poly_frag_raw);
				send[ii].as_mut().unwrap().write(&poly_frag_raw)?;
				send[ii].as_mut().unwrap().flush()?;
			}
		}

		// recieve polynomial fragments from each player, and sum them to find my point on the shared/summed polynomial
		for ii in 0..playercount {
			if ii != playerindex {
				let mut poly_frag_raw = [0u8;SecpOrd::NBYTES];
				recv[ii].as_mut().unwrap().read_exact(&mut poly_frag_raw)?;
				let poly_frag = SecpOrd::from_bytes(&poly_frag_raw);
				poly_point = poly_point.add(&poly_frag);
			}
		}

		let mut points_com:Vec<Secp> = Vec::with_capacity(playercount);
		let mut pk = Secp::INF;

		if threshold >= playercount/2 {
			// calculate p(playerindex)*G, an EC point with my polynomial point in the exponent, and broadcast it to everyone
			// in the dishonest majority case, we also need a PoK
			let point_com = Secp::scalar_table_multi(&precomp::P256_TABLE, &poly_point);
			let (proofcommitment, proof) = prove_dl_fs_to_com(&poly_point, &point_com, &ModelessGroupROTagger::new(&ro,false), rng)?;
			for ii in 0..playercount {
				if ii != playerindex {
					send[ii].as_mut().unwrap().write(&proofcommitment)?;
					send[ii].as_mut().unwrap().flush()?;
				}
			}
			// now collect everyone else's commitments
			let mut othercommitments = vec![[0u8;32];playercount];
			for ii in 0..playercount {
				if ii != playerindex {
					recv[ii].as_mut().unwrap().read_exact(&mut othercommitments[ii])?;
				}
			}
			// when all commitments are in, release the proof
			let mut point_com_raw = [0u8; Secp::NBYTES];
			point_com.to_bytes(&mut point_com_raw);
			for ii in 0..playercount {
				if ii != playerindex {
					send[ii].as_mut().unwrap().write(&point_com_raw)?;
					send[ii].as_mut().unwrap().write(&proof)?;
					send[ii].as_mut().unwrap().flush()?;
				}
			}
			// and finally verify that the proofs are valid
			for ii in 0..playercount {
				if ii == playerindex {
					points_com.push(point_com);
				} else {
					recv[ii].as_mut().unwrap().read_exact(&mut point_com_raw)?;
					let this_point_com = Secp::from_bytes(&point_com_raw);
					if verify_dl_fs_with_com(&this_point_com, &othercommitments[ii], &ModelessDyadicROTagger::new(&ro.get_dyadic_tagger(ii).unwrap(),false), &mut recv[ii].as_mut().unwrap())? {
						points_com.push(this_point_com);	
					} else {
						return Err(MPECDSAError::Proof(ProofError::new(&format!("Proof of Knowledge failed for player {}'s public key fragment", ii))));
					}
				}
			}
		} else {
			// calculate p(playerindex)*G, an EC point with my polynomial point in the exponent, and broadcast it to everyone
			let point_com = Secp::scalar_table_multi(&precomp::P256_TABLE, &poly_point);
			let mut point_com_raw = [0u8; Secp::NBYTES];
			point_com.to_bytes(&mut point_com_raw);
			for ii in 0..playercount {
				if ii != playerindex {
					send[ii].as_mut().unwrap().write(&point_com_raw)?;
					send[ii].as_mut().unwrap().flush()?;
				}
			}

			// receive commitments to everyone's polynomial points
			for ii in 0..playercount {
				if ii == playerindex {
					points_com.push(point_com);
				} else {
					recv[ii].as_mut().unwrap().read_exact(&mut point_com_raw)?;
					points_com.push(Secp::from_bytes(&point_com_raw));
				}
			}
		}

		// for each contiguous set of parties, perform shamir reconsruction in the exponent and check the result against the known pk
		for ii in 0..(playercount-threshold+1) {
			let mut recon_sum = Secp::INF;
			for jj in 0..threshold {
				let mut coefnum = SecpOrd::ONE;
				let mut coefdenom = SecpOrd::ONE;
				// calculate lagrange coefficient
				for kk in 0..threshold {
					if kk != jj {
						coefnum = coefnum.mul(&SecpOrd::from_native((ii+kk+1) as u64));
						coefdenom = coefdenom.mul(&SecpOrd::from_native((ii+kk+1) as u64).sub(&SecpOrd::from_native((ii+jj+1) as u64)));
					}
				}
				let recon_frag = points_com[ii+jj].scalar_table(&coefnum.mul(&coefdenom.inv()));
				recon_sum = Secp::op(&recon_sum, &recon_frag);
			}
			recon_sum = recon_sum.affine();
			if pk == Secp::INF {
				pk = recon_sum;
			} else if recon_sum != pk {
				return Err(MPECDSAError::Proof(ProofError::new("Verification failed for public key reconstruction")));
			}
		}

		// finally, each pair of parties must have multiplier setup between them. The player with the higher index is always Bob.
		let mut rngs = Vec::with_capacity(playercount);
		for _ in 0..playercount {
			let mut newrng = rand::ChaChaRng::new_unseeded();
			newrng.set_counter(rng.next_u64(), rng.next_u64());
			rngs.push(newrng);
		}

		let threadcount = match std::env::var_os("RAYON_NUM_THREADS") {
		    Some(val) => {
		    	let val = val.into_string().unwrap().parse().unwrap();
		    	if val > 0 {
		    		val
		    	} else {
		    		playercount
		    	}
		    },
    		None => playercount
		};

		let rayonpool = rayon::ThreadPoolBuilder::new().num_threads(threadcount).build().unwrap();
		let multipliervec = rayonpool.install(|| { send.par_iter_mut().zip(recv.par_iter_mut()).zip(rngs.par_iter_mut()).enumerate().map(|(ii, ((sendi, recvi), rngi))| {
			if ii > playerindex {
				MulPlayer::Sender(mul::MulSender::new(&ro.get_dyadic_tagger(ii).unwrap(), rngi, recvi.as_mut().unwrap(), sendi.as_mut().unwrap()).unwrap())
			} else if ii < playerindex {
				MulPlayer::Recver(mul::MulRecver::new(&ro.get_dyadic_tagger(ii).unwrap(), rngi, recvi.as_mut().unwrap(), sendi.as_mut().unwrap()).unwrap())
			} else {
				MulPlayer::Null
			}
		}).collect() });

 		let pktable = Secp::precomp_table(&pk);
		Ok(ThresholdSigner {
			ro: ro,
			playerindex: playerindex,
			threshold: threshold,
			multiplier: multipliervec,
			poly_point: poly_point,
			pk: pk,
			pktable: pktable
		})
	}

	pub fn sign<TR:Read+Send, TW:Write+Send>(&mut self, counterparties: &[usize], msg:&[u8], rng:&mut dyn Rng, recv:&mut [Option<TR>], send:&mut [Option<TW>]) -> Result<Option<(SecpOrd, SecpOrd)>,MPECDSAError> {
		if counterparties.len() != (self.threshold-1) {
			return Err(MPECDSAError::General(GeneralError::new("Number of counterparties does not match threshold.")));
		}

		if self.threshold == 2 {
			let counterparty = counterparties[0];
			if self.playerindex > counterparty {
				return Ok(Some(self.sign2t_bob(counterparty, msg, rng, &mut recv[counterparty].as_mut().unwrap(), &mut send[counterparty].as_mut().unwrap())?));
			} else if self.playerindex < counterparty {
				self.sign2t_alice(counterparty, msg, rng, &mut recv[counterparty].as_mut().unwrap(), &mut send[counterparty].as_mut().unwrap())?;
				return Ok(None);
			} else {
				return Err(MPECDSAError::General(GeneralError::new("Tried to sign with self as counterparty.")));
			}
		} else {
			let mut parties: Vec<usize> = counterparties.to_vec();
			parties.push(self.playerindex);
			parties.sort();
			return Ok(Some(self.sign_threshold(&parties, msg, rng, recv, send)?));
		}
	}

	pub fn sign_and_gen_refresh<TR:Read+Send, TW:Write+Send>(&mut self, counterparties: &[usize], msg:&[u8], tag:&[u8], rng:&mut dyn Rng, recv:&mut [Option<TR>], send:&mut [Option<TW>]) -> Result<(Option<(SecpOrd, SecpOrd)>, ProactiveRefreshPackage),MPECDSAError> {
		if counterparties.len() != (self.threshold-1) {
			return Err(MPECDSAError::General(GeneralError::new("Number of counterparties does not match threshold.")));
		}

		if self.threshold == 2 {
			let counterparty = counterparties[0];

			if self.playerindex > counterparty {
				let (r,s,p) = self.sign2t_and_gen_refresh_bob(counterparty, msg, Some(tag), rng, recv[counterparty].as_mut().unwrap(), send[counterparty].as_mut().unwrap())?;
				return Ok((Some((r,s)),p.unwrap()));
			} else if self.playerindex < counterparty {
				return Ok((None,self.sign2t_and_gen_refresh_alice(counterparty, msg, Some(tag), rng, recv[counterparty].as_mut().unwrap(), send[counterparty].as_mut().unwrap())?.unwrap()));
			} else {
				return Err(MPECDSAError::General(GeneralError::new("Tried to sign with self as counterparty.")));
			}
		} else {
			return Err(MPECDSAError::General(GeneralError::new("Proactive refresh not available for this threshold")));
		}
	}

	pub fn apply_refresh(&mut self, refreshpackage: &ProactiveRefreshPackage) -> Result<(), MPECDSAError> {
		if self.threshold == 2 {
			self.apply_refresh_2t(refreshpackage)
		} else {
			Err(MPECDSAError::General(GeneralError::new("Proactive refresh not available for this threshold")))
		}
	}

	fn sign_threshold<TR:Read+Send, TW:Write+Send>(&mut self, counterparties: &[usize], msg:&[u8], rng:&mut dyn Rng, recv:&mut [Option<TR>], send:&mut [Option<TW>]) -> Result<(SecpOrd, SecpOrd),MPECDSAError> {
		self.ro.apply_subgroup_list(counterparties)?;
		let sroindex = self.ro.current_broadcast_counter();

		let ki = SecpOrd::rand(rng);
		let kipad = SecpOrd::rand(rng);
		let kii = ki.inv();
		let kipadki = kii.mul(&kipad);

		// create reduced sets of resources for the multipliers
		let mut prunedrecv : Vec<&mut Option<TR>> = recv.iter_mut().enumerate().filter_map(|(index, val)| if counterparties.contains(&index) {Some(val)} else {None}).collect();
		let mut prunedsend : Vec<&mut Option<TW>> = send.iter_mut().enumerate().filter_map(|(index, val)| if counterparties.contains(&index) {Some(val)} else {None}).collect();
		let mut prunedmultiplier : Vec<&mul::MulPlayer> = self.multiplier.iter().enumerate().filter_map(|(index, val)| if counterparties.contains(&index) {Some(val)} else {None}).collect();
		let tempplayeri = self.playerindex;
		let prunedplayerindex = counterparties.iter().position(|&x| x == tempplayeri).unwrap();

		//instance key and inverse instance key multiplication
		
		let threadcount = match std::env::var_os("RAYON_NUM_THREADS") {
		    Some(val) => {
		    	let val = val.into_string().unwrap().parse().unwrap();
		    	if val > 0 {
		    		val
		    	} else {
		    		counterparties.len()
		    	}
		    },
			None => counterparties.len()
		};

		let rayonpool = rayon::ThreadPoolBuilder::new().num_threads(threadcount).build().unwrap();

		// message 1 send+recv, message 2 send
		let prodshares = mprmul_round_one(4, prunedplayerindex, &mut prunedmultiplier, &self.ro, rng, &mut prunedrecv.as_mut_slice(), &mut prunedsend.as_mut_slice(), &rayonpool)?;

		let mut helpfulsendbuffer = vec![Some(Cursor::new(Vec::new())); counterparties.len()];

		{
			let prodshares1: Vec<&[SecpOrd]> = prodshares.iter().map(|x| if x.0.len() > 0 {
				&x.0[0..2]
			} else {
				&x.0[..]
			}).collect();

			// message 2 send
			mpmul_first(&[ki, kipadki], prunedplayerindex, prodshares1.as_slice(), helpfulsendbuffer.iter_mut().collect::<Vec<_>>().as_mut_slice())?;
		}

		let helpfulsentbuffer = helpfulsendbuffer.into_iter().map(|x| x.unwrap().into_inner()).collect();

		// message 2 recv
		let linshares = mprmul_round_two(prunedplayerindex, &prodshares, &mut prunedmultiplier, &self.ro, rng, &mut prunedrecv.as_mut_slice(), &mut prunedsend.as_mut_slice(), &rayonpool, Some(helpfulsentbuffer))?;

		let shares: Vec<Vec<(SecpOrd,SecpOrd)>> = prodshares.into_iter().zip(linshares.into_iter()).map(|(prodel,linel)|  {
			prodel.0.into_iter().zip(linel.into_iter()).collect()
		}).collect();

		let shares1: Vec<&[(SecpOrd,SecpOrd)]> = shares.iter().map(|x| if x.len() > 0 {
			&x[0..2]
		} else {
			&x[..]
		}).collect();

		let shares2: Vec<&[(SecpOrd,SecpOrd)]> = shares.iter().map(|x| if x.len() > 0 {
			&x[2..4]
		} else {
			&x[..]
		}).collect();

		// message 2 recv, message 3 to log(n)+1 send+recv
		let mulresult = mpmul_rest(&[ki, kipadki], prunedplayerindex, shares1.as_slice(), &mut prunedrecv.as_mut_slice(), &mut prunedsend.as_mut_slice())?;
		let ui = mulresult[0];
		let vi = mulresult[1];

		let mut coefnum = SecpOrd::ONE;
		let mut coefdenom = SecpOrd::ONE;
		// calculate lagrange coefficient
		for kk in 0..self.threshold {
			if kk != prunedplayerindex {
				coefnum = coefnum.mul(&SecpOrd::from_native((counterparties[kk]+1) as u64));
				coefdenom = coefdenom.mul(&SecpOrd::from_native((counterparties[kk]+1) as u64).sub(&SecpOrd::from_native((self.playerindex+1) as u64)));
			}
		}
		let zi = self.poly_point.mul(&coefnum.mul(&coefdenom.inv()));

		//secret key multiplication, step one
		// message log(n)+2 send
		mpswapmul_send(&[(vi, zi)], prunedplayerindex, shares2.as_slice(), &mut prunedsend.as_mut_slice())?;

		//R and phi commitment, plus broadcast RO sync
		let ri = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &ui).affine();
		let mut pad_raw = [0u8; SecpOrd::NBYTES + RO_TAG_SIZE];
		let mut ri_raw = [0u8; Secp::NBYTES + RO_TAG_SIZE];
		kipad.to_bytes(&mut pad_raw[RO_TAG_SIZE..]);
		ri.to_bytes(&mut ri_raw[RO_TAG_SIZE..]);

		let mut hashout = [0u8;HASH_SIZE];
		let mut doublecom = vec![[0u8;2*HASH_SIZE]; self.threshold];
		ri_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_broadcast_tag());
		pad_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_broadcast_tag());
		hash(&mut hashout, &ri_raw);
		doublecom[prunedplayerindex][HASH_SIZE..2*HASH_SIZE].copy_from_slice(&hashout[..]);
		hash(&mut hashout, &pad_raw);
		doublecom[prunedplayerindex][0..HASH_SIZE].copy_from_slice(&hashout[..]);
		

		// synchronize the random oracles
		let mut sroindex_raw  = [0u8;8];
		LittleEndian::write_u64(&mut sroindex_raw, sroindex);

		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+2 send
				prunedsend[ii].as_mut().unwrap().write(&sroindex_raw)?;
				prunedsend[ii].as_mut().unwrap().write(&doublecom[prunedplayerindex])?;
				prunedsend[ii].as_mut().unwrap().flush()?;
			}
		}

		//secret key multiplication, step two
		// message log(n)+2 recv
		let wi = mpswapmul_recv(&[(vi, zi)], prunedplayerindex, shares2.as_slice(), &mut prunedrecv.as_mut_slice())?[0];

		// receive commitments to kjpad, rj, poks
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+2 recv
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut sroindex_raw)?;
				self.ro.advance_counterparty_broadcast_counter(counterparties[ii], LittleEndian::read_u64(&sroindex_raw))?;
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut doublecom[ii])?;
			}
		}

		// release ri + pok
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+3 send
				prunedsend[ii].as_mut().unwrap().write(&ri_raw[RO_TAG_SIZE..])?;
				prunedsend[ii].as_mut().unwrap().flush()?;
			}
		}

		// receive rj + pok and verify against commitment
		let mut r = ri;
		let mut rjs = vec![Secp::INF; self.threshold];
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+3 recv
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut ri_raw[RO_TAG_SIZE..])?;
				ri_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_counterparty_broadcast_tag(ii)?);
				hash(&mut hashout, &ri_raw);
				if hashout != doublecom[ii][HASH_SIZE..2*HASH_SIZE] {
					return Err(MPECDSAError::Proof(ProofError::new(&format!("Player {} failed to decommit R", counterparties[ii]))));
				}
				rjs[ii] = Secp::from_bytes(&ri_raw[RO_TAG_SIZE..]);
				r = Secp::op(&r, &rjs[ii]).affine();
			}
		}

		// message log(n)+3 recv

		let r_table = Secp::precomp_table(&r);
		let mut checkpt1 = Secp::scalar_table_multi(&r_table[..], &vi).affine();
		let mut checkpt2 = Secp::op(&Secp::scalar_table_multi(&self.pktable[..], &vi), &Secp::scalar_table_multi(&precomp::P256_TABLE[..], &wi).neg()).affine();
		let mut checkpt3 = Secp::scalar_table_multi(&r_table[..], &wi).affine();
		
		let mut checkpt123_raw = [0u8; 3*Secp::NBYTES+RO_TAG_SIZE];
		checkpt1.to_bytes(&mut checkpt123_raw[RO_TAG_SIZE..(Secp::NBYTES+RO_TAG_SIZE)]);
		checkpt2.to_bytes(&mut checkpt123_raw[(Secp::NBYTES+RO_TAG_SIZE)..(2*Secp::NBYTES+RO_TAG_SIZE)]);
		checkpt3.to_bytes(&mut checkpt123_raw[(2*Secp::NBYTES+RO_TAG_SIZE)..(3*Secp::NBYTES+RO_TAG_SIZE)]);
		let mut checkpt123_coms  = vec![[0u8; HASH_SIZE]; self.threshold];
		checkpt123_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_broadcast_tag());
		hash(&mut checkpt123_coms[prunedplayerindex], &checkpt123_raw);
		// send commitment
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+4 send
				prunedsend[ii].as_mut().unwrap().write(&checkpt123_coms[prunedplayerindex])?;
				prunedsend[ii].as_mut().unwrap().flush()?;
			}
		}

		// receive commitments checkpts
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+4 recv
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut checkpt123_coms[ii])?;
			}
		}

		// release kipad and checkpts
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+5 send
				prunedsend[ii].as_mut().unwrap().write(&pad_raw[(RO_TAG_SIZE)..])?;
				prunedsend[ii].as_mut().unwrap().write(&checkpt123_raw[(RO_TAG_SIZE)..])?;
				prunedsend[ii].as_mut().unwrap().flush()?;
			}
		}

		// receive kjpad and verify against commitment
		let mut kpad = kipad;
		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				let mut comcomp = [0u8;HASH_SIZE];
				pad_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_counterparty_broadcast_tag(ii)?);
				// message log(n)+5 recv
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut pad_raw[RO_TAG_SIZE..])?;
				hash(&mut comcomp, &pad_raw);
				let kjpad = SecpOrd::from_bytes(&pad_raw[RO_TAG_SIZE..]);
				if comcomp == doublecom[ii][0..HASH_SIZE] {
					kpad = kpad.mul(&kjpad);
				} else {
					return Err(MPECDSAError::Proof(ProofError::new(&format!("Player {} failed to decommit multiplication pad", counterparties[ii]))));
				}

				checkpt123_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_counterparty_broadcast_tag(ii)?);
				// message log(n)+5 recv
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut checkpt123_raw[RO_TAG_SIZE..])?;
				hash(&mut comcomp, &checkpt123_raw);
				if comcomp == checkpt123_coms[ii] {
					let checkpt1_frag = Secp::from_bytes(&checkpt123_raw[RO_TAG_SIZE..(Secp::NBYTES+RO_TAG_SIZE)]);
					let checkpt2_frag = Secp::from_bytes(&checkpt123_raw[(Secp::NBYTES+RO_TAG_SIZE)..(2*Secp::NBYTES+RO_TAG_SIZE)]);
					let checkpt3_frag = Secp::from_bytes(&checkpt123_raw[(2*Secp::NBYTES+RO_TAG_SIZE)..(3*Secp::NBYTES+RO_TAG_SIZE)]);
					checkpt1 = Secp::op(&checkpt1, &checkpt1_frag).affine();
					checkpt2 = Secp::op(&checkpt2, &checkpt2_frag).affine();
					checkpt3 = Secp::op(&checkpt3, &checkpt3_frag).affine();
				} else {
					return Err(MPECDSAError::Proof(ProofError::new(&format!("Player {} failed to decommit consistency checks", counterparties[ii]))));
				}
			}
		}

		if kpad == SecpOrd::ZERO {
			return Err(MPECDSAError::Proof(ProofError::new(&"Multicplication pad value was zero")));
		}

		if checkpt1.affine() != Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kpad).affine() {
			return Err(MPECDSAError::Proof(ProofError::new(&"First consistency check failed")));
		}

		if !checkpt2.is_infinity() {
			return Err(MPECDSAError::Proof(ProofError::new(&"Second consistency check failed")));
		}

		if checkpt3 != Secp::scalar_table_multi(&self.pktable, &kpad).affine() {
			return Err(MPECDSAError::Proof(ProofError::new(&"Third consistency check failed")));
		}

		// hash the message
		let mut z = [0; HASH_SIZE];
		ecdsa_hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		let mut rxb = [0u8; SecpOrd::NBYTES];
		r.x.to_bytes(&mut rxb);
		let rx = SecpOrd::from_bytes(&rxb);

		let wiaug = wi.mul(&kpad.inv());
		let mut sig = z.mul(&vi).mul(&kpad.inv()).add(&wiaug.mul(&rx));
		let mut sig_frag_raw = [0u8;SecpOrd::NBYTES];
		sig.to_bytes(&mut sig_frag_raw);

		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+6 send
				prunedsend[ii].as_mut().unwrap().write(&sig_frag_raw)?;
				prunedsend[ii].as_mut().unwrap().flush()?;
			}
		}

		for ii in 0..self.threshold {
			if ii != prunedplayerindex {
				// message log(n)+6 recv
				prunedrecv[ii].as_mut().unwrap().read_exact(&mut sig_frag_raw)?;
				let sig_frag = SecpOrd::from_bytes(&sig_frag_raw);
				sig = sig.add(&sig_frag);
			}
		}

		if ecdsa::ecdsa_verify_with_tables(msg, (&rx, &sig), &precomp::P256_TABLE, &self.pktable[..]) {
			Ok((rx, sig))
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Signature verification failed for ECDSA signing")))
		}
	}

	fn sign2t_alice<TR:Read, TW:Write+Send>(&mut self, counterparty: usize, msg:&[u8], rng:&mut dyn Rng, recv:&mut TR, send:&mut TW) -> Result<(),MPECDSAError> {
		let res = self.sign2t_and_gen_refresh_alice(counterparty, msg, None, rng, recv, send);
		if res.is_ok() {
			Ok(())
		} else {
			Err(res.unwrap_err())
		}
	}

	fn sign2t_and_gen_refresh_alice<TR:Read, TW:Write+Send>(&mut self, counterparty: usize, msg:&[u8], tag:Option<&[u8]>, rng:&mut dyn Rng, recv:&mut TR, send:&mut TW) -> Result<Option<ProactiveRefreshPackage>,MPECDSAError> {
		let (parties, prunedcpindex) = if self.playerindex > counterparty {
			([counterparty, self.playerindex], 0)
		} else {
			([self.playerindex, counterparty], 1)
		};
		self.ro.apply_subgroup_list(&parties)?;
		let sroindex = self.ro.current_broadcast_counter();
		let mut sroindex_raw  = [0u8;8];
		// precompute things you won't need till later

		// alice's instance key is of a special form for the two round version:
		// k_a = H(k'_a*G)+k'_a
		// this prevents her from choosing the value conveniently
		let kaprime = SecpOrd::rand(rng);
		let kapad = SecpOrd::rand(rng);

		// hash the message
		let mut z = [0; HASH_SIZE];
		ecdsa_hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// calculate lagrange coefficient
		let mut coef = SecpOrd::from_native((counterparty+1) as u64);
		coef = coef.mul(&(SecpOrd::from_native((counterparty+1) as u64).sub(&SecpOrd::from_native((self.playerindex+1) as u64))).inv());
		let t0a = coef.mul(&self.poly_point);

		let multiplier = match self.multiplier[counterparty] {
			MulPlayer::Sender(ref multiplier) => multiplier,
			_ => return Err(MPECDSAError::General(GeneralError::new("Alice was given Recver half of multiplier protocol.")))
		};

		// online phase
		recv.read_exact(&mut sroindex_raw)?;
		self.ro.advance_counterparty_broadcast_counter(prunedcpindex, LittleEndian::read_u64(&sroindex_raw))?;
		let dro = self.ro.get_dyadic_tagger(prunedcpindex).unwrap();

		// recv D_b from bob
		let mut dbraw = [0u8; Secp::NBYTES];
		recv.read_exact(&mut dbraw)?;
		let db = Secp::from_bytes(&dbraw);
		let dbtable = Secp::precomp_table(&db);

		let rprime = Secp::scalar_table_multi(&dbtable[..],&kaprime).affine();
		let mut rprimeraw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		rprime.to_bytes(&mut rprimeraw[RO_TAG_SIZE..]);
		rprimeraw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
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
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES + RO_TAG_SIZE];
		let kaproof_randcommitment = Secp::scalar_table_multi(&dbtable[..], &kaproof_randcommitted);
		kaproof_randcommitment.to_bytes(&mut kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..(RO_TAG_SIZE + 2*Secp::NBYTES)]);
		r.to_bytes(&mut kaproof_buf[RO_TAG_SIZE..(RO_TAG_SIZE + Secp::NBYTES)]);
		kaproof_buf[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..(2*Secp::NBYTES+RO_TAG_SIZE)]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_z = ka.mul(&kaproof_challenge).add(&kaproof_randcommitted);
		kaproof_z.to_bytes(&mut kaproof_buf[(RO_TAG_SIZE + 2*Secp::NBYTES)..]);

		// generate OT extensions for two multiplications (input independent for alice)
		let extensions = multiplier.mul_extend(2, &dro, recv)?;

		// end first message (bob to alice)

		let mut bufsend = BufWriter::new(send);
		LittleEndian::write_u64(&mut sroindex_raw, sroindex);
		bufsend.write(&sroindex_raw)?;

		// alice sends D'_a = k'_a*G rather than D_a so that bob can check her work
		bufsend.write(&rprimeraw[RO_TAG_SIZE..])?;
		bufsend.write(&kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..])?;
		bufsend.flush()?;

		// optional: proactive refresh
		let (refreshpackage, mut bufsend) = if let Some(tag) = tag {
			let send = bufsend.into_inner().map_err(|_| MPECDSAError::General(GeneralError::new("Buffer unwrap error"))).unwrap();
			(Some(self.gen_refresh_2t(&r, tag, counterparty, prunedcpindex, rng, recv, send)?), BufWriter::new(send))
		} else {
			(None, bufsend)
		};

		// perform two multiplications with 1/k_a and sk_a/k_a.
		let t12 = multiplier.mul_transfer(&[&kai.add(&kapad),&t0ai,&kai], &[&extensions.0[0],&extensions.0[0],&extensions.0[1]], &extensions.1, &dro, rng, &mut bufsend)?;
		bufsend.flush()?;
		let t1a = t12[0];
		let t2aa = t12[1];
		let t2ba = t12[2];
		let t2a = t2aa.add(&t2ba);

		// compute check value Gamma_1 for alice
		let gamma1 = Secp::op( &Secp::op( &Secp::scalar_table_multi(&r_table[..], &t1a.neg()), &kapadda ), &Secp::gen()).affine();
		let mut gamma1raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma1.to_bytes(&mut gamma1raw[RO_TAG_SIZE..]);
		gamma1raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		kapad.to_bytes(&mut kapadraw);
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		bufsend.write(&kapadraw)?;
		bufsend.flush()?;

		// compute signature share m_a for alice
		let mut ma = [0u8;SecpOrd::NBYTES];
		let m_a = t1a.mul(&z).add( &t2a.mul(&rx) );
		m_a.to_bytes(&mut ma);

		// compute check value Gamma_2, and encrypt m_a with H(Gamma_2)
		let t2ag = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2a.neg());
		let t1apk = Secp::scalar_table_multi(&self.pktable[..], &t1a);
		let gamma2 = Secp::op(&t2ag, &t1apk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma2.to_bytes(&mut gamma2raw[RO_TAG_SIZE..]);
		gamma2raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		hash(&mut enckey, &gamma2raw);
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}

		// send encrypted signature share
		bufsend.write(&ma)?;
		bufsend.flush()?;

		// end second message (alice to bob)

		Ok(refreshpackage)
	}

	fn sign2t_bob<TR:Read, TW:Write+Send>(&mut self, counterparty: usize, msg:&[u8], rng:&mut dyn Rng, recv:&mut TR, send:&mut TW) -> Result<(SecpOrd, SecpOrd),MPECDSAError> {
		let res = self.sign2t_and_gen_refresh_bob(counterparty, msg, None, rng, recv, send);
		if let Ok((r0,r1,_)) = res {
			Ok((r0, r1))
		} else {
			Err(res.unwrap_err())
		}
	}

	fn sign2t_and_gen_refresh_bob <TR: Read, TW: Write>(&mut self, counterparty: usize, msg:&[u8], tag:Option<&[u8]>, rng:&mut dyn Rng, recv: &mut TR, send: &mut TW) -> Result<(SecpOrd, SecpOrd, Option<ProactiveRefreshPackage>),MPECDSAError> {
		let (parties, prunedcpindex) = if self.playerindex > counterparty {
			([counterparty, self.playerindex], 0)
		} else {
			([self.playerindex, counterparty], 1)
		};
		self.ro.apply_subgroup_list(&parties)?;
		let sroindex = self.ro.current_broadcast_counter();
		let mut sroindex_raw  = [0u8;8];
		LittleEndian::write_u64(&mut sroindex_raw, sroindex);

		let mut bufsend = BufWriter::new(send);
		bufsend.write(&sroindex_raw)?;

		let multiplier = match self.multiplier[counterparty] {
			MulPlayer::Recver(ref multiplier) => multiplier,
			_ => return Err(MPECDSAError::General(GeneralError::new("Bob was given Sender half of multiplier protocol.")))
		};
		// no precomputation - we want to begin writing as soon as possible

		// choose k_b, calc D_b = k_b*G, send D_b
		let kb = SecpOrd::rand(rng);
		let db = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kb);
		let mut dbraw = [0u8; Secp::NBYTES];
		db.to_bytes(&mut dbraw);
		bufsend.write(&dbraw)?;
		bufsend.flush()?;

		// calculate lagrange coefficient
		let mut coef = SecpOrd::from_native((counterparty+1) as u64);
		coef = coef.mul(&(SecpOrd::from_native((counterparty+1) as u64).sub(&SecpOrd::from_native((self.playerindex+1) as u64))).inv());
		let t0b = coef.mul(&self.poly_point);

		let dro = self.ro.get_dyadic_tagger(prunedcpindex).unwrap();
		let rprime_tag = dro.next_dyadic_tag();
		let kaproof_tag = dro.next_dyadic_tag();

		// generate OT extensions for multiplications with 1/k_b and sk_b/k_b
		let kbi  = kb.inv();
		let t0bi = kbi.mul(&t0b);
		let betas = [kbi.clone(), t0bi.clone()];
		let extensions = multiplier.mul_encode_and_extend(&betas, &dro, rng, &mut bufsend)?;
		bufsend.flush()?;

		// end first message (bob to alice)
		recv.read_exact(&mut sroindex_raw)?;
		self.ro.advance_counterparty_broadcast_counter(prunedcpindex, LittleEndian::read_u64(&sroindex_raw))?;

		// receive D'_a from alice, calculate D_a as D_a = H(D'_a)*G + D'_a
		let mut rprimeraw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		recv.read_exact(&mut rprimeraw[RO_TAG_SIZE..])?;
		rprimeraw[0..RO_TAG_SIZE].copy_from_slice(&rprime_tag);
		let rprime = Secp::from_bytes(&rprimeraw[RO_TAG_SIZE..]);
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
		let mut kaproof_buf = [0u8;2*Secp::NBYTES + SecpOrd::NBYTES+RO_TAG_SIZE];
		kaproof_buf[0..RO_TAG_SIZE].copy_from_slice(&kaproof_tag);
		r.to_bytes(&mut kaproof_buf[RO_TAG_SIZE..(Secp::NBYTES+RO_TAG_SIZE)]);
		recv.read_exact(&mut kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..])?;
		let kaproof_randcommitment = Secp::from_bytes(&kaproof_buf[(RO_TAG_SIZE + Secp::NBYTES)..(RO_TAG_SIZE + 2*Secp::NBYTES)]);
		let kaproof_z = SecpOrd::from_bytes(&kaproof_buf[(RO_TAG_SIZE + 2*Secp::NBYTES)..]);
		let mut kaproof_challenge = [0u8; HASH_SIZE];
		hash(&mut kaproof_challenge, &kaproof_buf[0..(2*Secp::NBYTES+RO_TAG_SIZE)]);
		let kaproof_challenge = SecpOrd::from_bytes(&kaproof_challenge[..]);
		let kaproof_lhs = Secp::op(&Secp::scalar_table_multi(&r_table[..], &kaproof_challenge), &kaproof_randcommitment).affine();
		let kaproof_rhs = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &kaproof_z.mul(&kb)).affine();
		if kaproof_lhs != kaproof_rhs {
			return Err(MPECDSAError::Proof(ProofError::new("Proof of Knowledge failed for ECDSA signing (alice cheated)")))
		}

		// optional: proactive refresh
		let refreshpackage = if let Some(tag) = tag {
			let send = bufsend.into_inner().map_err(|_| MPECDSAError::General(GeneralError::new("Buffer unwrap error"))).unwrap();
			Some(self.gen_refresh_2t(&r, tag, counterparty, prunedcpindex, rng, recv, send)?)
		} else {
			None
		};

		// hash message
		let mut z = [0u8; HASH_SIZE];
		ecdsa_hash(&mut z, msg);
		let z = SecpOrd::from_bytes(&z);

		// perform multiplications using the extensions we just generated
		let t12 = multiplier.mul_transfer(&[&extensions.0[0],&extensions.0[0],&extensions.0[1]], &extensions.1, &[&extensions.2[0],&extensions.2[0],&extensions.2[1]], &extensions.3, &dro, recv)?;
		let t1b = t12[0];
		let t2ab = t12[1];
		let t2bb = t12[2];
		let t2b = t2ab.add(&t2bb);
		let gamma1 = Secp::scalar_table_multi(&r_table[..], &t1b).affine(); // start calculating gamma_b early, to give the sender extra time
		let mut gamma1raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma1.to_bytes(&mut gamma1raw[RO_TAG_SIZE..]);
		gamma1raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		let mut enckey = [0u8;HASH_SIZE];
		hash(&mut enckey, &gamma1raw);

		// compute the first check messages Gamma_1, and decrypt the pad
		let mut kapadraw = [0u8;SecpOrd::NBYTES];
		recv.read_exact(&mut kapadraw)?;
		for ii in 0..SecpOrd::NBYTES {
			kapadraw[ii] ^= enckey[ii];
		}
		let kapad = SecpOrd::from_bytes(&kapadraw);

		let t1baug = t1b.sub(&kbi.mul(&kapad));
		let t2bg = Secp::scalar_table_multi(&precomp::P256_TABLE[..], &t2b);
		let t1bpk = Secp::scalar_table_multi(&self.pktable[..], &t1baug.neg());
		let gamma2 = Secp::op(&t2bg, &t1bpk).affine();
		let mut gamma2raw = [0u8;Secp::NBYTES+RO_TAG_SIZE];
		gamma2.to_bytes(&mut gamma2raw[RO_TAG_SIZE..]);
		gamma2raw[0..RO_TAG_SIZE].copy_from_slice(&dro.next_dyadic_tag());
		hash(&mut enckey, &gamma2raw);

		// compute bob's signature share m_b
		let m_b = t1baug.mul(&z).add( &t2b.mul(&rx));

		// receive alice's signature share m_a, and decrypt using expected key
		let mut ma = [0u8; SecpOrd::NBYTES];
		recv.read_exact(&mut ma)?;
		for ii in 0..SecpOrd::NBYTES {
			ma[ii] ^= enckey[ii];
		}
		let m_a = SecpOrd::from_bytes(&ma);

		// reconstruct signature
		let s = m_a.add( &m_b );

		// end second message (alice to bob)

		// verify signature. Abort if it's incorrect.
		if ecdsa::ecdsa_verify_with_tables(msg, (&rx, &s), &precomp::P256_TABLE, &self.pktable[..]) {
			Ok((rx, s, refreshpackage))
		} else {
			Err(MPECDSAError::Proof(ProofError::new("Signature verification failed for ECDSA signing (alice cheated)")))
		}
	}

	fn gen_refresh_2t <TR:Read, TW:Write>(&self, R: &Secp, tag: &[u8], counterparty:usize, prunedcpindex:usize, rng: &mut dyn Rng, recv: &mut TR, send: &mut TW) -> Result<ProactiveRefreshPackage,MPECDSAError> {
		let my_coin = SecpOrd::rand(rng);
		let (my_nonce_dl, my_nonce) = Secp::rand(rng);
		let mut coin_raw = [0u8;SecpOrd::NBYTES + RO_TAG_SIZE];
		let mut nonce_raw = [0u8;Secp::NBYTES];
		let mut coincom = [0u8;HASH_SIZE];
		my_coin.to_bytes(&mut coin_raw[RO_TAG_SIZE..]);
		my_nonce.to_bytes(&mut nonce_raw);
		coin_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_broadcast_tag()[..]);
		hash(&mut coincom, &coin_raw);
		let (mut prfcom,proof) = prove_dl_fs_to_com(&my_nonce_dl, &my_nonce, &ModelessGroupROTagger::new(&self.ro, false), rng).unwrap();
		send.write(&coincom)?;
		send.write(&prfcom)?;
		send.flush()?;

		recv.read_exact(&mut coincom)?;
		recv.read_exact(&mut prfcom)?;

		send.write(&coin_raw[RO_TAG_SIZE..])?;
		send.write(&nonce_raw)?;
		send.write(&proof)?;
		send.flush()?;

		recv.read_exact(&mut coin_raw[RO_TAG_SIZE..])?;
		coin_raw[0..RO_TAG_SIZE].copy_from_slice(&self.ro.next_counterparty_broadcast_tag(prunedcpindex).unwrap()[..]);
		let mut coincomcomp = [0u8;HASH_SIZE];
		hash(&mut coincomcomp, &coin_raw);
		if coincom != coincomcomp {
			return Err(MPECDSAError::Proof(ProofError::new("Counterparty decommitted incorrectly in proactive refresh")));
		}

		recv.read_exact(&mut nonce_raw)?;
		let cp_nonce = Secp::from_bytes(&nonce_raw);
		let proofresult = verify_dl_fs_with_com(&cp_nonce, &prfcom, &ModelessDyadicROTagger::new(&self.ro.get_dyadic_tagger(prunedcpindex).unwrap(), false), recv)?;

		if !proofresult {
			return Err(MPECDSAError::Proof(ProofError::new("Counterparty failed to prove discrete log in proactive refresh")));
		}

		let schnorr_nonce = Secp::op(&my_nonce, &cp_nonce).affine();
		let coin = my_coin.add(&SecpOrd::from_bytes(&coin_raw[RO_TAG_SIZE..]));

		let mut schnorr_e_in = vec![0u8;2*Secp::NBYTES + SecpOrd::NBYTES + tag.len()];
		R.to_bytes(&mut schnorr_e_in[0..Secp::NBYTES]);
		schnorr_nonce.to_bytes(&mut schnorr_e_in[Secp::NBYTES..2*Secp::NBYTES]);
		coin.to_bytes(&mut schnorr_e_in[2*Secp::NBYTES..2*Secp::NBYTES+SecpOrd::NBYTES]);

		let mut schnorr_e = [0u8;HASH_SIZE];
		hash(&mut schnorr_e, &schnorr_e_in);
		let schnorr_e = SecpOrd::from_bytes(&schnorr_e);

		// calculate lagrange coefficient
		let mut coef = SecpOrd::from_native((counterparty+1) as u64);
		coef = coef.mul(&(SecpOrd::from_native((counterparty+1) as u64).sub(&SecpOrd::from_native((self.playerindex+1) as u64))).inv());
		let my_sk = coef.mul(&self.poly_point);
		let schnorr_z = my_sk.mul(&schnorr_e).add(&my_nonce_dl);
		let mut schnorr_z_raw = [0u8;SecpOrd::NBYTES];
		schnorr_z.to_bytes(&mut schnorr_z_raw);

		send.write(&schnorr_z_raw)?;
		send.flush()?;
		recv.read_exact(&mut schnorr_z_raw)?;
		let cp_schnorr_z = SecpOrd::from_bytes(&schnorr_z_raw);

		let cp_pk_e = Secp::op(&self.pk, &Secp::scalar_table_multi(&precomp::P256_TABLE[..], &my_sk).neg()).scalar_table(&schnorr_e);

		if Secp::scalar_table_multi(&precomp::P256_TABLE[..], &cp_schnorr_z).affine() != Secp::op(&cp_pk_e, &cp_nonce).affine() {
			return Err(MPECDSAError::Proof(ProofError::new("Counterparty refresh signature failed to verify")));
		}

		Ok((*R, tag.to_vec(), coin, schnorr_nonce, schnorr_z.add(&cp_schnorr_z)))
	}

	fn apply_refresh_2t(&mut self, refreshpackage: &ProactiveRefreshPackage) -> Result<(),MPECDSAError> {
		let (R, tag, coin, schnorr_nonce, schnorr_z) = refreshpackage;
		self.ro.remove_subgroup_mask();

		let mut schnorr_e_in = vec![0u8;2*Secp::NBYTES + SecpOrd::NBYTES + tag.len()];
		R.to_bytes(&mut schnorr_e_in[0..Secp::NBYTES]);
		schnorr_nonce.to_bytes(&mut schnorr_e_in[Secp::NBYTES..2*Secp::NBYTES]);
		coin.to_bytes(&mut schnorr_e_in[2*Secp::NBYTES..2*Secp::NBYTES+SecpOrd::NBYTES]);

		let mut schnorr_e = [0u8;HASH_SIZE];
		hash(&mut schnorr_e, &schnorr_e_in);
		let schnorr_e = SecpOrd::from_bytes(&schnorr_e);

		if Secp::scalar_table_multi(&precomp::P256_TABLE[..], &schnorr_z).affine() != Secp::op(&self.pk.scalar_table(&schnorr_e), &schnorr_nonce).affine() {
			Err(MPECDSAError::Proof(ProofError::new("Refresh Package failed to verify")))
		} else {
			self.poly_point = self.poly_point.add(&coin.mul(&SecpOrd::from_native((self.playerindex + 1) as u64)));
			for (ii,mulinstance) in self.multiplier.iter_mut().enumerate() {
				match mulinstance {
					MulPlayer::Sender(m) => {m.apply_refresh(&schnorr_e_in[2*Secp::NBYTES..2*Secp::NBYTES+SecpOrd::NBYTES], &self.ro.get_dyadic_tagger(ii).unwrap()).unwrap();},
					MulPlayer::Recver(m) => {m.apply_refresh(&schnorr_e_in[2*Secp::NBYTES..2*Secp::NBYTES+SecpOrd::NBYTES], &self.ro.get_dyadic_tagger(ii).unwrap()).unwrap();},
					MulPlayer::Null => {}
				};
			}
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use super::channelstream::*;
	use std::thread;
	use test::Bencher;
	
	#[test]
	fn test_mpecdsa_2psign() {
		let msg = "The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);
		
		let (mut writ_a, mut read_b) = channelstream::new_channelstream();
		let (mut writ_b, mut read_a) = channelstream::new_channelstream();
		
		let thandle = thread::spawn(move || {
			
			let mut rng = rand::thread_rng();
			let bob = Bob2P::new(&skb,&mut rng, &mut read_b, &mut writ_b);
			if bob.is_err() {
				return Err(bob.err().unwrap());
			}
			let bob = bob.unwrap();
            
			let mut results = Vec::with_capacity(10);
			for _ in 0..10 {
				results.push(bob.sign(&msg, &mut rng, &mut read_b, &mut writ_b));
			}
            
			Ok(results)
		});
        
		let alice = Alice2P::new(&ska, &mut rng, &mut read_a, &mut writ_a);
		assert!(alice.is_ok());
		let alice = alice.unwrap();
		let mut aliceresults = Vec::with_capacity(10);
		for _ in 0..10 {
			aliceresults.push(alice.sign(&msg, &mut rng, &mut read_a, &mut writ_a));
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
	fn test_mpecdsa_3p2tsetup() {
		let threshold = 2;
		let parties = 3;
		
		let (sendvec, recvvec) = spawn_n2_channelstreams(parties);
		
		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(ii, (si, ri))| {
			thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let mut sin = si;
				let mut rin = ri;
				ThresholdSigner::new(ii, threshold, &mut rng, &mut rin, &mut sin)
			})
		}).collect::<Vec<_>>();
 
		let mut firstpk = Secp::INF;
		for handle in thandles {
			let signer = handle.join().unwrap();
			//signer.is_ok();
			assert!(signer.is_ok());
			if firstpk == Secp::INF {
				firstpk = signer.unwrap().pk;
			} else {
				assert_eq!(signer.unwrap().pk, firstpk);
			}
		}
	}

	#[test]
	fn test_mpecdsa_3p2tsign() {

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(3);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandlea = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut alice = ThresholdSigner::new(0, 2, &mut rng, &mut r0[..], &mut s0[..]).unwrap();
			let result1 = alice.sign(&[1], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			let result2 = alice.sign(&[2], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			(result1, result2)
		});

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let thandleb = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut bob = ThresholdSigner::new(1, 2, &mut rng, &mut r1[..], &mut s1[..]).unwrap();
			let result1 = bob.sign(&[0], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			let result2 = bob.sign(&[2], &"Lorem ipsum dolor sit amet".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			(result1, result2)
		});

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);
		
		let thandlec = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut charlie = ThresholdSigner::new(2, 2, &mut rng, &mut r2[..], &mut s2[..]).unwrap();
			let result1 = charlie.sign(&[0], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
			let result2 = charlie.sign(&[1], &"Lorem ipsum dolor sit amet".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
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
	fn test_mpecdsa_3p2trefresh_gen() {

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(3);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandlea = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut alice = ThresholdSigner::new(0, 2, &mut rng, &mut r0[..], &mut s0[..]).unwrap();
			let result1 = alice.sign_and_gen_refresh(&[1], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &"YW".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			let result2 = alice.sign_and_gen_refresh(&[2], &"etaoin shrdlu".as_bytes(), &"YTMP".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			(result1, result2)
		});

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let thandleb = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut bob = ThresholdSigner::new(1, 2, &mut rng, &mut r1[..], &mut s1[..]).unwrap();
			let result1 = bob.sign_and_gen_refresh(&[0], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &"YW".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			let result2 = bob.sign_and_gen_refresh(&[2], &"Lorem ipsum dolor sit amet".as_bytes(), &"YWQMD".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			(result1, result2)
		});

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);
		
		let thandlec = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut charlie = ThresholdSigner::new(2, 2, &mut rng, &mut r2[..], &mut s2[..]).unwrap();
			let result1 = charlie.sign_and_gen_refresh(&[0], &"etaoin shrdlu".as_bytes(), &"YTMP".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
			let result2 = charlie.sign_and_gen_refresh(&[1], &"Lorem ipsum dolor sit amet".as_bytes(), &"YWQMD".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
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
	fn test_mpecdsa_3p2trefresh_gen_apply() {

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(3);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandlea = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut alice = ThresholdSigner::new(0, 2, &mut rng, &mut r0[..], &mut s0[..]).unwrap();
			let result1 = alice.sign_and_gen_refresh(&[1], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &"YW".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			let result2 = alice.sign_and_gen_refresh(&[2], &"etaoin shrdlu".as_bytes(), &"YTMP".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			(result1, result2, alice)
		});

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let thandleb = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut bob = ThresholdSigner::new(1, 2, &mut rng, &mut r1[..], &mut s1[..]).unwrap();
			let result1 = bob.sign_and_gen_refresh(&[0], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &"YW".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			let result2 = bob.sign_and_gen_refresh(&[2], &"Lorem ipsum dolor sit amet".as_bytes(), &"YWQMD".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			(result1, result2, bob)
		});

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);
		
		let thandlec = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut charlie = ThresholdSigner::new(2, 2, &mut rng, &mut r2[..], &mut s2[..]).unwrap();
			let result1 = charlie.sign_and_gen_refresh(&[0], &"etaoin shrdlu".as_bytes(), &"YTMP".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
			let result2 = charlie.sign_and_gen_refresh(&[1], &"Lorem ipsum dolor sit amet".as_bytes(), &"YWQMD".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
			(result1, result2, charlie)
		});

		let aliceout = thandlea.join().unwrap();
		assert!(aliceout.0.is_ok());
		assert!(aliceout.1.is_ok());
		let bobout = thandleb.join().unwrap();
		assert!(bobout.0.is_ok());
		assert!(bobout.1.is_ok());
		let charlieout = thandlec.join().unwrap();
		assert!(charlieout.0.is_ok());
		assert!(charlieout.1.is_ok());

		if let ((Ok((_,ar0)),Ok((_,ar1)),mut alice), (Ok((_,br0)),Ok((_,br1)),mut bob), (Ok((_,cr0)),Ok((_,cr1)),mut charlie)) = (aliceout, bobout, charlieout) {
			for refpack in [ar0,br0,cr0,ar1,br1,cr1].iter() {
				assert!(alice.apply_refresh(&refpack).is_ok());
				assert!(bob.apply_refresh(&refpack).is_ok());
				assert!(charlie.apply_refresh(&refpack).is_ok());
			}

			let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(3);

			let mut s0 = sendvec.remove(0);
			let mut r0 = recvvec.remove(0);

			let thandlea = thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let result1 = alice.sign_and_gen_refresh(&[1], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &"YW".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
				let result2 = alice.sign_and_gen_refresh(&[2], &"etaoin shrdlu".as_bytes(), &"YTMP".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
				(result1, result2)
			});

			let mut s1 = sendvec.remove(0);
			let mut r1 = recvvec.remove(0);

			let thandleb = thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let result1 = bob.sign_and_gen_refresh(&[0], &"The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes(), &"YW".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
				let result2 = bob.sign_and_gen_refresh(&[2], &"Lorem ipsum dolor sit amet".as_bytes(), &"YWQMD".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
				(result1, result2)
			});

			let mut s2 = sendvec.remove(0);
			let mut r2 = recvvec.remove(0);
			
			let thandlec = thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let result1 = charlie.sign_and_gen_refresh(&[0], &"etaoin shrdlu".as_bytes(), &"YTMP".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
				let result2 = charlie.sign_and_gen_refresh(&[1], &"Lorem ipsum dolor sit amet".as_bytes(), &"YWQMD".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
				(result1, result2)
			});

			let aliceout = thandlea.join().unwrap();
			match aliceout.0 {
			    Ok(_) => println!("working"),
			    Err(e) => println!("{:?}", e),
			}
			//assert!(aliceout.0.is_ok());
			assert!(aliceout.1.is_ok());
			let bobout = thandleb.join().unwrap();
			assert!(bobout.0.is_ok());
			assert!(bobout.1.is_ok());
			let charlieout = thandlec.join().unwrap();
			assert!(charlieout.0.is_ok());
			assert!(charlieout.1.is_ok());

		} else {
			assert!(false);
		}
	}

	#[test]
	fn test_mpecdsa_3p3tsign() {

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(3);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandlea = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut alice = ThresholdSigner::new(0, 3, &mut rng, &mut r0[..], &mut s0[..]).unwrap();
			let result1 = alice.sign(&[1,2], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]);
			result1
		});

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let thandleb = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut bob = ThresholdSigner::new(1, 3, &mut rng, &mut r1[..], &mut s1[..]).unwrap();
			let result1 = bob.sign(&[0,2], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r1[..], &mut s1[..]);
			result1
		});

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);

		let thandlec = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut charlie = ThresholdSigner::new(2, 3, &mut rng, &mut r2[..], &mut s2[..]).unwrap();
			let result1 = charlie.sign(&[0, 1], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]);
			result1
		});

		let alice = thandlea.join().unwrap();
		assert!(alice.is_ok());
		let bob = thandleb.join().unwrap();
		assert!(bob.is_ok());
		let charlie = thandlec.join().unwrap();
		assert!(charlie.is_ok());
	}

	#[test]
	fn test_mpecdsa_7p4tsetup() {
		let threshold = 4;
		let parties = 7;
		
		let (sendvec, recvvec) = spawn_n2_channelstreams(parties);
		
		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(ii, (si, ri))| {
			thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let mut sin = si;
				let mut rin = ri;
				ThresholdSigner::new(ii, threshold, &mut rng, &mut rin, &mut sin)
			})
		}).collect::<Vec<_>>();
 
		let mut firstpk = Secp::INF;
		for handle in thandles {
			let signer = handle.join().unwrap();
			//signer.is_ok();
			assert!(signer.is_ok());
			if firstpk == Secp::INF {
				firstpk = signer.unwrap().pk;
			} else {
				assert_eq!(signer.unwrap().pk, firstpk);
			}
		}
	}

	#[test]
	fn test_mpecdsa_7p3tsetup() {
		let threshold = 3;
		let parties = 7;
		
		let (sendvec, recvvec) = spawn_n2_channelstreams(parties);
		
		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(ii, (si, ri))| {
			thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let mut sin = si;
				let mut rin = ri;
				ThresholdSigner::new(ii, threshold, &mut rng, &mut rin, &mut sin)
			})
		}).collect::<Vec<_>>();
 
		let mut firstpk = Secp::INF;
		for handle in thandles {
			let signer = handle.join().unwrap();
			assert!(signer.is_ok());
			if firstpk == Secp::INF {
				firstpk = signer.unwrap().pk;
			} else {
				assert_eq!(signer.unwrap().pk, firstpk);
			}
		}
	}

	#[test]
	fn test_mpecdsa_7p5tsign() {
		let threshold = 5;
		let parties : usize = 7;

		let (sendvec, recvvec) = spawn_n2_channelstreams(parties);
		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(ii, (si, ri))| {
			thread::spawn(move || {
				let mut rng = rand::thread_rng();
				let mut sin = si;
				let mut rin = ri;
				let mut signer = ThresholdSigner::new(ii, threshold, &mut rng, &mut rin[..], &mut sin[..])?;
				if ii < threshold {
					signer.sign(&(0usize..ii).chain((ii+1)..threshold).collect::<Vec<usize>>(), &"etaoin shrdlu".as_bytes(), &mut rng, &mut rin[..], &mut sin[..])
				} else {
					Ok(None)
				}
			})
		}).collect::<Vec<_>>();

		let mut somecount = 0;
		for handle in thandles {
			let result = handle.join().unwrap();
			assert!(result.is_ok());
			if result.is_ok() {
				let res2 = result.unwrap();
				if res2.is_some() {
					somecount += 1;
				}
			}
		}
		assert_eq!(somecount, threshold);
	}

	#[bench]
	fn bench_ecdsa_2psign(b: &mut Bencher) -> () {
		let msg = "The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();
		let mut rng = rand::thread_rng();
		let ska = SecpOrd::rand(&mut rng);
		let skb = SecpOrd::rand(&mut rng);

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(2);

		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);

		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);

		let thandle = thread::spawn(move || {


			let mut rng = rand::thread_rng();
			let bob = Bob2P::new(&skb,&mut rng, &mut r1[1].as_mut().unwrap(), &mut s1[1].as_mut().unwrap()).expect("Failed to instantiate Bob");
			
			let mut keepgoing = [1u8; 1];

			r1[1].as_mut().unwrap().read_exact(&mut keepgoing).expect("Bob failed to read (1)");
			while keepgoing[0] > 0 {
				bob.sign(&msg, &mut rng, &mut r1[1].as_mut().unwrap(), &mut s1[1].as_mut().unwrap()).expect("Bob failed to sign");
				r1[1].as_mut().unwrap().read_exact(&mut keepgoing).expect("Bob failed to read (2)");
			}
		});

		let alice = Alice2P::new(&ska,&mut rng, &mut r2[0].as_mut().unwrap(), &mut s2[0].as_mut().unwrap()).expect("Failed to instantiate Alice");
		b.iter(|| { 
			s2[0].as_mut().unwrap().write(&[1]).expect("Alice failed to write (1)");
			s2[0].as_mut().unwrap().flush().expect("Alice failed to flush");
			alice.sign(&msg, &mut rng, &mut r2[0].as_mut().unwrap(), &mut s2[0].as_mut().unwrap()).expect("Bob failed to sign");
		});
		s2[0].as_mut().unwrap().write(&[0]).expect("Alice failed to write (2)");
		s2[0].as_mut().unwrap().flush().expect("Alice failed to flush");

		thandle.join().unwrap();
	}

	#[bench]
	fn bench_ecdsa_3p2tsetup(b: &mut Bencher) -> () {
		let mut rng = rand::thread_rng();
		let threshold = 2;
		let parties = 3;

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(parties);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(iiminusone, (si, ri))| {			
			thread::spawn(move || {
				let ii = iiminusone + 1;
				let mut sin = si;
				let mut rin = ri;
				let mut rng = rand::thread_rng();

				let mut keepgoing = [1u8; 1];
				rin[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (1)", ii));
				while keepgoing[0] > 0 {
					ThresholdSigner::new(ii, threshold, &mut rng, &mut rin[..], &mut sin[..]).expect(&format!("Party {} failed to setup", ii));
					rin[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (2)", ii));
				}
			})
		}).collect::<Vec<_>>();

		b.iter(|| { 
			for ii in 1..parties {
				s0[ii].as_mut().unwrap().write(&[1]).expect("Party 0 failed to write (1)");
				s0[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
			}
			ThresholdSigner::new(0, threshold, &mut rng, &mut r0[..], &mut s0[..]).expect("Party 0 failed to setup");
		});
		for ii in 1..parties {
			s0[ii].as_mut().unwrap().write(&[0]).expect("Party 0 failed to write (2)");
			s0[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
		}
		for handle in thandles {
			handle.join().unwrap();
		}	
	}

	#[bench]
	fn bench_ecdsa_3p2tsign(b: &mut Bencher) -> () {
		let msg = "The Quick Brown Fox Jumped Over The Lazy Dog".as_bytes();
		
		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(3);
		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);
		let mut s1 = sendvec.remove(0);
		let mut r1 = recvvec.remove(0);
		let mut s2 = sendvec.remove(0);
		let mut r2 = recvvec.remove(0);

		let thandlec = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut charlie = ThresholdSigner::new(2, 2, &mut rng, &mut r2[..], &mut s2[..]).unwrap();
			charlie.sign(&[0], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r2[..], &mut s2[..]).unwrap();
		});

		let thandleb = thread::spawn(move || {
			let mut rng = rand::thread_rng();
			let mut bob = ThresholdSigner::new(1, 2, &mut rng, &mut r1[..], &mut s1[..]).unwrap();
			let mut keepgoing = [1u8; 1];
			r1[0].as_mut().unwrap().read_exact(&mut keepgoing).expect("Bob failed to read (1)");
			while keepgoing[0] > 0 {
				bob.sign(&[0], &msg, &mut rng,  &mut r1[..], &mut s1[..]).expect("Bob failed to sign");
				r1[0].as_mut().unwrap().read_exact(&mut keepgoing).expect("Bob failed to read (2)");
			}
		});

		let mut rng = rand::thread_rng();

		let mut alice = ThresholdSigner::new(0, 2, &mut rng, &mut r0[..], &mut s0[..]).unwrap();
		alice.sign(&[2], &"etaoin shrdlu".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]).unwrap();
		thandlec.join().unwrap();
			
		b.iter(|| { 
			s0[1].as_mut().unwrap().write(&[1]).expect("Alice failed to write (1)");
			s0[1].as_mut().unwrap().flush().expect("Alice failed to flush");
			alice.sign(&[1], &msg, &mut rng, &mut r0[..], &mut s0[..]).expect("Alice failed to sign");
		});
		s0[1].as_mut().unwrap().write(&[0]).expect("Alice failed to write (2)");
		s0[1].as_mut().unwrap().flush().expect("Alice failed to flush");
		thandleb.join().unwrap();
	}

	#[bench]
	fn bench_ecdsa_3p3tsign(b: &mut Bencher) {
		let parties = 3;
		let threshold = 3;

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(parties);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(iiminusone, (si, ri))| {			
			thread::spawn(move || {
				let ii = iiminusone + 1;
				let mut sin = si;
				let mut rin = ri;
				let mut rng = rand::thread_rng();
				let mut rngs = Vec::with_capacity(parties);
				for _ in 0..parties {
					let mut newrng = rand::ChaChaRng::new_unseeded();
					newrng.set_counter(rng.next_u64(), rng.next_u64());
					rngs.push(newrng);
				}
				
				let mut signer = ThresholdSigner::new(ii, threshold, &mut rng, &mut rin[..], &mut sin[..]).unwrap();

				let mut keepgoing = [1u8; 1];
				rin[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (1)", ii));
				while keepgoing[0] > 0 {
					if ii < threshold {
						signer.sign(&(0usize..ii).chain((ii+1)..threshold).collect::<Vec<usize>>(), &"etaoin shrdlu".as_bytes(), &mut rng, &mut rin[..], &mut sin[..]).unwrap();
					}
					rin[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (2)", ii));
				}
			})
		}).collect::<Vec<_>>();

		let mut rng = rand::thread_rng();
		let mut rngs = Vec::with_capacity(parties);
		for _ in 0..parties {
			let mut newrng = rand::ChaChaRng::new_unseeded();
			newrng.set_counter(rng.next_u64(), rng.next_u64());
			rngs.push(newrng);
		}

		let mut signer = ThresholdSigner::new(0, threshold, &mut rng, &mut r0[..], &mut s0[..]).unwrap();

		b.iter(|| { 
			for ii in 1..parties {
				s0[ii].as_mut().unwrap().write(&[1]).expect("Party 0 failed to write (1)");
				s0[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
			}
			signer.sign(&(1..(threshold)).collect::<Vec<usize>>(), &"etaoin shrdlu".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]).unwrap();
		});

		for ii in 1..parties {
			s0[ii].as_mut().unwrap().write(&[0]).expect("Party 0 failed to write (2)");
			s0[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
		}
		for handle in thandles {
			handle.join().unwrap();
		}	
	}

	#[bench]
	fn bench_ecdsa_7p7tsign(b: &mut Bencher) {
		let parties = 7;
		let threshold = 7;

		let (mut sendvec, mut recvvec) = spawn_n2_channelstreams(parties);

		let mut s0 = sendvec.remove(0);
		let mut r0 = recvvec.remove(0);

		let thandles = sendvec.into_iter().zip(recvvec.into_iter()).enumerate().map(|(iiminusone, (si, ri))| {			
			thread::spawn(move || {
				let ii = iiminusone + 1;
				let mut sin = si;
				let mut rin = ri;
				let mut rng = rand::thread_rng();
				let mut rngs = Vec::with_capacity(parties);
				for _ in 0..parties {
					let mut newrng = rand::ChaChaRng::new_unseeded();
					newrng.set_counter(rng.next_u64(), rng.next_u64());
					rngs.push(newrng);
				}
				
				let mut signer = ThresholdSigner::new(ii, threshold, &mut rng, &mut rin[..], &mut sin[..]).unwrap();

				let mut keepgoing = [1u8; 1];
				rin[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (1)", ii));
				while keepgoing[0] > 0 {
					if ii < threshold {
						signer.sign(&(0usize..ii).chain((ii+1)..threshold).collect::<Vec<usize>>(), &"etaoin shrdlu".as_bytes(), &mut rng, &mut rin[..], &mut sin[..]).unwrap();
					}
					rin[0].as_mut().unwrap().read_exact(&mut keepgoing).expect(&format!("Party {} failed to read (2)", ii));
				}
			})
		}).collect::<Vec<_>>();

		let mut rng = rand::thread_rng();
		let mut rngs = Vec::with_capacity(parties);
		for _ in 0..parties {
			let mut newrng = rand::ChaChaRng::new_unseeded();
			newrng.set_counter(rng.next_u64(), rng.next_u64());
			rngs.push(newrng);
		}

		let mut signer = ThresholdSigner::new(0, threshold, &mut rng, &mut r0[..], &mut s0[..]).unwrap();

		b.iter(|| { 
			for ii in 1..parties {
				s0[ii].as_mut().unwrap().write(&[1]).expect("Party 0 failed to write (1)");
				s0[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
			}
			signer.sign(&(1..(threshold)).collect::<Vec<usize>>(), &"etaoin shrdlu".as_bytes(), &mut rng, &mut r0[..], &mut s0[..]).unwrap();
		});

		for ii in 1..parties {
			s0[ii].as_mut().unwrap().write(&[0]).expect("Party 0 failed to write (2)");
			s0[ii].as_mut().unwrap().flush().expect("Party 0 failed to flush");
		}
		for handle in thandles {
			handle.join().unwrap();
		}	
	}
}