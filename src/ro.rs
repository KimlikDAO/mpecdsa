/***********
 * This module implements a tagging system for Random Oracle queries (i.e. hash function calls)
 * Tags come in two flavors: dyadic tags, which are shared between pairs of parties and require no synchronization,
 * and broadcast tags, which are shared among arbitrary subsets of a large group of parties, operate in a single
 * source -> multiple destinations fashion, and require synchronization among the parties before they can be used.
 ***********/

use std::result::Result;
use std::sync::atomic::{AtomicU64,Ordering};

use rand::{Rng};

use byteorder::{ByteOrder, LittleEndian};

use super::mpecdsa_error::*;
use super::*;

pub struct TagRange {
	base: [u8;RO_TAG_SIZE],
	counter: u64,
	length: u64
}

pub struct GroupROTagger {
	playerindex: usize,
	puids: Vec<[u8;HASH_SIZE]>,
	subgroup_mask: Vec<bool>,
	subgroup_map_to_super: Vec<Option<usize>>,
	supergroup_map_to_sub: Vec<Option<usize>>,
	subgroup_size: usize,
	dyadic_bases: Vec<[u8;RO_TAG_SIZE]>,
	dyadic_counters: Vec<AtomicU64>,
	broadcast_bases: Vec<[u8;RO_TAG_SIZE]>,
	broadcast_counters: Vec<AtomicU64>
}

pub struct DyadicROTagger<'a> {
	#[allow(dead_code)]
	playerindex: usize,
	counterparty: usize,
	dyadic_base: &'a [u8;RO_TAG_SIZE],
	dyadic_counter: &'a AtomicU64,
	counterparty_broadcast_base: &'a [u8;RO_TAG_SIZE],
	counterparty_broadcast_counter: &'a AtomicU64
}

pub struct ModelessGroupROTagger<'a> {
	tagger: &'a GroupROTagger,
	is_dyadic: bool
}

pub struct ModelessDyadicROTagger<'a> {
	tagger: &'a DyadicROTagger<'a>,
	is_dyadic: bool
}

pub trait ROTagger {	
	fn advance_counterparty_broadcast_counter(&self, usize, u64) -> Result<(),MPECDSAError>;
	fn next_counterparty_broadcast_tag(&self, usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError>;
	fn allocate_counterparty_broadcast_range(&self, counterparty:usize, length:u64) -> Result<TagRange,MPECDSAError>;

	fn advance_counterparty_dyadic_counter(&self, usize, u64) -> Result<(),MPECDSAError>;
	fn next_counterparty_dyadic_tag(&self, counterparty:usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError>;
	fn allocate_counterparty_dyadic_range(&self, counterparty:usize, length:u64) -> Result<TagRange,MPECDSAError>;
}

pub trait ModelessROTagger {
	fn next_tag(&self) -> Result<[u8;RO_TAG_SIZE],MPECDSAError>;
	fn allocate_range(&self, length:u64) -> Result<TagRange,MPECDSAError>;
	fn next_counterparty_tag(&self, usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError>;
	fn allocate_counterparty_range(&self, counterparty:usize, length:u64) -> Result<TagRange,MPECDSAError>;
}

// works over supergroup indices
fn party_broadcast_base(party:usize, puids:&[[u8;HASH_SIZE]], subgroup_mask:&[bool]) -> [u8;RO_TAG_SIZE] {
	let mut hashin = vec![0u8; puids.len() * HASH_SIZE + 8];
	LittleEndian::write_u64(&mut hashin[0..8], party as u64);
	for ii in 0..puids.len() {
		if subgroup_mask[ii] {
			hashin[(ii*HASH_SIZE+8)..((ii+1)*HASH_SIZE+8)].copy_from_slice(&puids[ii][..]);
		}
	}
	let mut hashout = [0u8;HASH_SIZE];
	hash(&mut hashout, &hashin);
	let mut ro_out = [0u8;RO_TAG_SIZE];
	ro_out.copy_from_slice(&hashout[0..RO_TAG_SIZE]);
	ro_out
}



impl GroupROTagger {
	// this constructor initializes all counters to 0 and does not allow anyone to complain - in practice, parties should be able to object to each others' counter values
	pub fn from_network_unverified<TR:Read, TW:Write>(playerindex:usize, rng: &mut dyn Rng, recv:&mut [Option<&mut TR>], send:&mut [Option<&mut TW>]) -> Result<GroupROTagger,MPECDSAError> {
		if recv.len() != send.len() { panic!("Number of Send streams does not match number of Recv streams"); }
		
		let playercount = recv.len();
		let mut puid_seed = vec![0u8; playercount*HASH_SIZE];
		rng.fill_bytes(&mut puid_seed[(playerindex*HASH_SIZE)..((playerindex+1)*HASH_SIZE)]);

		for ii in 0..playercount {
			if ii != playerindex {
				send[ii].as_mut().unwrap().write(&puid_seed[(playerindex*HASH_SIZE)..((playerindex+1)*HASH_SIZE)])?;
				send[ii].as_mut().unwrap().flush()?;
			}
		}

		for ii in 0..playercount {
			if ii != playerindex {
				recv[ii].as_mut().unwrap().read_exact(&mut puid_seed[(ii*HASH_SIZE)..((ii+1)*HASH_SIZE)])?;
			}
		}

		Self::from_seed(playerindex, playercount, &mut puid_seed, &vec![true;playercount])
	}

	// this constructor initializes all counters to 0 and does not allow anyone to complain - in practice, parties should be able to object to each others' counter values
	// note also that playerindex is given in supergroup indices!
	fn from_seed(playerindex:usize, playercount:usize, puid_seed: &[u8], subgroup_mask: &[bool]) -> Result<GroupROTagger,MPECDSAError> {
		if subgroup_mask.len() != playercount { panic!("Subgroup mask length does not match player count"); }
		if !subgroup_mask[playerindex] {return Err(MPECDSAError::General(GeneralError::new("Cannot apply subgroup mask that omits active party")));}

		let mut ps = vec![0u8; puid_seed.len()+8];
		let mut puids = vec![[0u8;HASH_SIZE]; playercount];

		ps[8..puid_seed.len()+8].copy_from_slice(puid_seed);

		for ii in 0..playercount {
			LittleEndian::write_u64(&mut ps[0..8], ii as u64);
			hash(&mut puids[ii], &ps);
		}

		// each dyadic base is the hash of the uids of the two parties that share it, in numerical order
		let mut dyadic_bases = vec![[0u8;RO_TAG_SIZE]; playercount];
		let mut hashin = [0u8; 2*HASH_SIZE];
		let mut hashout = [0u8;HASH_SIZE];
		
		// first calculate dyadic bases for pairings in which this party comes second
		hashin[HASH_SIZE..(2*HASH_SIZE)].copy_from_slice(&puids[playerindex]);
		for ii in 0..playerindex {
			hashin[0..HASH_SIZE].copy_from_slice(&puids[ii]);
			hash(&mut hashout, &hashin);
			dyadic_bases[ii].copy_from_slice(&hashout[0..RO_TAG_SIZE]);
		}
		// then calculate dyadic bases for pairings in which this party comes first
		hashin[0..HASH_SIZE].copy_from_slice(&puids[playerindex]);
		for ii in playerindex+1..playercount {
			hashin[HASH_SIZE..(2*HASH_SIZE)].copy_from_slice(&puids[ii]);
			hash(&mut hashout, &hashin);
			dyadic_bases[ii].copy_from_slice(&hashout[0..RO_TAG_SIZE]);
		}

		// now, finally, the broadcast bases
		let mut broadcast_bases = vec![[0u8;RO_TAG_SIZE];playercount];
		let mut subgroup_map_to_super = vec![None;playercount];
		let mut supergroup_map_to_sub = vec![None;playercount];
		let mut subgroup_size = 0;
		for ii in 0..playercount {
			if subgroup_mask[ii] {
				subgroup_map_to_super[subgroup_size] = Some(ii);
				supergroup_map_to_sub[ii] = Some(subgroup_size);
				broadcast_bases[ii] = party_broadcast_base(ii, &puids, subgroup_mask);
				subgroup_size += 1;	
			}
		}

		// initialize all counters to 0. SEE NOTE AT FUNCTION HEADER.
		let mut dyadic_counters = Vec::with_capacity(playercount);
		let mut broadcast_counters = Vec::with_capacity(playercount);
		for _ in 0..playercount {
			dyadic_counters.push(AtomicU64::new(0));
			broadcast_counters.push(AtomicU64::new(0));
		}

		Ok(GroupROTagger {
			playerindex: playerindex,
			puids: puids,
			subgroup_mask: subgroup_mask.to_vec(),
			subgroup_map_to_super: subgroup_map_to_super,
			supergroup_map_to_sub: supergroup_map_to_sub,
			subgroup_size: subgroup_size,
			dyadic_bases: dyadic_bases,
			dyadic_counters: dyadic_counters,
			broadcast_bases: broadcast_bases,
			broadcast_counters: broadcast_counters
		})
	}

	// Why not just implement Clone? We don't want people doing it accidentally. Cloning an ROTagger is not secure.
	// Note: this PANICS if any counters are locked! Use with extreme caution.
	pub fn unsafe_clone(&self) -> GroupROTagger {
		let mut dyadic_counters_cloned = Vec::with_capacity(self.puids.len());
		let mut broadcast_counters_cloned = Vec::with_capacity(self.puids.len());
		for ii in 0..self.puids.len() {
			dyadic_counters_cloned.push(AtomicU64::new(self.dyadic_counters[ii].load(Ordering::Relaxed)));
			broadcast_counters_cloned.push(AtomicU64::new(self.broadcast_counters[ii].load(Ordering::Relaxed)));
		}

		GroupROTagger {
			playerindex: self.playerindex,
			puids: self.puids.clone(),
			subgroup_mask: self.subgroup_mask.clone(),
			subgroup_map_to_super: self.subgroup_map_to_super.clone(),
			supergroup_map_to_sub: self.supergroup_map_to_sub.clone(),
			subgroup_size: self.subgroup_size,
			dyadic_bases: self.dyadic_bases.clone(),
			dyadic_counters: dyadic_counters_cloned,
			broadcast_bases: self.broadcast_bases.clone(),
			broadcast_counters: broadcast_counters_cloned
		}
	}

	pub fn apply_subgroup_mask(&mut self, new_mask: &[bool]) -> Result<(),MPECDSAError> {
		if new_mask.len() != self.puids.len() {panic!("Subgroup mask length does not match player count");}
		//if !new_mask[self.playerindex] {return Err(MPECDSAError::General(GeneralError::new("Cannot apply subgroup mask that omits active party")));}

		let mut subgroup_size = 0;
		for ii in 0..new_mask.len() {
			if new_mask[ii] {
				self.subgroup_map_to_super[subgroup_size] = Some(ii);
				self.supergroup_map_to_sub[ii] = Some(subgroup_size);
				self.broadcast_bases[ii] = party_broadcast_base(ii, &self.puids, new_mask);
				subgroup_size += 1;
			} else {
				self.supergroup_map_to_sub[ii] = None;
			}
		}
		for ii in subgroup_size..new_mask.len() {
			self.subgroup_map_to_super[ii] = None;
		}

		self.subgroup_size = subgroup_size;
		self.subgroup_mask = new_mask.to_vec();
		Ok(())
	}

	pub fn apply_subgroup_list(&mut self, list: &[usize]) -> Result<(),MPECDSAError> {
		if list.len() > self.puids.len() {panic!("Subgroup list length greater than player count");}
		let mut mask = vec![false;self.puids.len()];
		for user in list {
			if *user >= mask.len() {return Err(MPECDSAError::General(GeneralError::new("Subgroup list contains invalid user")))};
			mask[*user] = true;
		}
		self.apply_subgroup_mask(&mask)
	}

	pub fn remove_subgroup_mask(&mut self) {
		self.apply_subgroup_mask(&vec![true;self.puids.len()]).unwrap();
	}

	pub fn get_subgroup_party_count(&self) -> usize {
		self.subgroup_size
	}

	pub fn get_supergroup_party_count(&self) -> usize {
		self.puids.len()
	}

	pub fn current_broadcast_counter(&self) -> u64 {
		self.broadcast_counters[self.playerindex].load(Ordering::Relaxed)
	}

	pub fn advance_broadcast_counter(&self, tagindex: u64) -> Result<(),MPECDSAError> {
		self.advance_counterparty_broadcast_counter(self.supergroup_map_to_sub[self.playerindex].unwrap(), tagindex)
	}

	pub fn next_broadcast_tag(&self) -> [u8;RO_TAG_SIZE] {
		self.next_counterparty_broadcast_tag(self.supergroup_map_to_sub[self.playerindex].unwrap()).unwrap()
	}

	pub fn allocate_broadcast_range(&self, length: u64) -> TagRange {
		self.allocate_counterparty_broadcast_range(self.supergroup_map_to_sub[self.playerindex].unwrap(), length).unwrap()
	}

	pub fn fork_tagger(&self) -> GroupROTagger {
		self.fork_counterparty_tagger(self.supergroup_map_to_sub[self.playerindex].unwrap()).unwrap()
	}

	pub fn fork_counterparty_tagger(&self, counterparty: usize) -> Result<GroupROTagger,MPECDSAError> {
		// implicitly uses subgroup indices
		let tag = self.next_counterparty_broadcast_tag(counterparty)?;
		Self::from_seed(self.playerindex, self.puids.len(), &tag[..], &self.subgroup_mask)
	}

	pub fn get_dyadic_tagger<'a>(&'a self, counterparty:usize) -> Result<DyadicROTagger<'a>,MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}.", counterparty))))?;
		//if supercounterparty == self.playerindex {panic!("Cannot get dyadic tagger for self.");}
		Ok(DyadicROTagger {
			playerindex: self.supergroup_map_to_sub[self.playerindex].unwrap(),
			counterparty: counterparty, // uses subgroup indices
			dyadic_base: &self.dyadic_bases[supercounterparty],
			dyadic_counter: &self.dyadic_counters[supercounterparty],
			counterparty_broadcast_base: &self.broadcast_bases[supercounterparty],
			counterparty_broadcast_counter: &self.broadcast_counters[supercounterparty]
		})
	}
}

impl ROTagger for GroupROTagger {
	fn advance_counterparty_broadcast_counter(&self, counterparty:usize, tagindex: u64) -> Result<(),MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}.", counterparty))))?;
		let oldcounter = self.broadcast_counters[supercounterparty].fetch_max(tagindex, Ordering::Relaxed);
		if oldcounter > tagindex {
			Err(MPECDSAError::Proof(ProofError::new(&format!("Party {}/{} (subgroup/supergroup) attempted to reuse Random Oracle tag", counterparty, supercounterparty))))
		} else {
			Ok(())
		}
	}	

	fn next_counterparty_broadcast_tag(&self, counterparty:usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}.", counterparty))))?;
		let oldcounter = self.broadcast_counters[supercounterparty].fetch_add(1, Ordering::Relaxed);
		let mut ro_out = [0u8;RO_TAG_SIZE];
		ro_out.copy_from_slice(&self.broadcast_bases[supercounterparty]);
		let temp = LittleEndian::read_u64(&ro_out[0..8]).wrapping_add(oldcounter);
		LittleEndian::write_u64(&mut ro_out[0..8], temp);
		Ok(ro_out)
	}

	fn allocate_counterparty_broadcast_range(&self, counterparty:usize, length: u64) -> Result<TagRange,MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}.", counterparty))))?;
		let mut base = [0u8;RO_TAG_SIZE];
		base.copy_from_slice(&self.broadcast_bases[supercounterparty]);
		let oldcounter = self.broadcast_counters[supercounterparty].fetch_add(length, Ordering::Relaxed);
		Ok(TagRange {
			base: base,
			counter: oldcounter,
			length: oldcounter + length
		})
	}

	fn advance_counterparty_dyadic_counter(&self, counterparty:usize, tagindex: u64) -> Result<(),MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}", counterparty))))?;
		let oldcounter = self.dyadic_counters[supercounterparty].fetch_max(tagindex, Ordering::Relaxed);
		if oldcounter > tagindex {
			Err(MPECDSAError::Proof(ProofError::new(&format!("Party {}/{} (subgroup/supergroup) attempted to reuse Random Oracle tag", counterparty, supercounterparty))))
		} else {
			Ok(())
		}
	}

	fn next_counterparty_dyadic_tag(&self, counterparty:usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}", counterparty))))?;
		let oldcounter = self.dyadic_counters[supercounterparty].fetch_add(1, Ordering::Relaxed);
		let mut ro_out = [0u8;RO_TAG_SIZE];
		ro_out.copy_from_slice(&self.dyadic_bases[supercounterparty]);
		let temp = LittleEndian::read_u64(&ro_out[0..8]).wrapping_add(oldcounter);
		LittleEndian::write_u64(&mut ro_out[0..8], temp);
		Ok(ro_out)
	}

	fn allocate_counterparty_dyadic_range(&self, counterparty:usize, length: u64) -> Result<TagRange,MPECDSAError> {
		let supercounterparty = self.subgroup_map_to_super[counterparty].ok_or(MPECDSAError::General(GeneralError::new(&format!("Invalid counterparty {}", counterparty))))?;
		let mut base = [0u8;RO_TAG_SIZE];
		base.copy_from_slice(&self.dyadic_bases[supercounterparty]);
		let oldcounter = self.dyadic_counters[supercounterparty].fetch_add(length, Ordering::Relaxed);
		Ok(TagRange {
			base: base,
			counter: oldcounter,
			length: oldcounter + length
		})
	}
}

impl<'a> ModelessGroupROTagger<'a> {
	pub fn new(grot: &GroupROTagger, is_dyadic: bool) -> ModelessGroupROTagger {
		ModelessGroupROTagger {
			tagger: grot,
			is_dyadic: is_dyadic
		}
	}
}

impl<'a>  ModelessROTagger for ModelessGroupROTagger<'a> {
	fn next_tag(&self) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.is_dyadic {
			Err(MPECDSAError::General(GeneralError::new("Tried to generate dyadic tag with no defined counterparty")))
		} else {
			Ok(self.tagger.next_broadcast_tag())
		}
	}

	fn allocate_range(&self, length:u64) -> Result<TagRange,MPECDSAError> {
		if self.is_dyadic {
			Err(MPECDSAError::General(GeneralError::new("Tried to allocate dyadic tag range with no defined counterparty")))
		} else {
			Ok(self.tagger.allocate_broadcast_range(length))
		}
	}

	fn next_counterparty_tag(&self, counterparty: usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.is_dyadic {
			self.tagger.next_counterparty_dyadic_tag(counterparty)
		} else {
			self.tagger.next_counterparty_broadcast_tag(counterparty)
		}
	}

	fn allocate_counterparty_range(&self, counterparty:usize, length:u64) -> Result<TagRange,MPECDSAError> {
		if self.is_dyadic {
			self.tagger.allocate_counterparty_dyadic_range(counterparty, length)
		} else {
			self.tagger.allocate_counterparty_broadcast_range(counterparty, length)
		}
	}
}

impl<'a> DyadicROTagger<'a> {	
	pub fn next_dyadic_tag(&self)  -> [u8;RO_TAG_SIZE] {
		self.next_counterparty_dyadic_tag(self.counterparty).unwrap()
	}

	pub fn allocate_dyadic_range(&self, length: u64)  -> TagRange {
		self.allocate_counterparty_dyadic_range(self.counterparty, length).unwrap()
	}

	pub fn next_dyadic_counterparty_broadcast_tag(&self) -> Result<[u8;RO_TAG_SIZE], MPECDSAError> {
		self.next_counterparty_broadcast_tag(self.counterparty)
	}

	pub fn allocate_dyadic_counterparty_broadcast_range(&self, length: u64)  -> TagRange {
		self.allocate_counterparty_broadcast_range(self.counterparty, length).unwrap()
	}
}

impl<'a> ROTagger for DyadicROTagger<'a> {
	fn advance_counterparty_broadcast_counter(&self, counterparty:usize, tagindex: u64) -> Result<(),MPECDSAError> {
		if self.counterparty == counterparty {
			let oldcounter = self.counterparty_broadcast_counter.fetch_max(tagindex, Ordering::Relaxed);
			if oldcounter > tagindex {
				Err(MPECDSAError::Proof(ProofError::new(&format!("Party {} attempted to reuse Random Oracle tag", counterparty))))
			} else {
				Ok(())
			}
		} else {
			Err(MPECDSAError::General(GeneralError::new("Attempted to advance broadcast RO counter for non-designated counterparty")))
		}
	}

	fn next_counterparty_broadcast_tag(&self, counterparty:usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.counterparty == counterparty {
			let oldcounter = self.counterparty_broadcast_counter.fetch_add(1, Ordering::Relaxed);
			let mut ro_out = [0u8;RO_TAG_SIZE];
			ro_out.copy_from_slice(self.counterparty_broadcast_base);
			let temp = LittleEndian::read_u64(&ro_out[0..8]).wrapping_add(oldcounter);
			LittleEndian::write_u64(&mut ro_out[0..8], temp);
			Ok(ro_out)
		} else {
			Err(MPECDSAError::General(GeneralError::new("Attempted to generate broadcast RO tag for non-designated counterparty")))
		}
	}

	fn allocate_counterparty_broadcast_range(&self, counterparty:usize, length: u64) -> Result<TagRange,MPECDSAError> {
		if self.counterparty == counterparty {
			let oldcounter = self.counterparty_broadcast_counter.fetch_add(length, Ordering::Relaxed);
			let mut base = [0u8;RO_TAG_SIZE];
			base.copy_from_slice(self.counterparty_broadcast_base);
			Ok(TagRange {
				base: base,
				counter: oldcounter,
				length: length + oldcounter
			})
		} else {
			Err(MPECDSAError::General(GeneralError::new("Attempted to allocate broadcast RO tag range for non-designated counterparty")))
		}
	}

	fn advance_counterparty_dyadic_counter(&self, counterparty:usize, tagindex: u64) -> Result<(),MPECDSAError> {
		if self.counterparty == counterparty {
			let oldcounter = self.dyadic_counter.fetch_max(tagindex, Ordering::Relaxed);
			if oldcounter > tagindex {
				Err(MPECDSAError::Proof(ProofError::new(&format!("Party {} attempted to reuse Random Oracle tag.", counterparty))))
			} else {
				Ok(())
			}
		} else {
			Err(MPECDSAError::General(GeneralError::new("Attempted to advance dyadic RO counter for non-designated counterparty.")))
		}
	}

	fn next_counterparty_dyadic_tag(&self, counterparty:usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.counterparty == counterparty {
			let oldcounter = self.dyadic_counter.fetch_add(1, Ordering::Relaxed);
			let mut ro_out = [0u8;RO_TAG_SIZE];
			ro_out.copy_from_slice(self.dyadic_base);
			let temp = LittleEndian::read_u64(&ro_out[0..8]).wrapping_add(oldcounter);
			LittleEndian::write_u64(&mut ro_out[0..8], temp);
			Ok(ro_out)
		} else {
			Err(MPECDSAError::General(GeneralError::new("Attempted to generate dyadic RO tag for non-designated counterparty.")))
		}
	}

	fn allocate_counterparty_dyadic_range(&self, counterparty:usize, length: u64) -> Result<TagRange,MPECDSAError> {
		if self.counterparty == counterparty {
			let oldcounter = self.dyadic_counter.fetch_add(length, Ordering::Relaxed);
			let mut base = [0u8;RO_TAG_SIZE];
			base.copy_from_slice(self.dyadic_base);
			Ok(TagRange {
				base: base,
				counter: oldcounter,
				length: length + oldcounter
			})
		} else {
			Err(MPECDSAError::General(GeneralError::new("Attempted to allocate dyadic RO tag range for non-designated counterparty.")))
		}
	}
}

impl<'a> ModelessDyadicROTagger<'a> {
	pub fn new(drot: &'a DyadicROTagger, is_dyadic: bool) -> ModelessDyadicROTagger<'a> {
		ModelessDyadicROTagger {
			tagger: drot,
			is_dyadic: is_dyadic
		}
	}

	pub fn next_dyadic_counterparty_tag(&self) -> Result<[u8;RO_TAG_SIZE], MPECDSAError> {
		self.next_counterparty_tag(self.tagger.counterparty)
	}

	pub fn allocate_dyadic_counterparty_range(&self, length: u64)  -> TagRange {
		self.allocate_counterparty_range(self.tagger.counterparty, length).unwrap()
	}
}

impl<'a>  ModelessROTagger for ModelessDyadicROTagger<'a> {
	fn next_tag(&self) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.is_dyadic {
			Ok(self.tagger.next_dyadic_tag())
		} else {
			Err(MPECDSAError::General(GeneralError::new("Tried to autogenerate broadcast tags from dyadic tagger.")))
		}
	}

	fn allocate_range(&self, length:u64) -> Result<TagRange,MPECDSAError> {
		if self.is_dyadic {
			Ok(self.tagger.allocate_dyadic_range(length))
		} else {
			Err(MPECDSAError::General(GeneralError::new("Tried to autogenerate broadcast tags from dyadic tagger.")))
		}
	}

	fn next_counterparty_tag(&self, counterparty: usize) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.is_dyadic {
			self.tagger.next_counterparty_dyadic_tag(counterparty)
		} else {
			self.tagger.next_counterparty_broadcast_tag(counterparty)
		}
	}

	fn allocate_counterparty_range(&self, counterparty:usize, length:u64) -> Result<TagRange,MPECDSAError> {
		if self.is_dyadic {
			self.tagger.allocate_counterparty_dyadic_range(counterparty, length)
		} else {
			self.tagger.allocate_counterparty_broadcast_range(counterparty, length)
		}
	}
}

impl TagRange {
	pub fn next(&mut self) -> Result<[u8;RO_TAG_SIZE],MPECDSAError> {
		if self.counter < self.length {
			let mut ro_out = [0u8;RO_TAG_SIZE];
			ro_out.copy_from_slice(&self.base);
			let temp = LittleEndian::read_u64(&ro_out[0..8]).wrapping_add(self.counter);
			LittleEndian::write_u64(&mut ro_out[0..8], temp);
			self.counter += 1;
			Ok(ro_out)
		} else {
			Err(MPECDSAError::General(GeneralError::new("Random Oracle tag range exhausted")))
		}
	}
}