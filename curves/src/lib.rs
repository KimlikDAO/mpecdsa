#![feature(test)]
#![feature(specialization)]

/// Trait for a generic field element in Zq
///
/// Can be specific implementations for 2^255-19, or a generic one for all Fq.
//  This trait is used to instantiate an elliptic curve group generically
/// by specifying the field over which the curve points are added, and
/// specifying the curve coefficients.
///
/// aas, neucrypt
extern crate test;

pub mod ecdsa;
pub mod f_4141;
pub mod f_fc2f;
pub mod precomp;
pub mod secp256k1;

pub type SecpOrd = f_4141::FSecp256Ord;
pub type Secp = secp256k1::P256<f_fc2f::FSecp256, SecpOrd>;

use std::fmt::{Debug, Display};

pub trait Fq: Copy + Debug + Display + Eq {
    const ONE: Self;
    const ZERO: Self;
    const NBITS: usize;
    const NBYTES: usize;

    fn is_zero(&self) -> bool;
    fn is_one(&self) -> bool;

    fn from_slice(r: &[u64]) -> Self;
    //fn tostring(&self) -> String;
    fn add(&self, r: &Self) -> Self;
    fn sub(&self, r: &Self) -> Self;
    fn sqr(&self) -> Self;
    fn sqrt(&self) -> Result<Self, &'static str>;

    fn neg(&self, i: u64) -> Self;
    fn inv(&self) -> Self;

    fn to_bytes(&self, b: &mut [u8]);
    fn from_bytes(b: &[u8]) -> Self;

    fn rand(rng: &mut dyn rand::Rng) -> Self;
    fn mul(&self, b: &Self) -> Self;
    fn muli(&self, b: u64) -> Self;

    fn equals(&self, b: &Self) -> bool;

    // number of bits in representation
    fn bit(&self, i: u32) -> bool;

    fn normalize(&mut self);
    fn normalize_weak(&mut self);

    // memory oblivious routines
    // sets y = (1-sel)*a + sel*b with an oblivious memory access pattern
    fn mux(y: &mut Self, a: &Self, b: &Self, sel: u32);
    // swaps a and b if sel=1 with an oblivious memory access pattern
    fn swap(a: &mut Self, b: &mut Self, sel: u32);
    fn mov(&mut self, a: &Self, sel: bool);
}

/// trait needed by a field that represents Z modulo the order of a group
pub trait Ford: Copy + Debug + Display + Eq {
    const ONE: Self;
    const ZERO: Self;
    const NBITS: usize;
    const NBYTES: usize;

    fn from_slice(r: &[u64]) -> Self;

    fn is_zero(&self) -> bool;
    fn rand(rng: &mut dyn rand::Rng) -> Self;

    //fn nbits() -> usize;
    fn bit(&self, i: usize) -> bool;
    fn add(&self, r: &Self) -> Self;
    fn sub(&self, r: &Self) -> Self;
    fn mul(&self, b: &Self) -> Self;
    fn pow_native(&self, n: u64) -> Self;
    fn inv(&self) -> Self;
    fn sqr(&self) -> Self;
    fn neg(&self) -> Self;

    fn to_bytes(&self, b: &mut [u8]);
    fn from_bytes(b: &[u8]) -> Self;
    fn from_native(b: u64) -> Self;
    fn get_window(&self, i: usize) -> u8;
}

pub trait ECGroup<F, T>: Eq + PartialEq + Debug + Display
where
    F: Fq,
    T: Ford,
    Self: std::marker::Sized,
{
    const INF: Self;
    const NBYTES: usize;

    /// returns the generator
    /// this should be a constant, but at the time, rust doesnt allow
    /// a const trait field to be constructed using F::from_slice so there
    /// is no way to specify the generator
    fn gen() -> Self;

    fn x(&self) -> F;
    fn y(&self) -> F;

    /// constructs a point from an x,y coordinate
    /// checks that the point is actually on the curve, else returns Error
    fn from_xy(x: &F, y: &F) -> Result<Self, &'static str>;

    fn rand(rng: &mut dyn rand::Rng) -> (T, Self);
    // fn hash_to_curve(message: &[u8]) -> Self;

    fn is_infinity(&self) -> bool;

    /* set to affine - from (x,y,z) to (x,y) */
    fn affine(&self) -> Self;

    /* returns P + Q  */
    fn op(a: &Self, b: &Self) -> Self;
    fn dbl(&self) -> Self;
    fn neg(&self) -> Self;

    fn scalar(&self, x: &T) -> Self;
    fn scalar_table(&self, x: &T) -> Self;
    fn scalar_gen(x: &T) -> Self;
    fn scalar_table_multi(table: &[Self], x: &T) -> Self;
    fn precomp_table(x: &Self) -> Vec<Self>;

    fn to_bytes(&self, b: &mut [u8]);
    fn from_bytes(b: &[u8]) -> Self;
}
