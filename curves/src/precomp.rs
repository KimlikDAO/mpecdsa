use super::f_fc2f::FSecp256;
use super::secp256k1::P256;
/// This package holds fast rountines for computing multi-exponentations and
/// handling the specific computations needed in mul sharing
use super::{Fq, Secp, SecpOrd};

use std::marker::PhantomData;

pub const GADGET_TABLE_256: [SecpOrd; 256] = [
    SecpOrd {
        v: [0x1, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x2, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x4, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x8, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x10, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x20, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x40, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x80, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x100, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x200, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x400, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x800, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x1000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x2000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x4000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x8000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x10000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x20000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x40000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x80000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x100000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x200000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x400000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x800000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x1000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x2000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x4000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x8000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x10000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x20000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x40000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x80000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x100000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x200000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x400000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x800000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x1000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x2000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x4000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x8000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x10000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x20000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x40000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x80000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x100000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x200000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x400000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x800000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x1000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x2000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x4000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x8000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x10000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x20000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x40000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x80000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x100000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x200000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x400000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x800000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x1000000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x2000000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x4000000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x8000000000000000, 0x0, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x1, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x2, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x4, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x8, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x10, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x20, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x40, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x80, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x100, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x200, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x400, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x800, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x1000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x2000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x4000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x8000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x10000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x20000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x40000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x80000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x100000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x200000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x400000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x800000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x1000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x2000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x4000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x8000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x10000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x20000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x40000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x80000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x100000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x200000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x400000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x800000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x1000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x2000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x4000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x8000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x10000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x20000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x40000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x80000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x100000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x200000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x400000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x800000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x1000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x2000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x4000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x8000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x10000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x20000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x40000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x80000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x100000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x200000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x400000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x800000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x1000000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x2000000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x4000000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x8000000000000000, 0x0, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x1, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x2, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x4, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x8, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x10, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x20, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x40, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x80, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x100, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x200, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x400, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x800, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x1000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x2000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x4000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x8000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x10000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x20000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x40000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x80000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x100000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x200000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x400000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x800000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x1000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x2000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x4000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x8000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x10000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x20000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x40000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x80000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x100000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x200000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x400000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x800000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x1000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x2000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x4000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x8000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x10000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x20000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x40000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x80000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x100000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x200000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x400000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x800000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x1000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x2000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x4000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x8000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x10000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x20000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x40000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x80000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x100000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x200000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x400000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x800000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x1000000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x2000000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x4000000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x8000000000000000, 0x0],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x1],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x2],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x4],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x8],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x10],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x20],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x40],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x80],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x100],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x200],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x400],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x800],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x1000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x2000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x4000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x8000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x10000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x20000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x40000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x80000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x100000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x200000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x400000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x800000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x1000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x2000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x4000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x8000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x10000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x20000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x40000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x80000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x100000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x200000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x400000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x800000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x1000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x2000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x4000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x8000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x10000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x20000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x40000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x80000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x100000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x200000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x400000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x800000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x1000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x2000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x4000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x8000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x10000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x20000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x40000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x80000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x100000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x200000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x400000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x800000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x1000000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x2000000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x4000000000000000],
    },
    SecpOrd {
        v: [0x0, 0x0, 0x0, 0x8000000000000000],
    },
];

pub const P256_TABLE: [Secp; 256] = [
    P256 {
        x: FSecp256 {
            v: [
                0x2815b16f81798,
                0xdb2dce28d959f,
                0xe870b07029bfc,
                0xbbac55a06295c,
                0x79be667ef9dc,
            ],
        },
        y: FSecp256 {
            v: [
                0x7d08ffb10d4b8,
                0x48a68554199c4,
                0xe1108a8fd17b4,
                0xc4655da4fbfc0,
                0x483ada7726a3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc09b95c709ee5,
                0x4b8cef3ca7aba,
                0x5c07cd85c778e,
                0x7d6d3045406e9,
                0xc6047f9441ed,
            ],
        },
        y: FSecp256 {
            v: [
                0x431a950cfe52a,
                0x653266d0e1236,
                0x66ceaeef7f632,
                0xc339a3c584194,
                0x1ae168fea63d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa94abe8c4cd13,
                0x900ee0758474f,
                0x30b1404cc6c13,
                0x80f3581e49049,
                0xe493dbf1c10d,
            ],
        },
        y: FSecp256 {
            v: [
                0x97bdc47739922,
                0x33bfbdfe40cfe,
                0xea51448d967ae,
                0x55b75642e2098,
                0x51ed993ea0d4,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x84ef3e10a2a01,
                0x5e5af888a677,
                0x70f3c2f0a1bdd,
                0x351daff3843fb,
                0x2f01e5e15cca,
            ],
        },
        y: FSecp256 {
            v: [
                0xa2cb76cbde904,
                0xd6ba5b7617b5d,
                0x32d13b4c2e213,
                0x9949293d082a1,
                0x5c4da8a74153,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xee89e2a6dec0a,
                0x69b87a5ae9c44,
                0x1c23e97b2a313,
                0x9ec53011aabc2,
                0xe60fce93b59e,
            ],
        },
        y: FSecp256 {
            v: [
                0x32cce69616821,
                0x1e44d23f0be1f,
                0x5793710129689,
                0x95929db99f34f,
                0xf7e3507399e5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xdbd407143e65,
                0xb89904a61d75d,
                0x2f378cedacffc,
                0xa22d47b6e054e,
                0xd30199d74fb5,
            ],
        },
        y: FSecp256 {
            v: [
                0x3ff1f24106ab9,
                0xc364ed819605b,
                0x98380651f760c,
                0xd5c3b3d6dec9e,
                0x95038d9d0ae3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x918e6f874ef8b,
                0x1dcdbafd81e37,
                0x832823cfc4c6f,
                0xeab70b1051eaf,
                0xbf23c1542d16,
            ],
        },
        y: FSecp256 {
            v: [
                0x37efe66831d9f,
                0x54811e2f784dc,
                0xa5392e4c522fc,
                0x3737ad928a0b,
                0x5cb3866fc330,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x77456769a24e,
                0xd700535655647,
                0x7d1671cbcf55c,
                0x7a06696c3d09f,
                0x34ff3be4033f,
            ],
        },
        y: FSecp256 {
            v: [
                0x1067a73cc2f1a,
                0xc3e8f8b681849,
                0x832098c55df16,
                0x6c553f6619d89,
                0x5d9d11623a23,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6e23fd5f51508,
                0xabd5ac1ca1064,
                0x72de238d8c39c,
                0x9d9ea2a6e3e1,
                0x8282263212c6,
            ],
        },
        y: FSecp256 {
            v: [
                0xb6eaff6e26caf,
                0xac2f7b17bed31,
                0xb60ace62d613,
                0xdfe45e8256e83,
                0x11f8a8098557,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe2c00ef34a24d,
                0x68d9e159d0926,
                0xcf918d50adbc9,
                0x9ff3905a857a9,
                0x465370b287a7,
            ],
        },
        y: FSecp256 {
            v: [
                0x8fb20b33887f4,
                0xb215d37a10a2f,
                0xdeec2c1588e09,
                0xc082a4af8bdaf,
                0x35e531b38368,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x901b2e285131f,
                0xcdc813b088d5b,
                0x6ad6240aaec6e,
                0xbd77d664a18f6,
                0x241febb8e23c,
            ],
        },
        y: FSecp256 {
            v: [
                0x3e66f2750026d,
                0xfbd0cb5afabb,
                0x3981df8cd50fd,
                0xf8d3d6c420bd1,
                0x513378d9ff94,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb63069b920471,
                0x85f423de0dedc,
                0x3d8f8d9fc318b,
                0xfa79fce4cc298,
                0x5d1bdb4ea172,
            ],
        },
        y: FSecp256 {
            v: [
                0x30666f7b83103,
                0x9996c56e7b703,
                0x8a2265679eb1e,
                0x9e2e794bb9943,
                0x284382677937,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xce5b551e5b739,
                0x33fd2222ed73f,
                0x6fc846de0b938,
                0x865a72f99cc6c,
                0x175e159f728b,
            ],
        },
        y: FSecp256 {
            v: [
                0xa6ffee9fed695,
                0x5add24345c6ef,
                0xff71f5eacb595,
                0x79eba4ef97a51,
                0xd3506e0d9e3c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x8049e46bc47d6,
                0xb5c6da121bce7,
                0x139c62130fdfe,
                0x32d7a5ffbcc8e,
                0x423a013f03ff,
            ],
        },
        y: FSecp256 {
            v: [
                0x36e6d8b548a34,
                0xc3524f009ed12,
                0xaf6b3c7720d8e,
                0xd970a1179f7bb,
                0xb91ae00fe1e1,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xdf6f78416824a,
                0x2f3b3e2741302,
                0xcd6877649df66,
                0xb90508907a7ab,
                0x111d6a45ac1f,
            ],
        },
        y: FSecp256 {
            v: [
                0x111d42108e9d0,
                0x8996daca4ca9a,
                0xf065952f07000,
                0xaffbb90d48dbf,
                0x696911c478e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xedde01bced775,
                0x8a5ef74e56ab5,
                0xcb9dcff7290b6,
                0xc8b8ad795dbeb,
                0x4a4a6dc97ac7,
            ],
        },
        y: FSecp256 {
            v: [
                0xf8f68a78dd66d,
                0xdb424742acb2b,
                0x9c0f4571de90c,
                0x1e72943ef9f73,
                0x529911b01663,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbad8f83ff4640,
                0x7e55552ffe526,
                0x6262ee053441c,
                0xc9c99ceac05b,
                0x363d90d447b0,
            ],
        },
        y: FSecp256 {
            v: [
                0x3c7f3bee9de9,
                0x9008199ecb620,
                0x7f3363145b9a8,
                0x2221953b44539,
                0x4e273adfc73,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x12a5caf92c541,
                0x12edfb59dd27,
                0x93b02bf0b62fb,
                0x7e9b553973c6c,
                0x4c1b9866ed9a,
            ],
        },
        y: FSecp256 {
            v: [
                0x4f3fdc68fe020,
                0xd7e43eb1ad72c,
                0xe56e69cc652ea,
                0x8a0f7fbcb753c,
                0xc1f792d320be,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x8f28cbeaaf3d1,
                0xbc1a28f135e0c,
                0x780b54e3233ed,
                0xb12b529a2f3c0,
                0xa4083877ba83,
            ],
        },
        y: FSecp256 {
            v: [
                0xb534df0b254b9,
                0x576ed1ef90b12,
                0x361b3e22001e7,
                0xbc79b8bf83d69,
                0x40e9f612feef,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3db5a7940d33a,
                0xa454203b98cd,
                0xf56c86f6e0d88,
                0xc0b53a4e3e1a2,
                0xa804c641d28c,
            ],
        },
        y: FSecp256 {
            v: [
                0xe95fa6d46967a,
                0xa89cf736a943c,
                0x16047e81af18c,
                0xa6d03dec2842c,
                0x95be83252b2f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x79a55dffdf80c,
                0x81a15bcd1b69f,
                0x745638843e4a7,
                0xc2be8c6244b5b,
                0x8b4b5f165df3,
            ],
        },
        y: FSecp256 {
            v: [
                0xff0c65fd4fd36,
                0x546162ee56b3e,
                0xab0da04f9e336,
                0x8b4b3fbd7813,
                0x4aad0a6f68d3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xf26714755e4be,
                0xee417c997abb3,
                0x83c611071af64,
                0x91718ce17c7ec,
                0xed0c5ce4e132,
            ],
        },
        y: FSecp256 {
            v: [
                0x9fa6ea07bf42f,
                0x25763ddab163f,
                0xa7ea68049d939,
                0x45bdbf3dad7f5,
                0x221a9fc7bc23,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6e6c807cec8ab,
                0x566e0552ced4b,
                0x3f1fae8e53254,
                0xe694b3b15c3f8,
                0xfaecb013c44c,
            ],
        },
        y: FSecp256 {
            v: [
                0x1dfd9ab155070,
                0x86b85e2e2e898,
                0xc2fb13d9c32b2,
                0xcb57fc2e02c6e,
                0xcc09b5e90e9e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x64eae9ad1b1f7,
                0x824f23cd3e07f,
                0x7cbcafdb3b2dd,
                0xd2f2c8731a0b3,
                0x9bb8a132dca,
            ],
        },
        y: FSecp256 {
            v: [
                0x30627c3811c80,
                0x40f4752d53641,
                0xf863e850f54a8,
                0xe3b9b6f9dd284,
                0x945bb2b2afee,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x115925232fcda,
                0xffa6c0e77bcb6,
                0xbd548c7b700db,
                0x996d6bf771c00,
                0x723cbaa6e5db,
            ],
        },
        y: FSecp256 {
            v: [
                0xc069d9eb39f5f,
                0x653779494801d,
                0x8824d6e2660a0,
                0xc498a92113748,
                0x96e867b5595c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x383d60ca030d5,
                0x43079849071fd,
                0x773a3c62d240a,
                0x744d343d7dc45,
                0x57efa786437b,
            ],
        },
        y: FSecp256 {
            v: [
                0xab44274b02f9e,
                0x2ae5e9974ab07,
                0x8de03ec689b6d,
                0x8518893627c92,
                0xd712db0bd1b4,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xfc7770c584dd5,
                0x7e327b012a7fa,
                0x5226cb9108057,
                0xbc42a2df7e9cd,
                0x264bbd436a28,
            ],
        },
        y: FSecp256 {
            v: [
                0x227937704ab11,
                0x43717b8d8de61,
                0xc33be226a1182,
                0x93b4d4f75ce24,
                0xd87c6fa94ee0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x26bd84b2438e8,
                0x1fd5bdec9d2bf,
                0x236a79da78bc6,
                0xd2bbdac85c056,
                0xa94c6524bd40,
            ],
        },
        y: FSecp256 {
            v: [
                0x2c8dbf18661f4,
                0x60a0e39b2bc2e,
                0x5019e3a7e5d3c,
                0x6280fd7921950,
                0xb5201fd992f9,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x33eca0e7dd7fa,
                0x1237a919839a5,
                0x2c2d3b5094796,
                0xbf98ba5feec81,
                0xeebfa4d493be,
            ],
        },
        y: FSecp256 {
            v: [
                0xd4fdae1de8999,
                0xc3a711f712ddf,
                0x178089d9ae4cd,
                0xf0f269ee7edaf,
                0x5d9a8ca3970e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xee90847d297fd,
                0xc08f6766d676b,
                0x118495fc4ea4b,
                0x7bfda61c6031c,
                0x381c4ad7a7a9,
            ],
        },
        y: FSecp256 {
            v: [
                0xce3187d493fc5,
                0x32db939c0093a,
                0x9915eccf04510,
                0xeee48f3e5fa70,
                0x936af53b238e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd70422ede454c,
                0x5fefdd08b2448,
                0x9538c479cf1d0,
                0xc63bcce10831d,
                0xe1efb9cd05ad,
            ],
        },
        y: FSecp256 {
            v: [
                0xfd233a8913797,
                0x44a7a2d4c6ad9,
                0xe477123464e32,
                0x9be7b0154c1ff,
                0xecb4530d8af,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xfeeb329eb99a4,
                0x9f33d47b18d33,
                0xaf475a8c7e541,
                0x7010c5ac235e9,
                0x5318f9b1a269,
            ],
        },
        y: FSecp256 {
            v: [
                0x26eeefe91f92d,
                0x40d1e3ec652c7,
                0xbb405e8a41f2b,
                0xa4195772d93ae,
                0xf44ccfeb4bed,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x7835b39a48db0,
                0xa29b3c03bfefd,
                0xb7bde459f1215,
                0x71672791d0a09,
                0x100f44da696e,
            ],
        },
        y: FSecp256 {
            v: [
                0xd5cd62bc65a09,
                0x18ff5195ac0fb,
                0xc090666b7ff4a,
                0xb772ec8f3300,
                0xcdd9e13192a0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5284f1e4df706,
                0xf9237d08084b0,
                0xb4c4199d8d9c8,
                0xc771a8415dff2,
                0x8c0989f2ceb5,
            ],
        },
        y: FSecp256 {
            v: [
                0xac5a35d72fa98,
                0xf5156511aa736,
                0x9dc966c60de6b,
                0x2034ffd2172cb,
                0xfb4dbd044f43,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x63c33dc47bffd,
                0x39bc95bc1bb1e,
                0x262c0259c5285,
                0x6704c4a481743,
                0xfb8f153c5e26,
            ],
        },
        y: FSecp256 {
            v: [
                0xa45ddd949b095,
                0x89ac542613090,
                0x4bccd531dde13,
                0x621816fa11d9b,
                0x6ca27a9dc5e0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa1b8b4bb2629a,
                0x587737a7b8b8f,
                0x728708465a02c,
                0x51755a0cc9f0a,
                0xe747333fd75d,
            ],
        },
        y: FSecp256 {
            v: [
                0xd961a6946f6d6,
                0xaa6e1a969a9f8,
                0x4c2581c88376,
                0xc114cc436038,
                0xf2affe014507,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xacde6e534fd2d,
                0x4464f3b3852c8,
                0xa04c017a77f8d,
                0xed1b1dc9227a4,
                0xe1031be262c7,
            ],
        },
        y: FSecp256 {
            v: [
                0xf18f29456a00d,
                0x419e1ced79a44,
                0x597535af292dd,
                0x405e6bb6a4176,
                0x9d7061928940,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x27e36a95c8356,
                0xc5de94d85784e,
                0xf29b2c9028a6a,
                0x89eab9f95dcd0,
                0xf4b93f224c80,
            ],
        },
        y: FSecp256 {
            v: [
                0x861b9be001fd3,
                0x344915609abd5,
                0x40eee90c37ef1,
                0x62dfb0e5f6a7a,
                0xa67a92ec0629,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x62fe17b160e8a,
                0x12f97e696c20d,
                0x25b08b0d51e85,
                0x5236b19622ea0,
                0x9d1aca1fce5,
            ],
        },
        y: FSecp256 {
            v: [
                0x50c57ca04c44,
                0xee9212b5e534e,
                0xd8c27e6fe9e0,
                0xf0c63e56692ce,
                0x1153188f5101,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd7d0475ba7fc2,
                0x93bfc39562e97,
                0x821cde7518b3a,
                0x2b9e18a2ad793,
                0xc66c59cc454c,
            ],
        },
        y: FSecp256 {
            v: [
                0x3c69cf75f5956,
                0xddb15955977ec,
                0xac10cb2f00a60,
                0xfcfbea4f3cea,
                0xd9592fe2bfb3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe688d9094696d,
                0x66a41d6af52d5,
                0x43bd7ec5cf8b2,
                0x5b530ac2839f1,
                0xfeea6cae46d5,
            ],
        },
        y: FSecp256 {
            v: [
                0x5debf18090088,
                0x57cc41442d315,
                0xf3ecd5c981c89,
                0xe1bab06e4e12b,
                0xe57c6b6c97dc,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4040aee752b08,
                0xe0b331a1870aa,
                0xdb2e179141eca,
                0x87e1c53261af9,
                0x4d000b621adb,
            ],
        },
        y: FSecp256 {
            v: [
                0x2851f48302cea,
                0xf119c7293a3e7,
                0x2d972cccb7df5,
                0xd255cb6d82558,
                0x6a0d5b8f18e0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x962fd475c58ef,
                0x403e1f1b77f89,
                0x4717128d657a0,
                0xa05dd6aa26211,
                0x71f570ca203d,
            ],
        },
        y: FSecp256 {
            v: [
                0x49a72d35d420e,
                0xc3363e7df86,
                0xbc95b8df2445d,
                0x880dd25557345,
                0xeb42415b95dc,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x8b06043ff8359,
                0x1dc65e7651604,
                0x21da01446b482,
                0xd253b7d282b5c,
                0xa2b7b3629f7b,
            ],
        },
        y: FSecp256 {
            v: [
                0x97fecfe86fec2,
                0x35046f3835a23,
                0x71e29c910d108,
                0x122d57a937a3f,
                0x693038941695,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa978bc1ec6cb1,
                0x7d808583de33f,
                0x6ffca3cfeed65,
                0x9cdcb367be4be,
                0xda67a91d9104,
            ],
        },
        y: FSecp256 {
            v: [
                0xea8e27a68be1d,
                0xc508f740a17e9,
                0xc9780e5dec7ad,
                0x42bc41f463f7e,
                0x9bacaa354816,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3cc821fe741c9,
                0x35ccea5a835ee,
                0xf00d8718bbd9f,
                0xef587c0c0cfaa,
                0x4dbacd365fa1,
            ],
        },
        y: FSecp256 {
            v: [
                0xe10f8338eb623,
                0xa09fc0535f60b,
                0x838299d0cc384,
                0x892e7fdcfd59e,
                0x16c3540e8a51,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xda8bab4e218da,
                0xf15268605087e,
                0xf41c2590f4c85,
                0x9beee68f17d8f,
                0x13d1ffc48150,
            ],
        },
        y: FSecp256 {
            v: [
                0xb419ddb191c19,
                0x206d5bd127e0d,
                0x1b758bda4ad01,
                0x961dcecb9337b,
                0x6008391fa991,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb40caa2e96db8,
                0x16ce29dbff133,
                0x5b0533b3cc9d9,
                0x60007659c79c4,
                0x219b4f9cef6c,
            ],
        },
        y: FSecp256 {
            v: [
                0xf01a78d3b6bc7,
                0xc53e90576527d,
                0x372a6e394f8a,
                0xefeaf5a44180c,
                0x24d9c605d959,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x45ccc1a37b7c0,
                0xf7bb11069f575,
                0xef22151ec08d0,
                0x4cdda6e000935,
                0x53904faa0b33,
            ],
        },
        y: FSecp256 {
            v: [
                0xb096b022771c8,
                0x81e14434699dc,
                0x20d3c1c139999,
                0x106d88c9eccac,
                0x5bc087d0bc80,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd0f1f38a47ca9,
                0xaaad0f85ad57c,
                0x316995d2a6ee7,
                0x46753cf991196,
                0x1a575af9d41,
            ],
        },
        y: FSecp256 {
            v: [
                0x5df2e77ebcdb7,
                0x5d9f4d7ea667c,
                0x1bb8698bdb93c,
                0xdc3cc55fc52e,
                0x3038f1cb8ab2,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x9d755e315565b,
                0x83d3c20c6ee30,
                0x76155d6d3a61a,
                0xd439ca71f5c1b,
                0xf5f0e0437621,
            ],
        },
        y: FSecp256 {
            v: [
                0x430afdd2ecc82,
                0xbf3ed7e40a678,
                0xdf7101aa5bf61,
                0x52bf62189160,
                0x6b9f4e62be5a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x781d9f5362d33,
                0x2146227642cbe,
                0x70ca4e347cbc9,
                0x6e9a57a7f36d9,
                0x8f506f0b6c0b,
            ],
        },
        y: FSecp256 {
            v: [
                0x87d0c87fa243f,
                0x5d43bb8eaf304,
                0xf1c336848cf92,
                0x61719530c5424,
                0x469f955d2afa,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x959f43ad86047,
                0x43a9b8bcaeff,
                0x4ca906779b53a,
                0x83a7719cca776,
                0x8e7bcd0bd359,
            ],
        },
        y: FSecp256 {
            v: [
                0x47e8460372a,
                0x2e47fd68b3ea1,
                0xca9514579e88e,
                0xa4b3940310420,
                0x10b7770b2a3d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x2808bf13f0351,
                0x8d3d0389e777d,
                0x96950df3bc15b,
                0x729dc350f3199,
                0x33b35baa195e,
            ],
        },
        y: FSecp256 {
            v: [
                0x503cccb8d7418,
                0xefbc889b702bc,
                0x48d52bcaa6560,
                0xbf87f94640362,
                0xa58a0185640a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xdc7b24414bb36,
                0x9cad7bca6d71,
                0x71f7e2256f6e1,
                0x3f955cb83ad20,
                0x374deeae22c9,
            ],
        },
        y: FSecp256 {
            v: [
                0x5bea98daf734a,
                0x6300e54321787,
                0x806f7293828d6,
                0x4f9916032c06f,
                0x171165b64fcd,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa64ad6ae7d616,
                0xf2b62a9f0c5e8,
                0x5aeb0dc944dba,
                0xeae57c46e0739,
                0x2380c09c7f3a,
            ],
        },
        y: FSecp256 {
            v: [
                0x9be48161bbc1a,
                0x148f846756009,
                0x509b09a93af92,
                0x956af1598aefd,
                0x6f8e86193464,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x41e1599c43862,
                0xf18397e6690a8,
                0x9b81bde71a7f4,
                0xff21e6d081868,
                0x385eed34c1cd,
            ],
        },
        y: FSecp256 {
            v: [
                0x58fe5542e5453,
                0xec2086dc8cc04,
                0x9ebf4576b304e,
                0x23f56701de19e,
                0x283bebc3e8ea,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3a27078f2827c,
                0x42befc1ce2dc8,
                0xd5f67d147c826,
                0x54800456be134,
                0xf6f622083daf,
            ],
        },
        y: FSecp256 {
            v: [
                0xb20b520aaa102,
                0x7448321bf6d15,
                0x367cee7e657ca,
                0x3a0faf2c5715b,
                0x1bcd4e817de7,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x93209715adcb6,
                0xce7d8c6f369d8,
                0xd1fc255cd91c3,
                0x3de2bd70cb3c3,
                0xfb26e5188f95,
            ],
        },
        y: FSecp256 {
            v: [
                0xbca3b58ba68f3,
                0x31b8b7ab5449d,
                0x9d0176916d2cb,
                0xa34d58e846a71,
                0xf3e128811012,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4db7560788c1e,
                0x60e8bd1d7ed4,
                0x63ceab7d18c37,
                0x132d28f5c6bc7,
                0x8991225911b9,
            ],
        },
        y: FSecp256 {
            v: [
                0xc42228e8f0ef1,
                0x84fdef9e11635,
                0x9b136fa36969c,
                0xac9b27b876355,
                0xda8b4d987cc9,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6ed86c3fac3a7,
                0x4a5947fbc9c60,
                0x13dfa180fddf8,
                0xf191637c73a44,
                0x6f9d9b803ec,
            ],
        },
        y: FSecp256 {
            v: [
                0x890603a842160,
                0x2f5c281002d86,
                0xe45c4d47ea4dd,
                0x59ba69b8e2a30,
                0x7c80c68e6030,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd22744b7fd72d,
                0xe5a7e4da175c9,
                0x4482939da1745,
                0x411c1cdc36c28,
                0xae86eeea252b,
            ],
        },
        y: FSecp256 {
            v: [
                0x4cb7a4eee38bc,
                0x551472f728233,
                0x89ff0e98d9211,
                0x2f962ab0ace5,
                0x19e993c97073,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x474267c169290,
                0x75cf36f2ee7a1,
                0x6dc2c488718be,
                0xff55e61d2f8c5,
                0x2248c9f90bbf,
            ],
        },
        y: FSecp256 {
            v: [
                0xd8a12883ea257,
                0x235da2be2369,
                0x435ba18e16375,
                0xeed7a506bb55b,
                0xfa0594692d21,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xdac4bb50964e3,
                0x77dd1c6f76fd0,
                0x94085d0a99f08,
                0x44074ac11b48d,
                0xe11a6e16e05c,
            ],
        },
        y: FSecp256 {
            v: [
                0xfbf8b0682bfc8,
                0xe138318c6f767,
                0x6f0af2417adc6,
                0xd430e1ad5e259,
                0x87d6065b87a2,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x7e0e742d0e6bd,
                0x63db0f5e5313b,
                0x4d6ecbf774d1,
                0x4e2582a2147c1,
                0x3322d401243c,
            ],
        },
        y: FSecp256 {
            v: [
                0x3a2e96c28b2a0,
                0x3ea2873af624f,
                0xddaf9b72805f6,
                0x4ef5bfb019bc4,
                0x56e70797e966,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x96d32c0ade462,
                0xc8eadbcf29fc6,
                0x4c80cd50d4cdd,
                0xbdae120ef31b0,
                0x8d26200250ce,
            ],
        },
        y: FSecp256 {
            v: [
                0xa8b90f26470c,
                0x4e72678b3ad8e,
                0x3ee36ba1d4afb,
                0xf437d31f6f2dc,
                0xebed3bb4715b,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4643e1516e633,
                0xd072d9c8b916,
                0x594d03b8ed493,
                0xbea9ce4068a1f,
                0x1238c0766eae,
            ],
        },
        y: FSecp256 {
            v: [
                0xdb728c77b7805,
                0x2dcc74022805c,
                0x1c3dc17094625,
                0x1359d6c979e2d,
                0x8a9db02dbb27,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x1552788e7a66,
                0x282b0ec21619b,
                0xa6a11b9cddcd7,
                0x9c15e7b2ea758,
                0x271d5b0770cb,
            ],
        },
        y: FSecp256 {
            v: [
                0xd7258e03c9727,
                0xe3508a824e7a8,
                0x9ac877fe2a065,
                0xf491e457d0994,
                0x5d3aa45834e7,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd74d28134ab83,
                0x9af7643397721,
                0x9665868741b3f,
                0xb7da2bd1770d8,
                0x85672c7d2de0,
            ],
        },
        y: FSecp256 {
            v: [
                0x3094f790313a6,
                0xfcc5298f44c8e,
                0xa62c2e5e77f17,
                0xb2eb6374049bf,
                0x7c481b9b5b43,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb90bc1f17fc25,
                0x46df2e6d96998,
                0x5c8a61f3b89ea,
                0x9ec036c186121,
                0x534ccf6b740f,
            ],
        },
        y: FSecp256 {
            v: [
                0xc7f6ecfe86e76,
                0x77bfdd28ddd71,
                0x2d543550ae3d2,
                0x2ddb462ae3dd3,
                0xd5715cb09c8b,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x70923e8bee8b6,
                0x47ecfbc8d2c71,
                0x8f8aaed79020d,
                0xb7f3081e14201,
                0xa91d1f5cee87,
            ],
        },
        y: FSecp256 {
            v: [
                0xd16aa410644c1,
                0x9f628cb225003,
                0xddad3b2f80056,
                0x8ee15a7189c8d,
                0x748a324ee2df,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa1c255984cf74,
                0x45bef61f10aa1,
                0x2d4383c0735ae,
                0x8e35c1a214dde,
                0xc15c8c23d90c,
            ],
        },
        y: FSecp256 {
            v: [
                0x48cd839ccb000,
                0x2d50b015a2c4a,
                0x25fd7ba47bf77,
                0x2235c8dc6f45e,
                0x2ba954d82852,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x959af60c82a0a,
                0xc60f668832ffd,
                0x19413b10f9226,
                0x88a46b06c9f19,
                0x948bf809b19,
            ],
        },
        y: FSecp256 {
            v: [
                0xb7f88d8c8e589,
                0x8c97cd2bed4c,
                0x1c3418c6d4dff,
                0x6646dc6b74c5d,
                0x53a562856dcb,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xeb0457e8b000a,
                0x331e825e51396,
                0x291f0b6ef16c1,
                0x59360d5ce4c66,
                0x26952c7f372e,
            ],
        },
        y: FSecp256 {
            v: [
                0xd401f05ef705a,
                0x8f653d67318c3,
                0xd688422debe39,
                0xa68862bc893d2,
                0xf513ea4c5800,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x2588976134f96,
                0x6572d6b0e9f10,
                0x31ff243f52119,
                0xc5bdbef2be8b1,
                0xc62e58e6fc23,
            ],
        },
        y: FSecp256 {
            v: [
                0x77ed4d14cf97e,
                0x3563731c3e822,
                0x3141fc5bcfb85,
                0xa1678c3d67675,
                0x4397827d45b1,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6f8800b188cbb,
                0x200807de97368,
                0x16622b0b81c03,
                0x5c741683329a7,
                0x107460520eec,
            ],
        },
        y: FSecp256 {
            v: [
                0x7b6361f272124,
                0x748dce3da601d,
                0xcf54a11242e0d,
                0x598c35326b9b9,
                0xabe5d4c09a21,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xcd819f38fd8e8,
                0x4dfc69752acce,
                0x2873a8f1b0e4,
                0x1c34f067ce0f,
                0x6260ce7f4618,
            ],
        },
        y: FSecp256 {
            v: [
                0x84e95b2b4ae17,
                0x238051c198c1a,
                0x76a1ef7ecd292,
                0xb571a7f090497,
                0xbc2da82b6fa5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6746f3d477c2d,
                0x5196aad27e076,
                0x84f1a1316e65c,
                0x1a73dec8409be,
                0x85d8da4748ad,
            ],
        },
        y: FSecp256 {
            v: [
                0x9816fc7d1dd70,
                0x2033c4d5a6207,
                0x1efc7bc94b0a0,
                0x6690586b53653,
                0x58948b53665c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x312d6c0b80d9,
                0x100fdc47f0485,
                0xc3ee3ee4d1e7e,
                0x4b968c0892e9c,
                0x8e2a7166e7ec,
            ],
        },
        y: FSecp256 {
            v: [
                0x61f2ad6b29f50,
                0x88d706349a49c,
                0x16a9d485297b6,
                0xbe592cedd29b7,
                0xeadb0ba9ae2c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x1fa3d2c4561be,
                0xe81359d90f992,
                0x78f8950ee4ab2,
                0xf58edc8366ecd,
                0x769bc75842bf,
            ],
        },
        y: FSecp256 {
            v: [
                0x20bffb0d9685f,
                0x767b7873add59,
                0x73f5d4741a177,
                0x83bac8dce4cef,
                0x4bf817362fe7,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3cc8d2037fa2d,
                0xf575bfdc43295,
                0xbbf4103043ec8,
                0xd8d43d8348414,
                0xe5037de0afc1,
            ],
        },
        y: FSecp256 {
            v: [
                0x5dc841d755bda,
                0x3ec481f10e0e,
                0xb990bddbd5f5b,
                0xd3b5f9f98d09f,
                0x4571534baa94,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3c8c79e3d34ef,
                0x7c792a2ddb8c6,
                0x2d61b3ec3ab21,
                0x5494f40b6cf7d,
                0xa5e00da467fd,
            ],
        },
        y: FSecp256 {
            v: [
                0x5c5ce2f7adb4c,
                0xfe790900acb85,
                0x9bf43d25b60dc,
                0x8555421726fe9,
                0x98fe5f5e560,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x37160d7b91252,
                0x2e4477572ae67,
                0xc9bfbc46d4afd,
                0x2b403519f4bb1,
                0xa99415f5ef3a,
            ],
        },
        y: FSecp256 {
            v: [
                0x377ac4bedc264,
                0xad590f4ddd73a,
                0x4f6f6b6899a16,
                0xf84bb9e2f10f2,
                0x82d0e64cae81,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x465b66a540f17,
                0x705f0c132bd8c,
                0x8f935f84c750d,
                0xd1fc7d8edde09,
                0xb56f4e9f9e4f,
            ],
        },
        y: FSecp256 {
            v: [
                0x2fcae0200102d,
                0x63cbcca85446a,
                0x582d1d21d429,
                0xa856d3dc11adf,
                0x32e8e53429cc,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x66a0ae4fce725,
                0xd1c6a6c5b7258,
                0xf1771b4e7e8db,
                0x7adf5ea905e8,
                0xe06372b0f4a2,
            ],
        },
        y: FSecp256 {
            v: [
                0x34f94eee31dd,
                0x7787104870b27,
                0xd5a488cd7484a,
                0x8cfe12a27bb2a,
                0x7a908974bce1,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x9aee43ed2ff3e,
                0xdb4ec6ed3cfe0,
                0xfad3f3c045ebf,
                0x6b8f9c8dbd304,
                0xeac134ca204,
            ],
        },
        y: FSecp256 {
            v: [
                0x206207d210988,
                0x96b7f21376e17,
                0x2b11799ac19f6,
                0x9b4245bf103bf,
                0x49630dbe7935,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x706e4dfbfa4dc,
                0x7804c85b17476,
                0xadbb41ff5948a,
                0xea198392119d7,
                0xd6788590731f,
            ],
        },
        y: FSecp256 {
            v: [
                0xbcd6bbd3b5406,
                0xc4ddc9a07cca7,
                0x21c13aa6206f1,
                0x63c4940ef5c6d,
                0x28eaa8c89d50,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5fb40e48ff9b3,
                0x205599b01a727,
                0x2b71d4bc7b1a6,
                0x40974abf210f1,
                0x6930fccbd9a0,
            ],
        },
        y: FSecp256 {
            v: [
                0xdab5f8ee96a4e,
                0x13e4acc51acfd,
                0x75f6d78090f9b,
                0x1eada30fcdb8,
                0x7f02ae94b947,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd6908d0559754,
                0xdde2a3f58540a,
                0xc0ce02204b10b,
                0xd45358d0bbf9d,
                0x213c7a715cd5,
            ],
        },
        y: FSecp256 {
            v: [
                0x2c27534b458f2,
                0xf5f36a7eeddff,
                0x45ba190bb4850,
                0x62507013ad062,
                0x4b6dad0b5ae4,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3895e0ec87fac,
                0x74622e7cf0899,
                0x323480e0d1ab9,
                0x9a7f66ae9fed8,
                0x1c5e548132b4,
            ],
        },
        y: FSecp256 {
            v: [
                0xd7b3d5fc2d4ef,
                0xeb26fe324c555,
                0xd4c2ad3a3deac,
                0x468f2bb959fa1,
                0x4ffcf60f837f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xfcba1d4531dbc,
                0x19fed5c970e20,
                0xbbc7ce1f901c,
                0x668ddef6e9421,
                0x46276d0602c5,
            ],
        },
        y: FSecp256 {
            v: [
                0x730099686b8e2,
                0xfbffe1bc99af8,
                0x70ded99498bad,
                0x75b84a2922875,
                0xe0f7f24d44c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4ef13522f001d,
                0xacdc78d899611,
                0xc3191636850e0,
                0xc24f4e65eb211,
                0xefea68eca7a6,
            ],
        },
        y: FSecp256 {
            v: [
                0x8419f73bc4415,
                0x9fb3848771c12,
                0x3719a17e41395,
                0x3c14da150307a,
                0xaab847869d58,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc3a3b08fbd53c,
                0x70adc62cddf0c,
                0x5419a87e2838c,
                0xb34e8dbb9352a,
                0x4e7c272a7af4,
            ],
        },
        y: FSecp256 {
            v: [
                0x3941817dcaae6,
                0x14bff7dd33e0b,
                0xdef681b530b96,
                0xb18e16fd09f6,
                0x17749c766c9d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x21e6e7c6e1b4d,
                0x5a1bef8790e28,
                0xe385d9c9b11f2,
                0x888f268a269f4,
                0x899017b02696,
            ],
        },
        y: FSecp256 {
            v: [
                0xaebdad814ab2b,
                0xc0f932b212009,
                0x6358bfae4e51b,
                0x34f0bb4579833,
                0x43ae2cdab5b3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x635a17e5f712f,
                0xbf91b583a8af2,
                0x3227f0e2831f5,
                0x5fd4a8f4728e6,
                0x67f644f76e90,
            ],
        },
        y: FSecp256 {
            v: [
                0xacb5e707160e5,
                0x88f7d36198d68,
                0x586cf785e0e14,
                0x5d04f05adeb7b,
                0xb833d68f6644,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x263ed3b89a762,
                0x3012ee6b8dc10,
                0x68b4712930dc9,
                0x2555fa80a0549,
                0x327f876c9365,
            ],
        },
        y: FSecp256 {
            v: [
                0xfd959b9203301,
                0x70febd7dfe9c9,
                0xe1997b9755350,
                0x4026b09969255,
                0xb2d404eab352,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x27e2840fb27b6,
                0xb2be430576324,
                0x1686aa5c76e3d,
                0x8b1b10f238ad6,
                0xfea74e3dbe77,
            ],
        },
        y: FSecp256 {
            v: [
                0xd3db7f23cb96f,
                0x6b973f7b77701,
                0xcb6af93126b59,
                0x13297cf674dec,
                0x6e0568db9b0b,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x97c961f9756e4,
                0xe5de3730488fd,
                0xe8cd0ebb570e,
                0x80ff180e03d85,
                0xed9441c83042,
            ],
        },
        y: FSecp256 {
            v: [
                0xe09f93f3abfae,
                0x74fe4de98bff0,
                0xb13911e09f237,
                0xfa19afa176128,
                0x3dbe9e9efe8b,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xad033d51cf119,
                0xd84fab4d3015b,
                0x4b487515b10bd,
                0x7c3fc9fed3f62,
                0x29d9698ee67a,
            ],
        },
        y: FSecp256 {
            v: [
                0x8740575056339,
                0xe93a7c2963c8,
                0x4f1c96fb89c94,
                0x2b45277a12540,
                0x7fd02c517dc8,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc44537f422491,
                0x4a86060cff467,
                0x3580a31fd453e,
                0x936d6f3fb7bd3,
                0x126b57d05013,
            ],
        },
        y: FSecp256 {
            v: [
                0x31f199da3ef84,
                0xc30bf39347afa,
                0x2bf3fb0e148ba,
                0x62c2e3c4a3eba,
                0xc1a7dc130616,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x2a4417bdde39,
                0x79b760432952c,
                0x99968d31544e1,
                0xcf0e10a2570d5,
                0x76e64113f677,
            ],
        },
        y: FSecp256 {
            v: [
                0x1752d1901ac01,
                0xd2b56d2032b4b,
                0x681f0d35e2a33,
                0x95cf577066d70,
                0xc90ddf8dee4e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x999a83a1187a5,
                0x622c29ae691cf,
                0x161c810005d57,
                0xc73bee87c9d88,
                0x708a530e9e52,
            ],
        },
        y: FSecp256 {
            v: [
                0x4f19b473db9c0,
                0x3c6d353e8a58a,
                0xb6d38283ecda7,
                0xa897fa9656dcb,
                0x9b884811e1f9,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb16c6cde4f5be,
                0x6d86b2b59e2e1,
                0x5e462cf9f374b,
                0x3be219bd64839,
                0x19cf034fc48b,
            ],
        },
        y: FSecp256 {
            v: [
                0x1532b6f321af2,
                0xc93f0f1c0c0a9,
                0xb181947ef91d1,
                0xb466c3b4be68a,
                0x28e32b06a15a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbc209d17cf3e8,
                0x34bea2219e3a,
                0x397f576ee93bd,
                0x5f0d7c719c2f8,
                0xaf6c44a078cb,
            ],
        },
        y: FSecp256 {
            v: [
                0xdd0601751baea,
                0xea7ca0d435b8a,
                0xcb246dfec362a,
                0x4b30af9e73153,
                0x784096fe85d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x150242bcbb891,
                0x43df26cbee3ab,
                0x43f8f9a8f7cc6,
                0xabe1e8281baa7,
                0xc738c56b03b2,
            ],
        },
        y: FSecp256 {
            v: [
                0x735d9699a84c3,
                0xef7880cfe917e,
                0xcbfbbbb82314e,
                0xd2537f718f2ea,
                0x893fb578951a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xab0784662ab1b,
                0xea49b8c9e4dda,
                0x2e7aa94647197,
                0x37435b32a699,
                0x5578845ecd7c,
            ],
        },
        y: FSecp256 {
            v: [
                0xd18f3056f3511,
                0x746a5d64de316,
                0xd2a4053f653a7,
                0xe2c3cea6d0a51,
                0xe61d07978b6d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x869b8948b6c29,
                0x54fce3996094f,
                0xd0ceccd22f123,
                0x64cc4abfa3bc1,
                0x47f3383888a3,
            ],
        },
        y: FSecp256 {
            v: [
                0xee1120e537ef9,
                0x9588f994a81ed,
                0xb416c7118bb49,
                0x2937190e48675,
                0x48ca9a8d0f03,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa6c8f05ff4adb,
                0xd6fcbef768a81,
                0x6a5d5f614f570,
                0xb8cfe466b4c9c,
                0xc0c01f34ae41,
            ],
        },
        y: FSecp256 {
            v: [
                0xeff73ac351065,
                0xd170d15b85fc4,
                0x75b8cecdbc43,
                0x7f5c7c937a0b4,
                0xb84f5bee435,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe9f6588f6c14b,
                0x5f3a925014372,
                0xc972877d1d72e,
                0x5b81e264c7637,
                0xd895626548b6,
            ],
        },
        y: FSecp256 {
            v: [
                0x63ed75d7d991f,
                0x632bb067e1793,
                0x8c340eb03428d,
                0x7eae728ec6081,
                0xfebfaa38f2bc,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb594b77078424,
                0x7a0ec40c3fba5,
                0x3a26703ecaf,
                0x44e8a3a43622,
                0xfd136eef8971,
            ],
        },
        y: FSecp256 {
            v: [
                0x1eeefc671ddf1,
                0xf78a2adfa8cd6,
                0x5c5efa57cf2b1,
                0x52cc67a1d191b,
                0x218da834f3c6,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd84ec8db1cb3c,
                0xa0d43f024a5f1,
                0x7519f861b7003,
                0x8d140e9cca536,
                0xd99e8e9dd963,
            ],
        },
        y: FSecp256 {
            v: [
                0xa29e36b8637a7,
                0xf8ffc8765cd88,
                0xbceba6e6286fe,
                0xa3a7a945bb321,
                0x36dc19ad1cc0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6f68d3c385172,
                0x1e0440e636fd4,
                0x5b09191d20335,
                0x8317a1bd8a54e,
                0x3fdf1619a19,
            ],
        },
        y: FSecp256 {
            v: [
                0xc67f0fccb9794,
                0x9e90e7232b79a,
                0xc8573755b9b92,
                0x12c3fe470c7d3,
                0x408d02c06e5c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x50a564f676e03,
                0x3693e84edd491,
                0x71e8761ceffc7,
                0x7518eb0f64335,
                0xb8da94032a95,
            ],
        },
        y: FSecp256 {
            v: [
                0x8e4e74efdf6e7,
                0x4d95ff3b51148,
                0x62808b092cc58,
                0xa1e4d7c99cc97,
                0x2804dfa44805,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3f414c5af726a,
                0x5cb25bf6e6d41,
                0xab620f9469a3e,
                0xc5ce53f2cb698,
                0x6d36d105ed8c,
            ],
        },
        y: FSecp256 {
            v: [
                0x491a13f9fc7d,
                0x36b4108a35c57,
                0x5c50029dcc599,
                0x669e72d8c66c9,
                0xe4ba5c34e377,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x2a30ca540db99,
                0xc0534b812286e,
                0x6f0b0e3eb1309,
                0xac0cd06883fa6,
                0x3ab6bde10cd3,
            ],
        },
        y: FSecp256 {
            v: [
                0x73fe31bda78a3,
                0xb0e369c043e68,
                0xa13e99c38d137,
                0x71d7fc3117a96,
                0xbaca62079be8,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x7bf279f1048da,
                0xf373ddd3ba777,
                0xd07bce2ba2fd4,
                0x56f0fdba069d9,
                0x796634e3f1ad,
            ],
        },
        y: FSecp256 {
            v: [
                0x9be24a106cf01,
                0xd8cfd74862e8f,
                0xa7927f2532576,
                0xb8956de74735,
                0x4d8ee2b6cfb2,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x11778e3c0df5d,
                0xfb5156a792f1a,
                0x75d7fab2019ef,
                0xb33a7d8adab94,
                0xe80fea14441f,
            ],
        },
        y: FSecp256 {
            v: [
                0x4291b6ac9ec78,
                0x80af322ea9fcb,
                0x3ca94472d155e,
                0x771e89768ca,
                0xeed1de7f638e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe78b0f83cd58,
                0x3877d2f9162db,
                0xefe7a37122dcc,
                0x1265981ac4ed1,
                0x440ca1f08ea4,
            ],
        },
        y: FSecp256 {
            v: [
                0xbc069b88a3f4b,
                0x4269c0a260b07,
                0xd4e2f02a21e4d,
                0xe122af8954dc9,
                0xa6c8b0d2cd5e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbda2712998b10,
                0xbcc1b229d9e81,
                0x3a907819bc70e,
                0x6c1cc5f7f829d,
                0xf694cbaf2b96,
            ],
        },
        y: FSecp256 {
            v: [
                0x88b1700f05e51,
                0xc3183c2a47f67,
                0xc46d82aeb6c64,
                0xf03d633c5ffac,
                0x40a63eba61be,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa13358dd553fd,
                0x95c08b6414f95,
                0x9a2595047abf6,
                0x684850b6d4f43,
                0x8b6e862a3556,
            ],
        },
        y: FSecp256 {
            v: [
                0x3dad33e9be5ed,
                0x5a183383d0d80,
                0x4eb9fa124ac3c,
                0x1cb40d10bc2df,
                0xea5e08910ed1,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x7bbcc4e16070,
                0x31efd6915ddc,
                0xd567543f2a182,
                0x704313ba48e51,
                0xa301697bdfcd,
            ],
        },
        y: FSecp256 {
            v: [
                0xd1a041e177ea1,
                0xf7c0a11a130c0,
                0x5d40f9b1735db,
                0xe4f5081809fa2,
                0x7370f91cfb67,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x20316f24ba5ae,
                0x4c34b5d8114,
                0xe0bff74b43965,
                0xf049f3e8d2419,
                0x27e1e59cff79,
            ],
        },
        y: FSecp256 {
            v: [
                0x5bfee883a45b3,
                0xa69afa63f784a,
                0xc79df05df48a1,
                0xe209ee1b5e3cf,
                0x310b26a6c804,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x9175c9caed7ae,
                0xde84fbfb4f996,
                0x92d7e4f5a39ad,
                0x4aee16588ec38,
                0xc712e7a5f686,
            ],
        },
        y: FSecp256 {
            v: [
                0x148aa46156294,
                0x544b0ce63784d,
                0x11dd9e5380d8e,
                0x63b365ed4b823,
                0x496441075163,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3e1fe44a6db03,
                0x6f58275d791b4,
                0xb8675fcb2c85d,
                0x235d065c0d426,
                0xbfc0504a4b3,
            ],
        },
        y: FSecp256 {
            v: [
                0xc8d1a464b8542,
                0x97345d4f0558a,
                0x4a6c992374271,
                0xf3453fb8ec7f9,
                0x1955467a6c34,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xac63e3fb04ed4,
                0xb11307fffab7,
                0x2678de208cc33,
                0xb936463f9d051,
                0x90ad85b389d6,
            ],
        },
        y: FSecp256 {
            v: [
                0xd4d48cb6ef150,
                0xbe1582894d991,
                0x27222b839aefa,
                0x8261affdcbd94,
                0xe507a3620a3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x8b0eda7dc0151,
                0xe646707bad281,
                0x8425e3d7e125b,
                0x4077f44b1d154,
                0x7e2cd40ef8c9,
            ],
        },
        y: FSecp256 {
            v: [
                0xbc53920721ec7,
                0x40aeee082c9a3,
                0x21ef95d889bee,
                0xfab382a61a8b3,
                0x905b75082adc,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3ae41345e597,
                0xf9db853cf90e1,
                0x1ef52a79c636b,
                0xdace21c975bbd,
                0xa146f52195be,
            ],
        },
        y: FSecp256 {
            v: [
                0x5676af45a770a,
                0xb221f094b0767,
                0xbb31b40ea67a5,
                0xfeb09ae95dd2d,
                0xa5a99b0ab053,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb53fc4ce45444,
                0x1efeccc4e20cb,
                0x25a8114dbde42,
                0x93b9bcfbf9dab,
                0xd24c75a1cf19,
            ],
        },
        y: FSecp256 {
            v: [
                0x3246987dd4a57,
                0xf499f1e524cb9,
                0xe5a78abf7593,
                0xc1d1cfcb7d181,
                0x58fe1d2de84d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb444c9ec4c0da,
                0x78723ea3351b7,
                0x81f162ee88c56,
                0x5f339239c1ad9,
                0x8f68b9d2f63b,
            ],
        },
        y: FSecp256 {
            v: [
                0xcbf79501fff82,
                0xfe95510bfdf23,
                0x6be215dbbea2c,
                0x3986de1d90c2b,
                0x662a9f2dba06,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x47df84cf27076,
                0xade7627eaee68,
                0xfd9af59d89858,
                0x8158fcafebe77,
                0x4d49aefd784e,
            ],
        },
        y: FSecp256 {
            v: [
                0xb66203aa781e,
                0x1a7df4d8466b9,
                0x59ca6f06e0f2d,
                0xd135e723f2103,
                0xcd32fc59a10d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbcb5729b62026,
                0xe0889d1d4ee8d,
                0xf5c5aa78d2a3d,
                0x6f8537d6619e1,
                0x7564539e85d5,
            ],
        },
        y: FSecp256 {
            v: [
                0x2c8fadace0cf3,
                0xd954b79f33417,
                0xa722925684aac,
                0xb3c65231df524,
                0xc1d685413749,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4dacd57b4a278,
                0x5f1ff4082b536,
                0xad9ccc878f61a,
                0x27796746ff301,
                0x210a917ad9df,
            ],
        },
        y: FSecp256 {
            v: [
                0x713fd0c7b2231,
                0x1aaff20bfc7f2,
                0x8d6737d3789e6,
                0xe57b7a39be81f,
                0x670e1b5450b5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6fd5053231e11,
                0x6503681e3e668,
                0x98c36091f48e8,
                0x85d65ff99ff91,
                0xe4f3fb0176af,
            ],
        },
        y: FSecp256 {
            v: [
                0xc38576feb73bc,
                0x4ec951d1c9822,
                0xa02b7286cc7e7,
                0x4f1c1661a6d0e,
                0x1e63633ad0ef,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xee2233bcdaf2f,
                0x825ba172953bf,
                0xbdb362f88531a,
                0x73e01ec64110a,
                0x4b30cbb76867,
            ],
        },
        y: FSecp256 {
            v: [
                0x33d463d26b5b7,
                0x81e4348575680,
                0x7c3c4a91fdf3c,
                0x629b6f9e2c577,
                0x74c6350265bb,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe9c29a673059f,
                0x5050e0fa192ff,
                0x7464817ec1171,
                0x700dcd15b20b1,
                0xcbb434aa7ae1,
            ],
        },
        y: FSecp256 {
            v: [
                0xa9642227c070c,
                0x4f0ad5f845b7d,
                0x8b5dfad41d45e,
                0xbd17562d49233,
                0x4a1a200ab4da,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x786e106de12c0,
                0xc5874610e94d4,
                0x557244c6d9cda,
                0x2c1cd06d7b1e7,
                0xf478056d9c10,
            ],
        },
        y: FSecp256 {
            v: [
                0x76ce6ca5361fe,
                0xf609ab92d769a,
                0x68694c26c17e,
                0x3946e68095e01,
                0x7f09e610f33e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb6eae20eae29e,
                0x2f0d4e1d0716f,
                0x45a4266c7034f,
                0xf331eb961537a,
                0x8c00fa9b18eb,
            ],
        },
        y: FSecp256 {
            v: [
                0x2a4c66702414b,
                0xfa81e36c54e7d,
                0x736c974c2fada,
                0x21a1a9dc343a3,
                0xefa47267fea5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc9ab0c18ada5f,
                0x7f29122fb3e84,
                0x36be1effd7e29,
                0xb46fa8bb5bf96,
                0x24cfc0176da2,
            ],
        },
        y: FSecp256 {
            v: [
                0xa6139978a586b,
                0xa1a4f814f268f,
                0xdeda927ed959c,
                0x61a69868714d5,
                0xebff8fbb079c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3189594679da2,
                0x7fc7f057edf10,
                0x1292ec616ddd6,
                0xbc82ea2ded72a,
                0x4a7d58d4b9,
            ],
        },
        y: FSecp256 {
            v: [
                0x7f484779ffe26,
                0x94963fa28a487,
                0xec71b3b71c3b4,
                0xcb75e6b1d8147,
                0xb98ac5b76702,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x34eadc87c4b65,
                0x8a1e07b2a9ccf,
                0x66ce4996f880,
                0x1c7fc76c5e2c,
                0xee7d69c4cbd0,
            ],
        },
        y: FSecp256 {
            v: [
                0x8f44ed136a95a,
                0x99bae942e523e,
                0x30f2ee2c33e89,
                0x13821a192abf0,
                0xecc8626ec1a4,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xfddfc60cb3e41,
                0x4f308b92c0997,
                0x9e98ed3143d08,
                0x829f3e10cec0a,
                0xe7a26ce69dd4,
            ],
        },
        y: FSecp256 {
            v: [
                0xa9421cf2cfd51,
                0xc0420e83e20e8,
                0xaafbb18d0a6b2,
                0x984b471b006a1,
                0x2a758e300fa7,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe5b917b4ae861,
                0xe4d6e32fa9d97,
                0x72089f5203c35,
                0xf8d00d38bfb67,
                0xf5cafaba036b,
            ],
        },
        y: FSecp256 {
            v: [
                0xc239c0d82239c,
                0x9c552f05f3cc9,
                0x40839159b3b2a,
                0x6d817bff99046,
                0x19e83b8a022a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd4cd7bd2a9651,
                0x9c494c982084f,
                0x7e805428f9e50,
                0x3f1f12df5156d,
                0xe9389024ceb6,
            ],
        },
        y: FSecp256 {
            v: [
                0xde2b75e786824,
                0xcec6770bfefef,
                0x671aaf18d7110,
                0x6595f9287abaf,
                0x864868872372,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd41ae7cddab8b,
                0x1253c68e6fcf2,
                0x82d0c379f0e4d,
                0x256bed116900d,
                0x264559d87829,
            ],
        },
        y: FSecp256 {
            v: [
                0x64b45001de473,
                0xaf39caf1e6c9f,
                0x34072d77a8631,
                0x512cef7bc6370,
                0x79e5bd1926d3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x29eb3de6b80ef,
                0x967d79424f3cf,
                0x3bcbdc571cbcb,
                0x2ec8d23540c22,
                0xb6459e0ee366,
            ],
        },
        y: FSecp256 {
            v: [
                0xbf0b61a71ba45,
                0x6d48e35b2ff30,
                0x5661db3c4b3ae,
                0xe06de1dadf16e,
                0x67c876d06f3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xef375033eb51f,
                0x76be79c211253,
                0x1f41593b68905,
                0x3c88e4d36f730,
                0xe5d8e8f0d982,
            ],
        },
        y: FSecp256 {
            v: [
                0x5bd965a62a2d9,
                0x46d9f0f54979d,
                0x8feeef0e509dc,
                0x3e04abb16a57d,
                0x4dc1e9b7861e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x676480f155e64,
                0x4fa8a3011737a,
                0x1bae0ddab66be,
                0x8c3dc56b0f732,
                0xa9ca27f77dbc,
            ],
        },
        y: FSecp256 {
            v: [
                0xf333c561b3297,
                0x821bcaf0ae1f3,
                0xc02d004875d41,
                0x14d4d197d2246,
                0xf4bb335678fb,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbc629d6ee247c,
                0x847f51cee06d4,
                0x1cfe7591f478e,
                0xd7f25eba10561,
                0x68fb71800686,
            ],
        },
        y: FSecp256 {
            v: [
                0xf822d1a01865d,
                0xb04c73c9dae1,
                0x1b0c079a8d58,
                0x9636737354275,
                0xcd12d23462dd,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa0f5b496943e8,
                0xc67e73c5a5ded,
                0x18f06231d6f1f,
                0xb840793234aa1,
                0xd68a80c8280b,
            ],
        },
        y: FSecp256 {
            v: [
                0xc84266b133120,
                0x8f7845295a294,
                0x7b0e28b5b0e7b,
                0x86d00c4b1f917,
                0xdb8ba9fff4b5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa222ca412b6fd,
                0x3c6f702b828bd,
                0x752373caced05,
                0x40be402f8efb3,
                0xf16a409c677a,
            ],
        },
        y: FSecp256 {
            v: [
                0xdae77eca052da,
                0x59249ebca4268,
                0x4e30e4e165406,
                0x2799d7a6a75a7,
                0x2a4131171453,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa0b6e326dd4e4,
                0x2f6bed98325c1,
                0x976f84db89f4f,
                0x6f42fbe37f699,
                0x4154b506ab76,
            ],
        },
        y: FSecp256 {
            v: [
                0x59295075ded1c,
                0xd9d1e22dd46c8,
                0x1025ff6414ea9,
                0x988894c6e44d6,
                0x23ad075043c5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x1a7a63f7f0246,
                0x49fc727ddf4c5,
                0xb5956ea93e86e,
                0x95c1080a8d4d0,
                0xb73c652769cc,
            ],
        },
        y: FSecp256 {
            v: [
                0xe5164ea2a407b,
                0xe4c6e554e5597,
                0x5b6c1ea1a0d72,
                0xca9d4b535893c,
                0x9a67db107174,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5980fc28d3d5d,
                0xb973449cea409,
                0x7a30b09612ae,
                0x804252dc02709,
                0x324aed7df65c,
            ],
        },
        y: FSecp256 {
            v: [
                0x224af96ab7c84,
                0xc7e332843967,
                0xaec1f4f19213b,
                0x1f2ff130c0c35,
                0x648a365774b6,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x38381b2919749,
                0x4a8de0db1fa8f,
                0x80d7203f72b3e,
                0x490228d326818,
                0x32c9331ea26f,
            ],
        },
        y: FSecp256 {
            v: [
                0xe97b0f290b5e3,
                0xbdae39ab09631,
                0x6f3dbb8268a4a,
                0x9cb5695a2f02b,
                0xd7cd272b3420,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc22527b9795e4,
                0xb6e1846b8e1e1,
                0xfec6b1c69c161,
                0x37854a02f6a70,
                0xeb292f3b3b98,
            ],
        },
        y: FSecp256 {
            v: [
                0xe9d2fae53a0fe,
                0x7509111c6f5b7,
                0x145835b57131d,
                0xbe801696634af,
                0x8c43c25a96ee,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x39d5789303fdd,
                0x7f19d1ed35aea,
                0x49fbe14d7145,
                0x5ef2e620d4310,
                0xa65a3a01df3b,
            ],
        },
        y: FSecp256 {
            v: [
                0x44a8d02e68703,
                0x24faed3cadad,
                0xed2c7686861d,
                0x5c6fb8f43d8d9,
                0x798ea0940cff,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbd373fd054c96,
                0x3ba8d1ca888e8,
                0x5fee5dceec414,
                0xe61f6d51dfdbe,
                0x4df9c14919cd,
            ],
        },
        y: FSecp256 {
            v: [
                0xbac06cad10d5d,
                0xcdc288490192e,
                0xa1d85d4b5d506,
                0x8728050974c23,
                0x35ec51092d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6b0fc1da49e04,
                0x54e57a8d70c0c,
                0x4b87088e9de45,
                0x998cd25317d4e,
                0xed32cad8d2cc,
            ],
        },
        y: FSecp256 {
            v: [
                0x120d17c1db9e0,
                0xacb49fab7db63,
                0x859d20b52da9f,
                0x204a541ca375,
                0x129fef5f1d03,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x418d4e883f855,
                0xcb63c34016cb7,
                0xc70366e28c36d,
                0x60f18049e4111,
                0xe821ab724d63,
            ],
        },
        y: FSecp256 {
            v: [
                0xe0c6a59852ddf,
                0xc614ec23efed4,
                0x416cf598b3b19,
                0x3ce367d0d4115,
                0xadefcbf863f5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xf59eeb441742e,
                0x47af3806e9fbf,
                0xc9693a72f14a5,
                0xd212f455452fb,
                0x3f0d8994e51a,
            ],
        },
        y: FSecp256 {
            v: [
                0x5363bcfecadbe,
                0x2c3ad13d958c6,
                0x47a6e0b1e205e,
                0x3dc445e5cb0e8,
                0xfbd76c23f28c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc99c8ac1f98cd,
                0x54d7f0308cbf,
                0xcc66021523489,
                0x4870faed8a9c1,
                0x9c3919a84a47,
            ],
        },
        y: FSecp256 {
            v: [
                0xe5e03d4fc599d,
                0xf76c64c8e6be7,
                0x260e641905326,
                0xdd57584f044bf,
                0xddb84f0f4a4d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xefb7b694a09ec,
                0xa53e8535f0435,
                0x5c92aa40cd326,
                0xd80f0a42fc69d,
                0x2e3c05326255,
            ],
        },
        y: FSecp256 {
            v: [
                0x4868188c7327e,
                0x3c707b6651253,
                0x82fc1abe048a5,
                0x6fb5bddae240b,
                0x1ff891656c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xf19a2ab9c7ce6,
                0x16a1908934205,
                0xe24dda4337103,
                0x1587ae15fb7e3,
                0xe8e2a24ccfa4,
            ],
        },
        y: FSecp256 {
            v: [
                0x1eb68836267c,
                0x3b5c27a73b2c,
                0xbee20596e09e6,
                0x5d1b4caf2b2b3,
                0x46c983ce0c6f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd39668ac7b3c2,
                0x92383d5b5f5b0,
                0x70032a212acaf,
                0x73c2b2f0a38b1,
                0xa7549aac5d85,
            ],
        },
        y: FSecp256 {
            v: [
                0xc91719287eaef,
                0x15537116dffa0,
                0x1947d2b5d6b51,
                0x2415335a1d70c,
                0xbd17d1b90d1c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x1382120a959e5,
                0x3a8b91d4cc5a2,
                0xd8e06bb91e149,
                0x2fdf8de05f281,
                0x6057170b1dd1,
            ],
        },
        y: FSecp256 {
            v: [
                0x9be932385a2a8,
                0xbc3ee24c65e89,
                0x71df262465152,
                0x4807add9a2daf,
                0x9a1af0b26a6a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x9ca5d82fd545c,
                0x8dd4a28e66189,
                0x6dc85df7c133f,
                0xe0640394110a4,
                0x6773fd677c52,
            ],
        },
        y: FSecp256 {
            v: [
                0x7f034947eb1ae,
                0xf5a1c6cf98e8c,
                0xd2b246bead780,
                0x652f0f0f25c9d,
                0x444eb6d8cd97,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc616b0b86f021,
                0x3810468050373,
                0xe0c87c20374e4,
                0xe565237c79aac,
                0xe0f86d94d17c,
            ],
        },
        y: FSecp256 {
            v: [
                0xb79ccb5bf325a,
                0xc0115fc45b3b6,
                0x1c89a2c9a80bc,
                0xbcf47a91e832f,
                0xc571c73730a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x772c02da6e03,
                0xf908cad6038ad,
                0xd696f4f4c277d,
                0x5041ce991e193,
                0x42ca15ab9f24,
            ],
        },
        y: FSecp256 {
            v: [
                0x889fa8c347793,
                0xa68106bea7836,
                0xcb800eed66e85,
                0x57c9647ce4d1f,
                0x68d2ef26c81c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6973eecb94266,
                0xfba7d4df12b1a,
                0x18da31880cef0,
                0x8411421439a45,
                0xa576df8e23a0,
            ],
        },
        y: FSecp256 {
            v: [
                0xbe11ae1b28ec8,
                0xa7f514d9f3ee8,
                0x58cd82c432e10,
                0x40b2c92b97afe,
                0x40a6bf20e766,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5725bda704896,
                0x63c9acfb8dcec,
                0xbe71bae6f3ba0,
                0x5a3b546520867,
                0x9e5dcc62ef3b,
            ],
        },
        y: FSecp256 {
            v: [
                0x2769dca82c835,
                0x186030f51248f,
                0x4c7612279605d,
                0x5f3ea5fd3a215,
                0x6fedd12ddb92,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xed58744bf7ea0,
                0xa05cef5833953,
                0x6f03b20e33625,
                0x45adf8d6e9f97,
                0xa7de08375b87,
            ],
        },
        y: FSecp256 {
            v: [
                0xc05539bbcabaa,
                0xc0febc5aa2e04,
                0x4888e9a645a47,
                0xa5e52104a0b33,
                0xa63d96b057ad,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x8fa104ad916fb,
                0xfde949e4a3a9f,
                0x1cff4cbe68065,
                0x80c9c13c35ac0,
                0xc266658e6890,
            ],
        },
        y: FSecp256 {
            v: [
                0xef52ba0887814,
                0xdfeb61138856a,
                0x24627ab6b8fec,
                0xdaab0f798170b,
                0xe7e8593854e7,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x63889be58ad71,
                0xf5cf9a3a208f7,
                0x9de8c38bb30d1,
                0xc3e30a05fe962,
                0x7778a78c28de,
            ],
        },
        y: FSecp256 {
            v: [
                0x13fc1fd9f43ac,
                0x11ff24ac563b5,
                0x2ff580087b384,
                0xb22ff7098e12f,
                0x34626d9ab5a5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa1c251073e879,
                0x5ae104eea7a7e,
                0xf0fe3932cf16a,
                0x6d1632f482d7,
                0xe7b9796b5ca0,
            ],
        },
        y: FSecp256 {
            v: [
                0x71089baa89d98,
                0x25eda98af338e,
                0x37cc1ca9cb5bf,
                0x9e2fdf42102a7,
                0x12b8988c1916,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd722bf2628f0f,
                0xaaf2aee919865,
                0xbe09a7365423d,
                0x6203c2c915a24,
                0x71bf0185087,
            ],
        },
        y: FSecp256 {
            v: [
                0xc5cbd45a1c334,
                0x6a231c80bbb57,
                0xc084ce2098f9c,
                0xcf4ae33600bc1,
                0x527aa15d504d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x376dfa39620e1,
                0xc8501213786f6,
                0xc03c39e5b1911,
                0xe56833a32e594,
                0x218343acb9b,
            ],
        },
        y: FSecp256 {
            v: [
                0x199f6506998b5,
                0xa42f43c9ec5e0,
                0x2fbfc0443299,
                0x50beaf3f24fd6,
                0xbea81d48970a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xeda9c06d903ac,
                0x74e5ad7e5cb09,
                0xe7afd2ed5f962,
                0xa84463729fd30,
                0x928955ee637,
            ],
        },
        y: FSecp256 {
            v: [
                0x80e935bcd091f,
                0xefa8a8d83fc51,
                0x93a95eeac3d26,
                0x42a827b78a130,
                0xc25621003d3f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x47a60f59dd9e,
                0xc55b58f0e7231,
                0xcb18ad67ce5e9,
                0xd350dad163b04,
                0x4f89bdee3771,
            ],
        },
        y: FSecp256 {
            v: [
                0x6ae320156b049,
                0x506638df5c101,
                0x43bb2471e4882,
                0x1f695c4baf4c0,
                0xca7952d5227a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc314cfff01197,
                0xf079a245bf529,
                0x2c3c4c994b668,
                0xc5a80c396baca,
                0xcb9e8304cae3,
            ],
        },
        y: FSecp256 {
            v: [
                0x4e0763b989c1d,
                0x8c015e0a24c33,
                0xf08891741b2d1,
                0xe6a127258cdf,
                0x62c7d2801eb8,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x9ffc2508d2cc2,
                0xd47048c58c15f,
                0x730dc58e0bee,
                0x69bd3c8cf2a41,
                0xe2f349b0f89c,
            ],
        },
        y: FSecp256 {
            v: [
                0x47bd8e0d4c04f,
                0xe8e09cbdb37e3,
                0x60215ba42344b,
                0x723781860aec7,
                0x1feb2f280f82,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xae75163d82751,
                0xa907ad354527a,
                0xe3b2855645b4,
                0xb109399064f3a,
                0x85d0fef3ec6d,
            ],
        },
        y: FSecp256 {
            v: [
                0x237a24eb1f962,
                0xe96877331582c,
                0x82cf5663e8751,
                0x8c0be29d496e5,
                0x1f03648413a3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x56d141d5fcade,
                0xe009711ff7563,
                0xd11df0468b482,
                0xc4f4f607a6cfc,
                0x6b790f4b19a4,
            ],
        },
        y: FSecp256 {
            v: [
                0xff86fc338d3ff,
                0xb47be26b0ab6f,
                0xcae09cba83fa5,
                0xeb3ef296661f9,
                0xd03a981b2ff9,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xccdabe3a3e0cb,
                0xde85978be0bb0,
                0xcc4f8fe3d2479,
                0xbed3c162c367a,
                0x41149b2c2d7e,
            ],
        },
        y: FSecp256 {
            v: [
                0x92e98339033a8,
                0x5ef490f2470e,
                0x902cf28b3ec78,
                0x30542b415c9b9,
                0xc90d5b92db7c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xddd28e3f3d3fc,
                0x8205c29cebf8d,
                0x872a7ba664a9b,
                0x849dfaec3dfe2,
                0xd1fad4fa4e7c,
            ],
        },
        y: FSecp256 {
            v: [
                0x2343c50f3704d,
                0x31eff37326ed2,
                0x58b7818bad371,
                0xfdfe5473f70e8,
                0x8fe19714a348,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x404824526087e,
                0x8882da20308f5,
                0x798b85dfdfb6d,
                0xce97c1c9b6041,
                0xff2b0dce97ee,
            ],
        },
        y: FSecp256 {
            v: [
                0x51e01f0c29907,
                0x6fb90e2ceb2c9,
                0x4d07936c7b7ed,
                0xba188af4c4dc5,
                0x493d13fef524,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3a9af3149f8ef,
                0x4ee638b4583bd,
                0xcb1bb223deb5c,
                0x6c9f78e29ebbe,
                0x2982dbbc5f36,
            ],
        },
        y: FSecp256 {
            v: [
                0x726b016c7a248,
                0x9412e3ed8456e,
                0x7b5bc9d095db9,
                0x220ab9fa5339c,
                0xa61b5be9af66,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x89f612380441b,
                0x4580e17658852,
                0x497db5860011f,
                0xc0f6b436eb590,
                0x1a28e5042af0,
            ],
        },
        y: FSecp256 {
            v: [
                0xf606a8452af25,
                0x5b46ee67aeb05,
                0x976f0ed04b3e7,
                0x9dab7c78329a8,
                0x55779a7996c5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xf0e39621e30a7,
                0xb7985d83242ee,
                0xd3f20142edd5e,
                0x30601d250cc0b,
                0xc8b83e9535f,
            ],
        },
        y: FSecp256 {
            v: [
                0xf7beb9ff688de,
                0x37b987134dbeb,
                0xefdc854aacad2,
                0xdac7b850e3f17,
                0xdcc7077065f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe5e2cf856e241,
                0x148cd6dd28780,
                0x1b212b57f1ee,
                0x80ea9ed2b2e63,
                0x827fbbe4b1e8,
            ],
        },
        y: FSecp256 {
            v: [
                0x5b68baec293ec,
                0x3186903166d60,
                0xd1d12687ff7a6,
                0x7b0b71bef2c67,
                0xc60f9c923c72,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe44b70cb1815d,
                0x9218b87461ef6,
                0x76e6b3660470a,
                0x6b973e2d7c8d5,
                0xb77f12a7dce5,
            ],
        },
        y: FSecp256 {
            v: [
                0x3d2bc8e57dbc5,
                0xf91a44816d6ba,
                0x3cc2e654c42f0,
                0xacc43f0cefb37,
                0x4b6f85b14f86,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5dad2c45565ec,
                0xdf4977c5970fe,
                0xb79f956d858d8,
                0xbf1247b308b2c,
                0x48973b943018,
            ],
        },
        y: FSecp256 {
            v: [
                0x79075faed07e9,
                0x96580477b83b8,
                0x1445af1511b35,
                0xdc1b6437bb3a0,
                0x761f75684f3c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4d742bbfd71fa,
                0x265b4527d4a4d,
                0xa704c170b775a,
                0x559c6d6972728,
                0xe931258e8eb5,
            ],
        },
        y: FSecp256 {
            v: [
                0xbd0d3174d3307,
                0xe1bb5e35f33d9,
                0xc954b40b3946c,
                0xdee0e85eb4169,
                0xfb1e33364c3f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb58fa2120e2b3,
                0xce7f47f9aa7f3,
                0xce6e5217a58fd,
                0xbdbae7be4ae34,
                0xeaa649f21f51,
            ],
        },
        y: FSecp256 {
            v: [
                0xa5305ba5ad93d,
                0x65f13f7e59d47,
                0x879aa5a01a6b9,
                0xb03ac69a80f89,
                0xbe3279ed5bbb,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbc1cc1fc9b0a8,
                0x5c705f3db453d,
                0x2279ea9e337b,
                0x97eec2623ea50,
                0x3adb9db3beb9,
            ],
        },
        y: FSecp256 {
            v: [
                0xe7975f05bbdda,
                0xf9870266cc61a,
                0xc095ff6aad9c8,
                0x4e713c774de07,
                0x374e2d6daee7,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe9e0c90ae86f9,
                0x56963e7caf054,
                0x6c5fc69fefdff,
                0x9cbb7e10955e5,
                0x129e53ac428e,
            ],
        },
        y: FSecp256 {
            v: [
                0xefdcd1e89c85d,
                0xfd16b3e01b822,
                0x712183fb2a232,
                0x9a29b2da2115b,
                0x415ecb958aee,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x243d5e855b8da,
                0x7d12894711922,
                0xee10956c75626,
                0x94485b85ecb6a,
                0x60144494c8f6,
            ],
        },
        y: FSecp256 {
            v: [
                0x590f34e4bbd,
                0xc27e3f2a4bad5,
                0x132e65b543955,
                0xe6469e8be1fd9,
                0x8bb5d669f681,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3632dda34d24f,
                0xf0c9a137401e2,
                0xcf42ee541b6d8,
                0x169d9391df6de,
                0xe4a42d43c5cf,
            ],
        },
        y: FSecp256 {
            v: [
                0xf7131deba9414,
                0xdfa8d8e4f13a7,
                0xb8ad34ce886ee,
                0xc73526fc99ccf,
                0x4d9f92e716d1,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xf2ea33e8f62bb,
                0x62f7ae4d2a303,
                0x6c4ef4d0553c5,
                0xb18d3ef0acf85,
                0xfd6451fb84cf,
            ],
        },
        y: FSecp256 {
            v: [
                0xd9086132c0911,
                0x92d200e83fd0a,
                0xbc344ccfa2ab4,
                0x1578b6fe7a5c1,
                0xe745ceb2b187,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd1fb9d5fe696b,
                0xd5dcf3c7a1fa1,
                0xf9edbbb0042e2,
                0x86bc716e81a06,
                0x1eee207cb240,
            ],
        },
        y: FSecp256 {
            v: [
                0x5670e7429337b,
                0x2e0afd694ebb4,
                0x461c95f7a0206,
                0x269cd2b196d12,
                0x652cbd19aef6,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x40f19ef94c0d5,
                0x17c57257908d,
                0x46e2111e1c0fc,
                0xeb14d465ab2c3,
                0xcc0ea33ea8a9,
            ],
        },
        y: FSecp256 {
            v: [
                0xbe597af452fe6,
                0x266113f543dea,
                0x5fbe663f6074f,
                0x8a2fb23dd203b,
                0xf9907a3b711c,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x73b9d4300bf19,
                0x76a88fea49471,
                0xb352b6b92b535,
                0xbdd954160fada,
                0x1ec80fef360c,
            ],
        },
        y: FSecp256 {
            v: [
                0xcdc1cc107cefd,
                0x7f6295a07b671,
                0x7abbf5e0146e7,
                0x340d2f3a4958a,
                0xaeefe93756b5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe805d414ff9e4,
                0xf6ebd890560da,
                0x4fc90bb8e8462,
                0x4bc6cbeeaa034,
                0x5be7ea3519f0,
            ],
        },
        y: FSecp256 {
            v: [
                0xb07847e0bdbb,
                0x302119a309403,
                0x55ab7fe0e99c6,
                0xe605477f890f6,
                0x32f32ec3f638,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb545f4ddb7bb8,
                0x649f853991e3f,
                0x8df7f5cd50028,
                0x4e650813fc869,
                0x58f099116eae,
            ],
        },
        y: FSecp256 {
            v: [
                0xc73582e5b2d6e,
                0x62d174302bde,
                0x4638066507ee4,
                0x111a0d62ff761,
                0x7e07002aaffe,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc1606cc9a8e2c,
                0x1a4cc1a1c1413,
                0x860cb0f823d8d,
                0x90b633bcc04fd,
                0xb0f9e4b9b297,
            ],
        },
        y: FSecp256 {
            v: [
                0x66c4df3d0db4,
                0x2c171cee76c2,
                0x6fde3f03350cc,
                0xde6d41cbb0b90,
                0x49e82bf1843a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb5928366642be,
                0x717d58ba889dd,
                0x80dfa8bce3490,
                0xc2f91b00af46,
                0x146a778c0467,
            ],
        },
        y: FSecp256 {
            v: [
                0x297483d83efd0,
                0x1d2f7e5ed1d0b,
                0x9d4b2870aaa97,
                0x28add669827f,
                0xb318e0ec3354,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x2365579de5cac,
                0x3c7ecb261911b,
                0xbcd14cfeefc98,
                0x7e24e5670b5c0,
                0x574ef0ce8a59,
            ],
        },
        y: FSecp256 {
            v: [
                0x9aea6c75a4805,
                0x7bef10008cae5,
                0x69b78451a260a,
                0x19c73bd6ada05,
                0x9b99930281f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc2d74260966d3,
                0xc1aeff8645808,
                0x98c835d10a770,
                0xf9f85d909397b,
                0xd3d97e799d8b,
            ],
        },
        y: FSecp256 {
            v: [
                0xeb850833c2e52,
                0x11be8dc4eebdd,
                0xd403ad3b5e487,
                0xc95e6aaa89275,
                0x8ddbb46376ba,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xfb93968c6d4b,
                0xcf8f494c12004,
                0xcbbee0ab2be78,
                0x18987b974e782,
                0xb1aa653288b3,
            ],
        },
        y: FSecp256 {
            v: [
                0x9e62ae891ac51,
                0x909d623cc383d,
                0xd63a83b100a1d,
                0xd712684aa8e2,
                0x7ed6071c6081,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6a8793180eef9,
                0x209a28b9776d7,
                0xaa07b128d0012,
                0xe5f07e3acebb1,
                0xfa50c0f61d22,
            ],
        },
        y: FSecp256 {
            v: [
                0xd8d7d3f4f2811,
                0x93a57a213b38c,
                0x281a68a5e6832,
                0xeba9b72cd2872,
                0x6b84c6922397,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5be23187f5048,
                0xd2448386d459c,
                0x2e90836e72328,
                0x74e0780140fe0,
                0x63964eee6190,
            ],
        },
        y: FSecp256 {
            v: [
                0xa284d89309df8,
                0x934dde6c84383,
                0x34bfbc93d580b,
                0xcf41a39ff9b1c,
                0x3b6cfb3a6b89,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4ba1ebadb2a65,
                0x2ad3cbda31f81,
                0xfc9f75afd7f1,
                0xb7e22d1469ddf,
                0x5a3ce25b4d15,
            ],
        },
        y: FSecp256 {
            v: [
                0x170cf1d327f1d,
                0xc3d825fe8ed8b,
                0xf3f99af3ee28b,
                0x5f63873a6dbfb,
                0x8b34125b92e0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x733754a9f44d0,
                0x6e69a8fa0016a,
                0xde41ff85dbcb,
                0x3eda6910be34f,
                0x5ce605af98f9,
            ],
        },
        y: FSecp256 {
            v: [
                0x5f3489d30105,
                0xbfa32eccc6c0d,
                0x1c76c58ab3cb1,
                0x6bfe7ba56bd03,
                0x4cddcf9bec22,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3d32b5f067ec2,
                0xb5d5bba5220e5,
                0xd88e8421a288a,
                0x1a11b1a5bf6b7,
                0xda1d61d0ca72,
            ],
        },
        y: FSecp256 {
            v: [
                0xfba0f1ad836f1,
                0x99d279b48a655,
                0x1c91e2966a738,
                0x306c79c076616,
                0x8157f55a7c99,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x210d22cd3c369,
                0x83e1f8e934b3c,
                0xdc1283a236054,
                0xc444df85d5f61,
                0x9c7be00b4ef4,
            ],
        },
        y: FSecp256 {
            v: [
                0xe3feba2329515,
                0x3a16769cbd29e,
                0xce401483e3115,
                0xd2052a26d455,
                0x9220c0de74b2,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xcd92d7bb8c9e3,
                0xa70541178e76b,
                0x8ccc49174dd06,
                0x263bb55664b23,
                0xfcd83f42825,
            ],
        },
        y: FSecp256 {
            v: [
                0xd55fbdf4aa9ad,
                0xcdf1627bf4e86,
                0x5fdb683adbeae,
                0xfbced1d8232de,
                0x6c0bc1cfeac5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x39944b26b64f1,
                0x28f5476d995cf,
                0x511e59db7edcf,
                0xf010d4cda4c62,
                0x7175407f1b58,
            ],
        },
        y: FSecp256 {
            v: [
                0xe7efab24234d5,
                0xb774471d2a426,
                0x34cc86eb01fe8,
                0xd550f36d34011,
                0x43b4554344e3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3b0610d064e13,
                0xe0446f1e062a7,
                0x8fd416615311d,
                0x6907215ff98e,
                0xa8e282ff0c97,
            ],
        },
        y: FSecp256 {
            v: [
                0x7c73111f4cc0c,
                0x3e50dd6bd6cef,
                0xb2515888b679a,
                0x1c09abfb7f3c5,
                0x7f97355b8db8,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xeb9ea7f7653a1,
                0xaa753d67c1c15,
                0xea66e63efbe9e,
                0xaecbcb876f805,
                0xcac6f2e7e27f,
            ],
        },
        y: FSecp256 {
            v: [
                0x10ad0fec5e556,
                0xe5688103a068c,
                0x42a345081e83a,
                0x6f194cdb65d9a,
                0xf7d416e5e2aa,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xf4ab08624003d,
                0x294238cb11cc9,
                0x58e43254ab767,
                0xd206efbc5932e,
                0xe6dfde46ee37,
            ],
        },
        y: FSecp256 {
            v: [
                0x8650e2216b93b,
                0xea527fd7dd754,
                0x88f92203b1ce5,
                0x39498f2f48f7b,
                0x8727b3b7be91,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x1103548dce109,
                0x149cf211d3b0e,
                0xac96082e250e3,
                0x823d66a40cfc7,
                0x3c4e089cd9a6,
            ],
        },
        y: FSecp256 {
            v: [
                0xf65923a19aeea,
                0x42d97fe697e2b,
                0x5764d379579e1,
                0x91b480757bca1,
                0x43fbbe669fe1,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x382de8319497c,
                0xfa512508c022f,
                0x913cab15d59b1,
                0x85872d39e56e6,
                0x174a53b9c9a2,
            ],
        },
        y: FSecp256 {
            v: [
                0xa13ac079afa73,
                0x1d8cb9854383d,
                0xc47f9e6646b3a,
                0x9c1657b4155f2,
                0xccc9dc37abfc,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xda36f840dd273,
                0xe0e4501115f5,
                0x1b92ea3d53d28,
                0x6bb630c7071ef,
                0x20e6e2e79694,
            ],
        },
        y: FSecp256 {
            v: [
                0xcfd15bb46b593,
                0x793da8693cc07,
                0x7874655811ec9,
                0x59e44a0ba1ad9,
                0xd3ad7afe4f15,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x54f301a077674,
                0x136cc24ca3e7b,
                0xe71db7035ae68,
                0x51dba80280a07,
                0x8e0ca824d7a3,
            ],
        },
        y: FSecp256 {
            v: [
                0x4cbec12b7ed98,
                0x19d2f910290b8,
                0xa62cf57cff604,
                0x2d41dc569d24d,
                0x4ec56075919,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xafc5ea8192441,
                0x21a321b4afe96,
                0xe3d66c1afdb58,
                0x82d1c5fa63553,
                0xf7bb50da51c9,
            ],
        },
        y: FSecp256 {
            v: [
                0x40ea1d45165ae,
                0x1fbbc4c74bbc6,
                0xde6485db1cfdc,
                0xa526311bc63bd,
                0x93cc3be30334,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xfdff09475b7ba,
                0x30e4918b3d884,
                0x5018cdbe039e7,
                0x785c3d3e57edf,
                0x959396981943,
            ],
        },
        y: FSecp256 {
            v: [
                0x8abf87524f2fd,
                0x64c8709385e9b,
                0xb9cd6849c653f,
                0x31dd8ba0386a4,
                0x2e7e552888c3,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x75a940bc8f53b,
                0x6b391747c7072,
                0xd73d95ed70222,
                0xa7deafe32ca7d,
                0xcbee1405ff0d,
            ],
        },
        y: FSecp256 {
            v: [
                0x2e6b278c87f45,
                0xf68126f728292,
                0xb8294cf0d9ff4,
                0xf902b51f3e689,
                0xf6211f4f4e75,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x7c88b14b311dd,
                0xaefbd71b9cf37,
                0xba252e03de3be,
                0xf5acdd580bfa0,
                0xadd5bad28faa,
            ],
        },
        y: FSecp256 {
            v: [
                0x982f349d6c38d,
                0xe7669b9b8902f,
                0x359814f52d4e1,
                0xc3a5974e434f8,
                0xe9c43cf4da3d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6400a0d7c0979,
                0x14bc5a8c96f5f,
                0xf41ced24a29b3,
                0x17143fa9df3df,
                0x53f2432ba817,
            ],
        },
        y: FSecp256 {
            v: [
                0x7e90c537b36a2,
                0xf5c9e8b845f9f,
                0x11b07de4bd5a4,
                0x79b7ccd4e3e09,
                0xbd52effbc1f0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x1340c9d82b151,
                0x3d561fba2dbb5,
                0xb109a8fcca0a4,
                0x1e56d645a1153,
                0xd2a63a50ae40,
            ],
        },
        y: FSecp256 {
            v: [
                0x42174dcf89405,
                0xaf484ca52d41,
                0x2948220a70f75,
                0xfcb7565aee58b,
                0xe82d86fb6443,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc4bacca72da5f,
                0x6b36c413497c6,
                0x33725f922b9cd,
                0x525e23bc72020,
                0xbaf183a76100,
            ],
        },
        y: FSecp256 {
            v: [
                0xce628a8f2a0cf,
                0xc5ca739361377,
                0xd69b1d18e2336,
                0x4d335688bd58d,
                0xdeac9fbe9ccb,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xaca58c56c3943,
                0x2d56b76a5ffa5,
                0xe48f6fd5adbd0,
                0x40238f9332906,
                0xf7aef8a7e384,
            ],
        },
        y: FSecp256 {
            v: [
                0xf627facf442f1,
                0x84a8dcd003431,
                0x3ab3fcfeec301,
                0xda797c442bbdc,
                0x4e3b0b44d5ff,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xc945711924459,
                0x25a3c7a78c1fa,
                0xdddbb1f7af2fa,
                0x9036c5a2e29f0,
                0xdfb547cb1001,
            ],
        },
        y: FSecp256 {
            v: [
                0x5e0dcc65fd9e,
                0x30e5c031dcfa2,
                0xdc864cc22af09,
                0x47088b8389ce9,
                0x9accd2a9ba0f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6f9b45617e073,
                0xbd3839317b343,
                0x7cfdc866bacbd,
                0x1eb890ee7896d,
                0x64587e233547,
            ],
        },
        y: FSecp256 {
            v: [
                0x99e5e9faf6589,
                0x39133aeab3582,
                0x7c299a185b90a,
                0x2e2ae96dd644,
                0xd99fcdd5bf69,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xcd88c4384480d,
                0xa22a91f2ef44b,
                0x92f0c1294e0b6,
                0x940f2cf28b54c,
                0xb866d6b142df,
            ],
        },
        y: FSecp256 {
            v: [
                0x59b470c4cafa8,
                0x804b1d86d60e6,
                0xa9ad7ac24e522,
                0xeb7089a278d7e,
                0x1914b0b3426a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x9cda81db20d6c,
                0xe4ed4fe455d22,
                0x102ba87e2d52a,
                0x819ec4d9d1646,
                0xec2bb89085de,
            ],
        },
        y: FSecp256 {
            v: [
                0x99c4d629cf4a0,
                0x4be87efa98a0e,
                0x50940c633a236,
                0x13a1332f66f06,
                0xccecc17661e0,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x60ecb23b09d0f,
                0x640f50becf38a,
                0xe545905e50050,
                0x96ced39d75ef5,
                0x71c4a7e389e2,
            ],
        },
        y: FSecp256 {
            v: [
                0xb1f01720ddb62,
                0x84a62ffc7637,
                0x2f810aa786f2b,
                0xf3ba0af3e0a29,
                0x1313fadb737a,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd6c86dd45e458,
                0xcea250e7fd358,
                0x549de042f0aa6,
                0xd885b3a546d3e,
                0x8481bde0e4e4,
            ],
        },
        y: FSecp256 {
            v: [
                0x4b1b59779057e,
                0xc42b262e556d6,
                0xcecb2ca900a79,
                0x4dd84a25bf39,
                0x38ee7b8cba54,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x433526ce9f114,
                0x5299561dde54,
                0x1d492bf392ed6,
                0x3a8b9fd43c6cd,
                0x9629a450bd38,
            ],
        },
        y: FSecp256 {
            v: [
                0x972c4a24aa391,
                0x3e5c56af8dca3,
                0xcef64db92559,
                0xb6d7576befd22,
                0xbf439b280c5f,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x38d9626ca6cc3,
                0x47e187e18383d,
                0xcc893df1477d7,
                0x4688eb1730da7,
                0xb73b1c47ef1e,
            ],
        },
        y: FSecp256 {
            v: [
                0x35d76a54fdba3,
                0x5209757f5afac,
                0xcc805097322a2,
                0x22a90a57d64bb,
                0x584315cb2949,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe2192d38f93e0,
                0x3bb676899f9c6,
                0x7a2fef7d05b2a,
                0x180311f989200,
                0xedfe16b2db40,
            ],
        },
        y: FSecp256 {
            v: [
                0x1793de29405ad,
                0xc46e227e3d0,
                0xb05d0d25b3d51,
                0xdb3694d74faa4,
                0xee6902f1fca5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x6303f6caf666b,
                0xd3c4b1ce30bcd,
                0x817f4637ffcfe,
                0x2aa62b6979ae,
                0x13464a57a781,
            ],
        },
        y: FSecp256 {
            v: [
                0x95a907f6ecc27,
                0xa81d0942e13f4,
                0x3ccb0ca48f300,
                0x4580ef7e43345,
                0x69be15900461,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x849c6065084ae,
                0x7dceabe577c75,
                0x5fe12d19182be,
                0x5362ec05c88c8,
                0xeb3cf8f53224,
            ],
        },
        y: FSecp256 {
            v: [
                0x7c1fff96b9480,
                0xc5e7dbd2a66f6,
                0xfdca4a1f52b45,
                0xd70043fe63dce,
                0xc833c78222d9,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5bcbcc2e9a5d0,
                0xf984a201d9f8e,
                0x84519b2a576fc,
                0x99974f7a60f21,
                0xbdf1a67d092d,
            ],
        },
        y: FSecp256 {
            v: [
                0x4f7018562ff7b,
                0x61e5626461cdb,
                0x6bf7baaa6280b,
                0xa1aaa80be54a8,
                0x4095902bab65,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x5fc173b27e771,
                0x96477da62abde,
                0x64483b48c3b41,
                0xec29cd5be267b,
                0x68856a6eddc4,
            ],
        },
        y: FSecp256 {
            v: [
                0x8d62a07bbdab6,
                0xf293b0733a611,
                0x19f7b4a331d22,
                0xa1fb13b6fd49c,
                0x77a33df14f79,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xa3a0d2d83f366,
                0xede2f28588cad,
                0xc1dc97a0cd9cc,
                0xfe2e9aef430bc,
                0xbc4a9df5b713,
            ],
        },
        y: FSecp256 {
            v: [
                0x8d666581f33c1,
                0xfbfa547b16d75,
                0x4b798caa6e8a9,
                0x5c06383937adf,
                0xd3a81ca6e78,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xde545f3fceb19,
                0x21f785c409282,
                0xce7bab42e89b2,
                0xccc0abc5c7626,
                0xda433d5e11ce,
            ],
        },
        y: FSecp256 {
            v: [
                0xe7120a6f5cc64,
                0x2d9227b277684,
                0xf95e5218e77fc,
                0x10301debbdc4a,
                0xe498dbd321a8,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xe275c5acf692a,
                0x8a72207e0654d,
                0x1c16efdbcc483,
                0xc7ec1c1c11698,
                0x31e8e1ee9e8,
            ],
        },
        y: FSecp256 {
            v: [
                0x2a84eb16f667a,
                0x27c5bf73b09cc,
                0xd6743b706498,
                0x353dd9d097029,
                0xad7e7f5b465b,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xbd7ff81f488b6,
                0x363fc7a91592b,
                0x2657f73e9c9bf,
                0x61155d3e00d86,
                0xa9878607a88d,
            ],
        },
        y: FSecp256 {
            v: [
                0xa7bbb031dab1d,
                0x1964ad5c6d495,
                0x2157c2239d0f0,
                0x95d61c063e7c8,
                0xd181a1abd588,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xab30fe5324caa,
                0xe30a9472a3954,
                0x452a32e694b65,
                0x8bc0d23d8c749,
                0x8c28a97bf829,
            ],
        },
        y: FSecp256 {
            v: [
                0x1dc73cbef9482,
                0xf0451cb9459e7,
                0xf7cc0eb7ae784,
                0x5193378fedf31,
                0x40a30463a330,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xb201f7611d8e2,
                0xe8de49fc4d5df,
                0x47f0da2c8130f,
                0xa2f196bed5a60,
                0xab1ac1872a38,
            ],
        },
        y: FSecp256 {
            v: [
                0x581f3c429d15b,
                0xd33e1e545f01a,
                0xb6a42b6f7ef93,
                0x17a1e9aa5f39d,
                0x13f4a37a324d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xaee642651b3fa,
                0x65772df434226,
                0x53f31ef8ea1b3,
                0xf82d3703a6072,
                0x2564fe9b5bee,
            ],
        },
        y: FSecp256 {
            v: [
                0x2e6a301e5122d,
                0xab6b79816edb8,
                0x203925f14f37d,
                0x389095fa14ae1,
                0x8ad9f7a60678,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x8e3d3ae180068,
                0x6c20bd3103b17,
                0x30dc01a7ea3d5,
                0x5b0cbfc6c5c0c,
                0xff3d6136ffac,
            ],
        },
        y: FSecp256 {
            v: [
                0x6bb6e188c6077,
                0xf24001f5e670a,
                0xd96adc1547676,
                0xe40d0372cd,
                0x133239be84e4,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x4ba111faccae0,
                0xc5a4bb33748c,
                0xf071fd23c8b35,
                0x27a8c1dd94ce4,
                0x8ea96661395,
            ],
        },
        y: FSecp256 {
            v: [
                0xf34a30e62b945,
                0xbe9cf0f8e955a,
                0xb95c5d735b783,
                0x2782e24e7c0cf,
                0x620efabbc8ee,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0x3131da190b632,
                0x23a4ab5ab9a29,
                0x5559d8263cf2a,
                0xcd9f3a66df31,
                0xc25f63717622,
            ],
        },
        y: FSecp256 {
            v: [
                0xbf3d6fc9590cf,
                0xff9e027a1d6ee,
                0x809d7980a9f04,
                0x2873989049903,
                0x53154fede94d,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xcb3b7d466d561,
                0xdc31978b4de2c,
                0x688544c0c7b55,
                0x6bab3e82d82a5,
                0x2a9e8dfe3cce,
            ],
        },
        y: FSecp256 {
            v: [
                0xccf5252e76373,
                0xec17a02182f96,
                0x8b96cf5e01ea,
                0x651fbac7b5ad6,
                0x1dfeda5c16e,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    P256 {
        x: FSecp256 {
            v: [
                0xd32043f8be384,
                0xada31db6c3e8b,
                0xfdef07271ec0a,
                0x3e1b251ad6c94,
                0xb23790a42be6,
            ],
        },
        y: FSecp256 {
            v: [
                0xa473deb19880e,
                0xf4149ecb58d10,
                0xa81f94517f004,
                0x5edbe8d50f88a,
                0xfc6b694919d5,
            ],
        },
        z: FSecp256::ONE,
        inf: false,
        p: PhantomData,
    },
    // P256 { x: FSecp256 { v:[0x76cc4eb9a9787, 0x815959968092f, 0xbd3788d89bdde, 0xa06074669716b, 0xdd3625faef5b] },
    //        y: FSecp256 { v: [0x68d00c644a573, 0x982883395937f, 0x45731ca941461, 0x30d461da25010, 0x7a188fa3520e]},
    //        z: FSecp256 { v: [0x1, 0x0, 0x0, 0x0, 0x0] },
    //        inf: false, p: PhantomData },
    // P256 { x: FSecp256 { v:[0x14d8f76a9a68, 0x4eba9dac5117f, 0xeef123be1520d, 0xa88365a441507, 0x276b9eff8f2a] },
    //        y: FSecp256 { v: [0x66ac5b8e7eb15, 0x14a0d6029e81d, 0x8e5dab73e8453, 0xdb81bc0ebc0d0, 0x39f8aab0f2f7]},
    //        z: FSecp256 { v: [0x1, 0x0, 0x0, 0x0, 0x0] },
    //        inf: false, p: PhantomData },
    // P256 { x: FSecp256 { v:[0x79775ce776c1, 0x525734feed0b3, 0x24ea870a2c5d0, 0xe80c3bdf4209e, 0x580945b2798e] },
    //        y: FSecp256 { v: [0x57358ca897c27, 0xa2c9da16f3ebe, 0x1a62357d5f84c, 0x8e0217f136210, 0x2e4965553d7]},
    //        z: FSecp256 { v: [0x1, 0x0, 0x0, 0x0, 0x0] },
    //        inf: false, p: PhantomData },
];
