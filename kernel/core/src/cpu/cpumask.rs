// SPDX-License-Identifier: MPL-2.0

//! The text formats of CPU sets in sysfs.
//!
//! Callers append the trailing newline.

use alloc::vec;
use core::fmt::{self, Write};

/// Writes `cpus`, given in ascending order, as a list of ranges, such as `0,2-3,5`.
///
/// An empty set produces nothing.
///
/// Reference: `bitmap_list_string` (`%*pbl`) in
/// <https://elixir.bootlin.com/linux/v7.2/source/lib/vsprintf.c#L1270-L1297>.
pub(crate) fn write_cpu_list<W: Write + ?Sized>(
    w: &mut W,
    cpus: impl IntoIterator<Item = u32>,
) -> fmt::Result {
    let mut cpus = cpus.into_iter().peekable();
    let mut first = true;
    while let Some(start) = cpus.next() {
        let mut end = start;
        while cpus.next_if(|&next| next == end + 1).is_some() {
            end += 1;
        }
        if !first {
            w.write_char(',')?;
        }
        first = false;
        if start == end {
            write!(w, "{}", start)?;
        } else {
            write!(w, "{}-{}", start, end)?;
        }
    }
    Ok(())
}

/// Writes `cpus` as a hexadecimal mask of `nr_bits` bits, such as `00,00000001`.
///
/// The mask is printed in 32-bit chunks, most significant first, separated by `,`.
/// The first chunk has as many digits as its bits need; the others have eight.
/// CPUs at or beyond `nr_bits` are ignored.
///
/// Reference: `bitmap_string` (`%*pb`) in
/// <https://elixir.bootlin.com/linux/v7.2/source/lib/vsprintf.c#L1226-L1267>.
pub(crate) fn write_cpu_mask<W: Write + ?Sized>(
    w: &mut W,
    cpus: impl IntoIterator<Item = u32>,
    nr_bits: usize,
) -> fmt::Result {
    const CHUNK_BITS: usize = 32;

    let mut chunks = vec![0u32; nr_bits.div_ceil(CHUNK_BITS)];
    for cpu in cpus {
        let cpu = cpu as usize;
        if cpu < nr_bits {
            chunks[cpu / CHUNK_BITS] |= 1 << (cpu % CHUNK_BITS);
        }
    }

    let top_bits = match nr_bits % CHUNK_BITS {
        0 => CHUNK_BITS,
        bits => bits,
    };
    for (i, chunk) in chunks.iter().rev().enumerate() {
        if i == 0 {
            write!(w, "{:01$x}", chunk, top_bits.div_ceil(4))?;
        } else {
            write!(w, ",{:08x}", chunk)?;
        }
    }
    Ok(())
}

#[cfg(ktest)]
mod test {
    use alloc::string::String;

    use ostd::prelude::ktest;

    use super::*;

    fn list(cpus: &[u32]) -> String {
        let mut s = String::new();
        write_cpu_list(&mut s, cpus.iter().copied()).unwrap();
        s
    }

    fn mask(cpus: &[u32], nr_bits: usize) -> String {
        let mut s = String::new();
        write_cpu_mask(&mut s, cpus.iter().copied(), nr_bits).unwrap();
        s
    }

    #[ktest]
    fn lists() {
        assert_eq!(list(&[]), "");
        assert_eq!(list(&[0]), "0");
        assert_eq!(list(&[0, 1, 2, 3]), "0-3");
        assert_eq!(list(&[0, 2, 3, 5]), "0,2-3,5");
        assert_eq!(list(&[1, 3, 4, 5, 9, 10]), "1,3-5,9-10");
    }

    #[ktest]
    fn masks() {
        assert_eq!(mask(&[0, 1, 2, 3], 4), "f");
        assert_eq!(mask(&[0, 1, 2, 3, 4, 5], 6), "3f");
        assert_eq!(mask(&[0], 1), "1");
        assert_eq!(mask(&[], 4), "0");
        assert_eq!(mask(&[1], 8), "02");
        assert_eq!(mask(&[0], 32), "00000001");
        assert_eq!(mask(&[0], 40), "00,00000001");
        assert_eq!(mask(&[39, 32, 31], 40), "81,80000000");
        assert_eq!(mask(&[0, 64], 65), "1,00000000,00000001");
        assert_eq!(mask(&[], 0), "");
    }
}
