// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(unsafe_op_in_unsafe_fn)]

use crate::block::Block;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};
use std::ptr::NonNull;

/// Structure representing the memory matrix.
pub struct Memory {
    /// The number of rows.
    rows: usize,

    /// The number of columns.
    cols: usize,

    /// The flat array of blocks representing the memory matrix.
    blocks: Box<[Block]>,
}

impl Memory {
    /// Creates a new memory matrix.
    pub fn new(lanes: u32, lane_length: u32) -> Memory {
        let rows = lanes as usize;
        let cols = lane_length as usize;
        let total = rows * cols;
        let blocks = vec![Block::zero(); total].into_boxed_slice();
        Memory { rows, cols, blocks }
    }

    /// Returns a pointer to the flat array of blocks useful for parallel disjoint access.
    pub fn as_unsafe_blocks(&mut self) -> UnsafeBlocks<'_> {
        UnsafeBlocks {
            blocks: NonNull::new(self.blocks.as_mut_ptr()).unwrap(),
            phantom: PhantomData,
        }
    }
}

/// A wrapped raw pointer to the flat array of blocks, useful for parallel disjoint access.
///
/// All operations on this type are unchecked and require `unsafe`. Callers are responsible for
/// accessing the blocks without violating the aliasing rules or resulting in data races.
pub struct UnsafeBlocks<'a> {
    blocks: NonNull<Block>,
    phantom: PhantomData<&'a [Block]>,
}

impl UnsafeBlocks<'_> {
    /// Get a shared reference to the `Block` at `index`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `index` is in bounds, no mutable references exist or are
    /// created to the corresponding block, and no data races happen while the returned reference
    /// lives.
    pub unsafe fn get_unchecked(&self, index: usize) -> &Block {
        // SAFETY: the caller promises that the `index` is in bounds; therefore, we're within the
        // bounds of the allocated object, and the offset in bytes fits in an `isize`.
        let ptr = unsafe { self.blocks.add(index) };
        // SAFETY: the caller promises that there are no mutable references to the requested
        // `Block` or data races; and `ptr` points to a valid and aligned `Block`.
        unsafe { ptr.as_ref() }
    }

    /// Get a mutable reference to the `Block` at `index`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `index` is in bounds, no other references exist or are created
    /// to the corresponding block, and no data races happen while the returned reference lives.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut_unchecked(&self, index: usize) -> &mut Block {
        // SAFETY: the caller promises that the `index` is in bounds; therefore, we're within
        // the bounds of the allocated object, and the offset in bytes fits in an `isize`.
        let mut ptr = unsafe { self.blocks.add(index) };
        // SAFETY: the caller promises that there are no other references, accesses, or data races
        // affecting the target `Block`; and `ptr` points to a valid and aligned `Block`.
        //
        // Also note that this isn't interior mutability, as we're going through a `NonNull`
        // pointer derived from a mutable reference (and interior mutability is not transitive
        // through raw pointers[1][2][3]).
        //
        // [1]: https://rust-lang.github.io/unsafe-code-guidelines/glossary.html#interior-mutability
        // [2]: https://doc.rust-lang.org/stable/reference/behavior-considered-undefined.html?highlight=undefin#r-undefined.immutable
        // [3]: https://github.com/rust-lang/reference/issues/1227
        unsafe { ptr.as_mut() }
    }
}

// SAFETY: passing or sharing an `UnsafeBlocks` accross threads is, in itself, safe (calling any
// methods on it isn't, but they already require `unsafe`).
unsafe impl Send for UnsafeBlocks<'_> {}
unsafe impl Sync for UnsafeBlocks<'_> {}

impl Debug for Memory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Memory {{ rows: {}, cols: {} }}", self.rows, self.cols)
    }
}

impl Index<u32> for Memory {
    type Output = Block;
    fn index(&self, index: u32) -> &Block {
        &self.blocks[index as usize]
    }
}

impl Index<u64> for Memory {
    type Output = Block;
    fn index(&self, index: u64) -> &Block {
        &self.blocks[index as usize]
    }
}

impl Index<(u32, u32)> for Memory {
    type Output = Block;
    fn index(&self, index: (u32, u32)) -> &Block {
        let pos = ((index.0 as usize) * self.cols) + (index.1 as usize);
        &self.blocks[pos]
    }
}

impl IndexMut<u32> for Memory {
    fn index_mut(&mut self, index: u32) -> &mut Block {
        &mut self.blocks[index as usize]
    }
}

impl IndexMut<u64> for Memory {
    fn index_mut(&mut self, index: u64) -> &mut Block {
        &mut self.blocks[index as usize]
    }
}

impl IndexMut<(u32, u32)> for Memory {
    fn index_mut(&mut self, index: (u32, u32)) -> &mut Block {
        let pos = ((index.0 as usize) * self.cols) + (index.1 as usize);
        &mut self.blocks[pos]
    }
}

#[cfg(test)]
mod tests {

    use crate::memory::Memory;

    #[test]
    fn new_returns_correct_instance() {
        let lanes = 4;
        let lane_length = 128;
        let memory = Memory::new(lanes, lane_length);
        assert_eq!(memory.rows, lanes as usize);
        assert_eq!(memory.cols, lane_length as usize);
        assert_eq!(memory.blocks.len(), 512);
    }
}
