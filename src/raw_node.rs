use crate::*;

use near_sdk::borsh;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};

use value_ref::ValueRef;
use utils::hash_bytes;

/// Trie node with memory cost of its subtree.
///
/// memory_usage is serialized, stored and contributes to hash.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers=[borsh])]
pub struct RawTrieNodeWithSize {
    pub node: RawTrieNode,
    pub memory_usage: u64,
}

impl RawTrieNodeWithSize {
    pub fn hash(&self) -> CryptoHash {
        hash_bytes(&borsh::to_vec(&self).unwrap())
    }
}

/// Trie node.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers=[borsh])]
#[allow(clippy::large_enum_variant)]
pub enum RawTrieNode {
    /// Leaf(key, value_length, value_hash)
    Leaf(Vec<u8>, ValueRef),
    /// Branch(children)
    BranchNoValue(Children),
    /// Branch(children, value)
    BranchWithValue(ValueRef, Children),
    /// Extension(key, child)
    Extension(Vec<u8>, CryptoHash),
}

impl RawTrieNode {
    #[inline]
    pub fn branch(children: Children, value: Option<ValueRef>) -> Self {
        match value {
            Some(value) => Self::BranchWithValue(value, children),
            None => Self::BranchNoValue(children),
        }
    }
}

/// Children of a branch node.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Children<T = CryptoHash>(pub [Option<T>; 16]);

impl<T> Children<T> {
    /// Iterates over existing children; `None` entries are omitted.
    #[inline]
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (u8, &'a T)> {
        self.0.iter().enumerate().flat_map(|(i, el)| Some(i as u8).zip(el.as_ref()))
    }
}

impl<T> Default for Children<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> std::ops::Index<u8> for Children<T> {
    type Output = Option<T>;
    fn index(&self, index: u8) -> &Option<T> {
        &self.0[usize::from(index)]
    }
}

impl<T> std::ops::IndexMut<u8> for Children<T> {
    fn index_mut(&mut self, index: u8) -> &mut Option<T> {
        &mut self.0[usize::from(index)]
    }
}

impl<T: BorshSerialize> BorshSerialize for Children<T> {
    fn serialize<W: std::io::Write>(&self, wr: &mut W) -> std::io::Result<()> {
        let mut bitmap: u16 = 0;
        let mut pos: u16 = 1;
        for child in self.0.iter() {
            if child.is_some() {
                bitmap |= pos
            }
            pos <<= 1;
        }
        bitmap.serialize(wr)?;
        self.0.iter().flat_map(Option::as_ref).map(|child| child.serialize(wr)).collect()
    }
}

impl<T: BorshDeserialize> BorshDeserialize for Children<T> {
    fn deserialize_reader<R: std::io::Read>(rd: &mut R) -> std::io::Result<Self> {
        let mut bitmap = u16::deserialize_reader(rd)?;
        let mut children = Self::default();
        while bitmap != 0 {
            let idx = bitmap.trailing_zeros() as u8;
            bitmap &= bitmap - 1;
            children[idx] = Some(T::deserialize_reader(rd)?);
        }
        Ok(children)
    }
}

mod children {
    struct Debug<'a, T>((u8, &'a T));

    impl<T: std::fmt::Debug> std::fmt::Debug for Debug<'_, T> {
        fn fmt(&self, fmtr: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(fmtr, "{}: {:?}", self.0 .0, self.0 .1)
        }
    }

    impl<T: std::fmt::Debug> std::fmt::Debug for super::Children<T> {
        fn fmt(&self, fmtr: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            fmtr.debug_list().entries(self.iter().map(Debug)).finish()
        }
    }
}
