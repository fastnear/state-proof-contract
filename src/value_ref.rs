use crate::*;
use crate::utils::hash_bytes;

/// State value reference. Used to charge fees for value length before retrieving the value itself.
#[derive(Clone, PartialEq, Eq, Hash)]
#[near(serializers=[borsh])]
pub struct ValueRef {
    /// Value length in bytes.
    pub length: u32,
    /// Unique value hash.
    pub hash: CryptoHash,
}

impl ValueRef {
    /// Create serialized value reference by the value.
    /// Resulting array stores 4 bytes of length and then 32 bytes of hash.
    /// TODO (#7327): consider passing hash here to avoid double computation
    pub fn new(value: &[u8]) -> Self {
        Self { length: value.len() as u32, hash: hash_bytes(value) }
    }
    //
    // /// Decode value reference from the raw byte array.
    // pub fn decode(bytes: &[u8; 36]) -> Self {
    //     let (length, hash) = bytes.sp;
    //     let length = u32::from_le_bytes(*length);
    //     ValueRef { length, hash: CryptoHash(*hash) }
    // }

    /// Returns length of the referenced value.
    pub fn len(&self) -> usize {
        usize::try_from(self.length).unwrap()
    }
}

impl std::cmp::PartialEq<[u8]> for ValueRef {
    fn eq(&self, rhs: &[u8]) -> bool {
        self.len() == rhs.len() && self.hash == hash_bytes(rhs)
    }
}

impl std::fmt::Debug for ValueRef {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "({}, {:?})", self.length, self.hash)
    }
}
