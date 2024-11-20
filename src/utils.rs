use crate::*;

pub(crate) const ACCOUNT_DATA_SEPARATOR: u8 = b',';
// The use of `ACCESS_KEY` as a separator is a historical artefact.
// Changing it would require a very long DB migration for basically no benefits.
pub(crate) const ACCESS_KEY_SEPARATOR: u8 = col::ACCESS_KEY;

pub(crate) fn hash_bytes(bytes: &[u8]) -> CryptoHash {
    near_sdk::env::sha256(bytes).try_into().unwrap()
}

pub(crate) fn into_magic_key(key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(key.len() * 2);
    for &k in key {
        v.push(k >> 4);
        v.push(k & 15);
    }
    v
}

pub(crate) fn decode_key(key: &[u8]) -> Option<Vec<u8>> {
    if key.is_empty() {
        return None;
    }
    let mut v = if key[0] & 16 == 16 {
        vec![key[0] & 15]
    } else {
        vec![]
    };
    v.reserve_exact(key.len() - 1);
    for &k in &key[1..] {
        v.push(k >> 4);
        v.push(k & 15);
    }
    Some(v)
}

/// Type identifiers used for DB key generation to store values in the key-value storage.
pub mod col {
    /// This column id is used when storing `primitives::account::Account` type about a given
    /// `account_id`.
    pub const ACCOUNT: u8 = 0;
    /// This column id is used when storing contract blob for a given `account_id`.
    pub const CONTRACT_CODE: u8 = 1;
    /// This column id is used when storing `primitives::account::AccessKey` type for a given
    /// `account_id`.
    pub const ACCESS_KEY: u8 = 2;
    /// This column id is used when storing `primitives::receipt::ReceivedData` type (data received
    /// for a key `data_id`). The required postponed receipt might be still not received or requires
    /// more pending input data.
    pub const RECEIVED_DATA: u8 = 3;
    /// This column id is used when storing `primitives::hash::CryptoHash` (ReceiptId) type. The
    /// ReceivedData is not available and is needed for the postponed receipt to execute.
    pub const POSTPONED_RECEIPT_ID: u8 = 4;
    /// This column id is used when storing the number of missing data inputs that are still not
    /// available for a key `receipt_id`.
    pub const PENDING_DATA_COUNT: u8 = 5;
    /// This column id is used when storing the postponed receipts (`primitives::receipt::Receipt`).
    pub const POSTPONED_RECEIPT: u8 = 6;
    /// This column id is used when storing:
    /// * the indices of the delayed receipts queue (a singleton per shard)
    /// * the delayed receipts themselves
    /// The identifier is shared between two different key types for historical reasons. It
    /// is valid because the length of `TrieKey::DelayedReceipt` is always greater than
    /// `TrieKey::DelayedReceiptIndices` when serialized to bytes.
    pub const DELAYED_RECEIPT_OR_INDICES: u8 = 7;
    /// This column id is used when storing Key-Value data from a contract on an `account_id`.
    pub const CONTRACT_DATA: u8 = 9;
    /// This column id is used when storing the indices of the PromiseYield timeout queue
    pub const PROMISE_YIELD_INDICES: u8 = 10;
    /// This column id is used when storing the PromiseYield timeouts
    pub const PROMISE_YIELD_TIMEOUT: u8 = 11;
    /// This column id is used when storing the postponed PromiseYield receipts
    /// (`primitives::receipt::Receipt`).
    pub const PROMISE_YIELD_RECEIPT: u8 = 12;
    /// Indices of outgoing receipts. A singleton per shard.
    /// (`primitives::receipt::BufferedReceiptIndices`)
    pub const BUFFERED_RECEIPT_INDICES: u8 = 13;
    /// Outgoing receipts that need to be buffered due to congestion +
    /// backpressure on the receiving shard.
    /// (`primitives::receipt::Receipt`).
    pub const BUFFERED_RECEIPT: u8 = 14;
}
