use crate::*;

use near_sdk::borsh;
use near_sdk::json_types::{Base58CryptoHash, Base64VecU8};
use near_sdk::serde_json::to_string;
use raw_node::RawTrieNode;
use raw_node::RawTrieNodeWithSize;
use std::collections::HashMap;
use utils::*;
use value_ref::ValueRef;

#[near(serializers=[json])]
pub struct RawTrieProof(pub Vec<Base64VecU8>);

#[derive(Debug, Clone)]
pub struct TrieProof {
    pub nodes: HashMap<CryptoHash, RawTrieNodeWithSize>,
}

impl TryFrom<RawTrieProof> for TrieProof {
    type Error = ();

    fn try_from(value: RawTrieProof) -> Result<Self, Self::Error> {
        let mut this = Self {
            nodes: HashMap::new(),
        };
        for node in value.0 {
            let hash = hash_bytes(&node.0);
            println!(
                "hash_parse: {}",
                to_string(&Base58CryptoHash::from(hash)).unwrap()
            );
            let node: RawTrieNodeWithSize = borsh::from_slice(&node.0).map_err(|_| ())?;
            this.nodes.insert(hash, node);
        }
        Ok(this)
    }
}

impl TrieProof {
    pub fn validate(&self, root: CryptoHash, key: &[u8], value: &[u8]) -> Option<()> {
        let mut offset = 0;
        let key = into_magic_key(key);
        println!("key: {:?}", key);
        let expected_value_ref = ValueRef::new(value);
        let mut hash = root;
        loop {
            println!(
                "hash: {}",
                to_string(&Base58CryptoHash::from(hash)).unwrap()
            );
            let node = self.nodes.get(&hash)?;
            println!("got node: {:?}", node);
            let need_leaf = offset == key.len();
            match &node.node {
                RawTrieNode::Leaf(leaf_key, value) => {
                    let leaf_key = decode_key(&leaf_key)?;
                    return (leaf_key == key[offset..] && value == &expected_value_ref)
                        .then_some(());
                }
                RawTrieNode::BranchNoValue(_children) if need_leaf => {
                    return None;
                }
                RawTrieNode::BranchWithValue(value, _children) if need_leaf => {
                    return (value == &expected_value_ref).then_some(());
                }
                RawTrieNode::BranchNoValue(children)
                | RawTrieNode::BranchWithValue(_, children) => {
                    let idx = key[offset];
                    if let Some(child) = children[idx].as_ref() {
                        hash = *child;
                        offset += 1;
                    } else {
                        return None;
                    }
                }
                RawTrieNode::Extension(ext_key, child) => {
                    let ext_key = decode_key(&ext_key)?;
                    if ext_key.is_empty() {
                        // Bad input. SCAM!
                        return None;
                    }
                    if !key[offset..].starts_with(&ext_key) {
                        return None;
                    }
                    hash = *child;
                    offset += ext_key.len();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{col, ACCOUNT_DATA_SEPARATOR};
    use near_sdk::json_types::Base58CryptoHash;
    use std::str::FromStr;

    #[test]
    pub fn test_proof_1() {
        let raw_proof = r#"[
          "AwEAAAAQnr0mq6XsNI3Lgd3VunppRjE5YZ2CX8WRkOLa3ARVPxX9bv+TAAAAAA==",
          "AQcC19f7QKgVWoGyAEqaCoqlfYdwB91IQwqb4VRURwxmUl0bj62zha+64cw7lPixT38qHv00iyu8X0W7nSCZm1geXHSIuUs5ulP1dF6zyaRJMnrczjxxl3kQpvtU4ZZn6JF0j9vSJCDd9LXE9F5FlCxrA5qCpVfnrPRS5D9T2W7wqNXJbv+TAAAAAA==",
          "AcgAThqDpQQMSFcimGqz4vyQ8oJVthFg1kSug9BhBSeuZznuG5Tu+umfKu1Lu0K6e8+jjbA9N94FyowyZHbVqfLHFFAEB/UJif+hl2JJkRp+ite8Zw9WBiDgl4V3ydlEs2WeEkHVAAAAAAA=",
          "Af7/aUXEwDTd7NnU2soGwKFZCw4FltXJgGqDx0ARMVOmBa/YaClooI8xUiQAlVB4oxzSXLdhKdk0BPZox1InYMMM0XVsbYL17mpkn6B95D1KnaOzvezSHfax5oyZ/1QLW5yyXBYNx6FznFjspWHP6A+l7AfBJUz8zKIWi50WnscSyttxbsKL0zSteLKii0XlmTM87aJ3d/utwamylQfrwYKuXJh5bwhEReRJXHSgJaRzusd29QgY870MGCVtABnPE6qXqMjKCtV7WSXotRQ2NVn7P4PWFl9zsuBq5pCIUN/lYy3n0MuMQAB9g24GhYv3RlDnz5dwe27bUiqPAz0VpTwWDeEYRy/ddKCRMIn22khREfd9Ilfrq6sfQb/MXFBc4IBl1PXb8d3eGBotTkKZ8j6clLn2MAftg4SmjgBQt579pijWi1/PRha0phjD36lOB6d+QtPizxiOoFrUneDe3HrMfNTPBc6P4N/xPOcw7w0fHRcK1ifzTUkGYw5MKhw858uKUBnGVSwqhLkSLK3LsEdvb/aqPenKRWKvNLGDl5+cnR5t3puez1fnnaUsB/9xF7BS8wUe/39j748hrfZYVCAOib/6M0dN/3kyXTbPMcQharZdr9fG+Nponu1XXA7rcj07Z/GuAAAAAAA=",
          "AcgAulp6DZ10irZO+cVoLi+RAu/ursczBCTKJphJ2SBg02ZEmTarghRXKDvPfR955cVhWiiOFbGfOBk2I1zrxPnU9G5/0SomOa2tYyknqoOnbiolxJNoGHoucq8QGXNh8jO7S8IQAAAAAAA=",
          "Af8DZRnIOlCuxt0LQuvMFNqnTSbpa7viOPwfA/JQdpvPtRPz1OnFXTF5csiUxDv3UZVyMfi3FTrVVC5wHFPQAtwLy5CThX/PHoGhrGzeaIlnQ6o1JxozmzD5cK17VL6aAfdp5cy7ZJy/2lDMaPus6usSgbkEJdUZw660ZbK90RrEbKn0dLL9qCDMJ2FFQIlkI9Bepel//tC0EriE7Xsrf1r3Dp7vAbKeCSPGT1nbU3oZMhNXkz+qnJCG6mpJldde13WF+3MuDzt5mO+7aHzo3FYoS0yzPAe0og3twMKmFYn2SC9kIlJBQFNWRD8TJbjDD5fWzDbnaWHBiRsxLFCtgPom7VqFCJBGiwF21IwolLOiOgYqraWHk6POKCZxmJBCkwNZCVPzJrbacnSMFfGfgEeKn0njXSfpewX12ycXsId+/oXIMAEAAAAAAA==",
          "AUgAnWNfzlIvwsyv7WSDtx+xElAqW9P9ImBQRVLOEuyYVPBEcuKZ6TLAtmUWimPkLNokTP0eDHKzPKjHkcn1+1HoEUgmAAAAAAAA",
          "ATwQPOvrPtBKiw51PTJDMSGVqAbm0tDtmWI9RZYZefxyDWzf6OOTMa+cs4I0Di1YP3nWHNGJpcQW0MSHBLyMDR0xrfAgFaHxvLJwrWqRFC8EzpIkFcDl/6Ptrh6USGqlJqokh44SDA5UWcEUJ/8wfKnGeFedUareqkUdzP2TQDt/l79YHN1by/C1+8CJ3SjX7kotV5+m6JiPzruUXI+TZp74RJERAAAAAAAA",
          "ADgAAAAgNTk4ODM1N2JjNWZmZTUxMWZmZjI4NmUwM2QwNTUwNWE3NmJjMS5sb2NrdXAubmVhcixTVEFURZsAAAD3OggS6hUxgWunEEcYSJBZHpgJ2Et81s8C9RHB4I1iuG8BAAAAAAAA"
        ]"#;
        let proof: RawTrieProof =
            serde_json::from_str(raw_proof).expect("Failed to parse JSON proof");
        let trie_proof = TrieProof::try_from(proof).expect("Failed to parse TrieProof");

        let partial_key: Base64VecU8 =
            serde_json::from_str("\"U1RBVEU=\"").expect("Failed to parse key");
        let partial_key = partial_key.0;
        let value: Base64VecU8 = serde_json::from_str("\"CgAAAGlsbGlhLm5lYXIAAAByaQZkbulbKQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAFq3NEQMAAAESAAAAdHJhbnNmZXItdm90ZS5uZWFyABUAAABsb2NrdXAtd2hpdGVsaXN0Lm5lYXIBEwAAAHphdm9kaWwucG9vbHYxLm5lYXIAAAAAb+wBHqFfaAwAAAAAAAA=\"").expect("Failed to parse value");
        let value = value.0;

        let account_id = "c3e5988357bc5ffe511fff286e03d05505a76bc1.lockup.near";

        let mut key = vec![col::CONTRACT_DATA];
        key.extend(account_id.as_bytes());
        key.push(ACCOUNT_DATA_SEPARATOR);
        key.extend(partial_key);

        let state_root = Base58CryptoHash::from_str("EAf6x6aQ79pQ5c21Q9NhsF3Jf64hwjPVqQmgNDydDV5W")
            .expect("Failed to parse state root")
            .into();

        assert!(trie_proof.validate(state_root, &key, &value).is_some());
    }

    #[test]
    pub fn test_proof_2() {
        let raw_proof = r#"[
            "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"
        ]"#;
        let proof: RawTrieProof =
            serde_json::from_str(raw_proof).expect("Failed to parse JSON proof");
        let trie_proof = TrieProof::try_from(proof).expect("Failed to parse TrieProof");

        let partial_key: Base64VecU8 =
            serde_json::from_str("\"U1RBVEU=\"").expect("Failed to parse key");
        let partial_key = partial_key.0;
        let value: Base64VecU8 = serde_json::from_str("\"CgAAAGlsbGlhLm5lYXIAAAByaQZkbulbKQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAFq3NEQMAAAESAAAAdHJhbnNmZXItdm90ZS5uZWFyABUAAABsb2NrdXAtd2hpdGVsaXN0Lm5lYXIBEAAAAGF1cm9yYS5wb29sLm5lYXIAAAAASkgBFBaVRQgAAAAAAAA=\"").expect("Failed to parse value");
        let value = value.0;

        let account_id = "c3e5988357bc5ffe511fff286e03d05505a76bc1.lockup.near";

        let mut key = vec![col::CONTRACT_DATA];
        key.extend(account_id.as_bytes());
        key.push(ACCOUNT_DATA_SEPARATOR);
        key.extend(partial_key);

        let state_root = Base58CryptoHash::from_str("6qexGgUPQCQCkqfNu9td1mSZpxzZBd2G2sHwTor31U8S")
            .expect("Failed to parse state root")
            .into();

        assert!(trie_proof.validate(state_root, &key, &value).is_some());
    }
}
