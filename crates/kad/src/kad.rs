use std::net::SocketAddr;

use uint::construct_uint;

use crate::kbucket::{KBucketDistance, KBucketKey};

construct_uint! {
    pub(crate) struct U256(4);
}

/// A kad key with 256 bits length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub [u8; 32]);

impl From<[u8; 32]> for Key {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Key {
    fn from(value: &[u8]) -> Self {
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();

        hasher.update(value);

        Self(hasher.finalize().into())
    }
}

impl From<identity::PeerId> for Key {
    fn from(value: identity::PeerId) -> Self {
        value.to_bytes().as_slice().into()
    }
}

impl KBucketKey for Key {
    type Length = generic_array::typenum::U256;
    type Distance = Distance;

    /// Calculate the distance between two [`Key`]s.
    fn distance(&self, rhs: &Self) -> Distance {
        let lhs = U256::from(self.0.as_slice());
        let rhs = U256::from((*rhs).0.as_slice());

        Distance(lhs ^ rhs)
    }

    /// Returns the uniquely determined key with the given distance to `self`.
    ///
    /// This implements the following equivalence:
    ///
    /// `self xor other = distance <==> other = self xor distance`
    fn for_distance(&self, distance: Distance) -> Self {
        let key_int = U256::from(self.0.as_slice()) ^ distance.0;

        Self(key_int.into())
    }

    /// Returns the longest common prefix length with `rhs`.
    fn longest_common_prefix(&self, rhs: &Self) -> usize {
        self.distance(rhs).0.leading_zeros() as usize
    }
}

/// The distance between two kad Keys.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance(pub(crate) U256);

impl KBucketDistance for Distance {
    /// Returns the integer part of the base 2 logarithm of the [`Distance`].
    ///
    /// Returns `None` if the distance is zero.
    fn k_index(&self) -> Option<u32> {
        (256 - self.0.leading_zeros()).checked_sub(1)
    }
}

/// Kad default `KBucketTable` type.
pub type KBucketTable = crate::kbucket::KBucketTable<Key, SocketAddr>;

#[cfg(test)]
mod tests {
    use super::*;

    use identity::PeerId;
    use quickcheck::*;

    impl Arbitrary for Key {
        fn arbitrary(_: &mut Gen) -> Key {
            Key::from(PeerId::random())
        }
    }

    #[test]
    fn distance_symmetry() {
        fn prop(a: Key, b: Key) -> bool {
            a.distance(&b) == b.distance(&a)
        }
        quickcheck(prop as fn(_, _) -> _)
    }

    #[test]
    fn for_distance() {
        fn prop(a: Key, b: Key) -> bool {
            a.for_distance(a.distance(&b)) == b
        }
        quickcheck(prop as fn(_, _) -> _)
    }

    #[test]
    fn k_distance_0() {
        assert_eq!(Distance(U256::from(0)).k_index(), None);
        assert_eq!(Distance(U256::from(1)).k_index(), Some(0));
        assert_eq!(Distance(U256::from(2)).k_index(), Some(1));
        assert_eq!(Distance(U256::from(3)).k_index(), Some(1));
    }

    #[test]
    fn k_bucket_update() {
        let local_key = Key::from(PeerId::random());
        let mut k_bucket_table = KBucketTable::new(local_key, 20);

        assert_eq!(k_bucket_table.len(), 0);

        let a = Key::from(PeerId::random());

        k_bucket_table.update(&a, |value| {
            assert!(value.is_none());

            Some("127.0.0.1:1921".parse().unwrap())
        });

        assert_eq!(k_bucket_table.len(), 1);

        let value = k_bucket_table.get(&a);

        assert_eq!(value, Some(&"127.0.0.1:1921".parse().unwrap()));

        k_bucket_table.update(&a, |value| {
            assert_eq!(value, Some(&"127.0.0.1:1921".parse().unwrap()));

            Some("127.0.0.1:1922".parse().unwrap())
        });

        assert_eq!(k_bucket_table.len(), 1);

        let value = k_bucket_table.get(&a);

        assert_eq!(value, Some(&"127.0.0.1:1922".parse().unwrap()));
    }
}
