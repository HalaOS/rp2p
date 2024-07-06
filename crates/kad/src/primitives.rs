use uint::construct_uint;

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

impl Key {
    /// Calculate the distance between two [`Key`]s.
    pub fn distance<U>(&self, rhs: U) -> Distance
    where
        U: Into<Key>,
    {
        let lhs = U256::from(self.0.as_slice());
        let rhs = U256::from(rhs.into().0.as_slice());

        Distance(lhs ^ rhs)
    }

    /// Returns the uniquely determined key with the given distance to `self`.
    ///
    /// This implements the following equivalence:
    ///
    /// `self xor other = distance <==> other = self xor distance`
    pub fn for_distance(&self, distance: Distance) -> Self {
        let key_int = U256::from(self.0.as_slice()) ^ distance.0;

        Self(key_int.into())
    }
}

/// The distance between two kad Keys.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance(pub(crate) U256);

impl Distance {
    /// Returns the integer part of the base 2 logarithm of the [`Distance`].
    ///
    /// Returns `None` if the distance is zero.
    pub fn k_index(&self) -> Option<u32> {
        (256 - self.0.leading_zeros()).checked_sub(1)
    }
}

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
    fn symmetry() {
        fn prop(a: Key, b: Key) -> bool {
            a.distance(b) == b.distance(a)
        }
        quickcheck(prop as fn(_, _) -> _)
    }
}
