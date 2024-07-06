use std::collections::VecDeque;

use generic_array::{ArrayLength, GenericArray};

/// A key type trait used for [`KBucketTable`]
pub trait KBucketKey {
    type Length: ArrayLength;
}

struct KBucket<Key, Value> {
    nodes: VecDeque<(Key, Value)>,
}

/// Kad route table implementation using k-bucket structure.
pub struct KBucketTable<Key, Value>
where
    Key: KBucketKey,
{
    /// The maximum constant value for the number of bucket nodes.
    const_k: usize,
    /// The pool of bucket objects that have been created.
    buckets: Vec<KBucket<Key, Value>>,
    /// Bucket index in bucket pool.
    indexes: GenericArray<usize, Key::Length>,
}

impl<Key, Value> Default for KBucketTable<Key, Value>
where
    Key: KBucketKey,
{
    fn default() -> Self {
        Self {
            const_k: 20,
            buckets: Default::default(),
            indexes: Default::default(),
        }
    }
}

impl<Key, Value> KBucketTable<Key, Value>
where
    Key: KBucketKey,
{
    /// Create `KBucketTable` with custom `const_k` value.
    pub fn new(const_k: usize) -> Self {
        Self {
            const_k,
            ..Default::default()
        }
    }

    /// Put key/value pair into the k-bucket table.
    pub fn put(&mut self, _key: Key, _value: Value) {}
}
