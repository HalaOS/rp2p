use std::collections::VecDeque;

use generic_array::{ArrayLength, GenericArray};

/// A key type trait used for [`KBucketTable`]
pub trait KBucketKey {
    type Length: ArrayLength;
    type Distance: KBucketDistance;

    /// Calculate the distance between two [`Key`]s.
    fn distance(&self, rhs: &Self) -> Self::Distance
    where
        Self: Sized;

    /// Returns the uniquely determined key with the given distance to `self`.
    ///
    /// This implements the following equivalence:
    ///
    /// `self xor other = distance <==> other = self xor distance`
    fn longest_common_prefix(&self, rhs: &Self) -> usize
    where
        Self: Sized;

    /// Returns the longest common prefix length with `rhs`.
    fn for_distance(&self, distance: Self::Distance) -> Self;
}

pub trait KBucketDistance {
    /// Returns the integer part of the base 2 logarithm of the [`Distance`].
    ///
    /// Returns `None` if the distance is zero.
    fn k_index(&self) -> Option<u32>;
}

#[derive(Debug)]
struct KBucket<Key, Value> {
    nodes: VecDeque<(Key, Value)>,
}

impl<Key, Value> Default for KBucket<Key, Value> {
    fn default() -> Self {
        Self {
            nodes: VecDeque::default(),
        }
    }
}

impl<Key, Value> KBucket<Key, Value> {
    fn remove(&mut self, remove_key: &Key) -> Option<(Key, Value)>
    where
        Key: PartialEq,
    {
        let mut remove_index = None;

        for (index, (key, _)) in self.nodes.iter().enumerate() {
            if *key == *remove_key {
                remove_index = Some(index);
                break;
            }
        }

        if let Some(remove_index) = remove_index {
            self.nodes.remove(remove_index)
        } else {
            None
        }
    }
}

/// Kad route table implementation using k-bucket data structure.
pub struct KBucketsTable<Key, Value>
where
    Key: KBucketKey,
{
    /// local node key.
    local_key: Key,
    /// The maximum constant value for the number of bucket nodes.
    const_k: usize,
    /// The pool of bucket objects that have been created.
    buckets: Vec<KBucket<Key, Value>>,
    /// Bucket index in bucket pool.
    indexes: GenericArray<Option<usize>, Key::Length>,
}

impl<Key, Value> KBucketsTable<Key, Value>
where
    Key: KBucketKey,
{
    /// Create `KBucketTable` with custom `const_k` value.
    pub fn new(local_key: Key, const_k: usize) -> Self {
        Self {
            local_key,
            const_k,
            buckets: Default::default(),
            indexes: Default::default(),
        }
    }

    /// update key/value pair in the k-bucket table.
    ///
    /// This function has no side effects if called with `local_key`.
    pub fn update<F>(&mut self, key: &Key, callback: F)
    where
        F: FnOnce(Option<&(Key, Value)>) -> Option<Value>,
        Key: Clone + PartialEq,
    {
        let k_index = key.distance(&self.local_key).k_index();

        if let Some(k_index) = k_index {
            let k_index = k_index as usize;
            assert!(k_index < self.indexes.len());

            let k_bucket = if let Some(index) = self.indexes[k_index] {
                self.buckets.get_mut(index).unwrap()
            } else {
                self.buckets.push(KBucket::default());
                self.indexes[k_index] = Some(self.buckets.len() - 1);
                self.buckets.last_mut().unwrap()
            };

            if let Some(pair) = k_bucket.remove(key) {
                if let Some(value) = callback(Some(&pair)) {
                    k_bucket.nodes.pop_front();
                    k_bucket.nodes.push_back((key.clone(), value));
                } else {
                    k_bucket.nodes.push_back(pair);
                }

                return;
            }

            if k_bucket.nodes.len() == self.const_k {
                if let Some(value) = callback(k_bucket.nodes.front()) {
                    k_bucket.nodes.pop_front();
                    k_bucket.nodes.push_back((key.clone(), value));
                } else {
                    let pair = k_bucket.nodes.pop_front().unwrap();
                    k_bucket.nodes.push_back(pair);
                }
            } else {
                let value = callback(None).expect("Expect key value");

                k_bucket.nodes.push_back((key.clone(), value));
            }
        }
    }

    /// Returns an iterator of up to `k` keys closest to `target`.
    pub fn closest_k(&self, _target: &Key) -> KBucketsTableIterator<'_, Key, Value> {
        todo!()
    }
}

pub struct KBucketsTableIterator<'a, Key, Value> {
    _buckets: &'a [KBucket<Key, Value>],
}
