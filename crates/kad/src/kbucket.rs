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

struct KBucket<Key, Value>(VecDeque<(Key, Value)>);

impl<Key, Value> Default for KBucket<Key, Value> {
    fn default() -> Self {
        Self(VecDeque::default())
    }
}

impl<Key, Value> KBucket<Key, Value> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn remove(&mut self, remove_key: &Key) -> Option<(Key, Value)>
    where
        Key: PartialEq,
    {
        let mut remove_index = None;

        for (index, (key, _)) in self.0.iter().enumerate() {
            if *key == *remove_key {
                remove_index = Some(index);
                break;
            }
        }

        if let Some(remove_index) = remove_index {
            self.0.remove(remove_index)
        } else {
            None
        }
    }
}

pub struct KBucketsTable<Key, Value>
where
    Key: KBucketKey,
{
    local_key: Key,
    const_k: usize,
    buckets: Vec<KBucket<Key, Value>>,
    k_index: GenericArray<Option<usize>, Key::Length>,
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
            k_index: Default::default(),
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
            assert!(k_index < self.k_index.len());

            let k_bucket = if let Some(index) = self.k_index[k_index] {
                self.buckets.get_mut(index).unwrap()
            } else {
                self.buckets.push(KBucket::default());
                self.k_index[k_index] = Some(self.buckets.len() - 1);
                self.buckets.last_mut().unwrap()
            };

            if let Some(pair) = k_bucket.remove(key) {
                if let Some(value) = callback(Some(&pair)) {
                    k_bucket.0.pop_front();
                    k_bucket.0.push_back((key.clone(), value));
                } else {
                    k_bucket.0.push_back(pair);
                }

                return;
            }

            if k_bucket.0.len() == self.const_k {
                if let Some(value) = callback(k_bucket.0.front()) {
                    k_bucket.0.pop_front();
                    k_bucket.0.push_back((key.clone(), value));
                } else {
                    let pair = k_bucket.0.pop_front().unwrap();
                    k_bucket.0.push_back(pair);
                }
            } else {
                let value = callback(None).expect("Expect key value");

                k_bucket.0.push_back((key.clone(), value));
            }
        }
    }

    /// Returns an iterator of up to `k` keys closest to `target`.
    pub fn closest_k(&self, target: &Key) -> KBucketsTableIter<'_, Key, Value> {
        let k_index = target
            .distance(&self.local_key)
            .k_index()
            .expect("Call closest_k with local key.") as usize;

        let bucket_len = if let Some(bucket) = self.bucket(k_index) {
            if bucket.len() == self.const_k {
                return KBucketsTableIter {
                    table: self,
                    k_offset: k_index,
                    k_end_offset: k_index,
                    k_inner_offset: 0,
                    k_end_inner_offset: self.const_k,
                };
            }

            bucket.len()
        } else {
            0
        };

        let mut k_offset = k_index;
        let mut k_end_offset = k_index;

        let mut k_inner_offset = 0;
        let mut k_end_inner_offset: usize = bucket_len;

        let mut nodes = bucket_len;

        while nodes < self.const_k {
            if k_offset > 0 {
                k_offset -= 1;
                if let Some(bucket) = self.bucket(k_offset) {
                    nodes += bucket.len();

                    if nodes >= self.const_k {
                        k_inner_offset = nodes - self.const_k;
                        // nodes = self.const_k;
                        break;
                    } else {
                        k_inner_offset = 0;
                    }
                }
            }

            if k_end_offset < self.k_index.len() {
                k_end_offset += 1;

                if let Some(bucket) = self.bucket(k_offset) {
                    nodes += bucket.len();
                    k_end_inner_offset = bucket.len();

                    if nodes >= self.const_k {
                        k_end_inner_offset -= nodes - self.const_k;
                        // nodes = self.const_k;
                        break;
                    }
                }
            } else {
                break;
            }
        }

        return KBucketsTableIter {
            table: self,
            k_offset,
            k_end_offset,
            k_inner_offset,
            k_end_inner_offset,
        };
    }

    fn bucket(&self, index: usize) -> Option<&KBucket<Key, Value>> {
        self.k_index[index].map(|index| &self.buckets[index])
    }
}

/// An immutable iterator over [`KBucketsTable`]
pub struct KBucketsTableIter<'a, Key, Value>
where
    Key: KBucketKey,
{
    table: &'a KBucketsTable<Key, Value>,
    k_offset: usize,
    k_inner_offset: usize,
    k_end_offset: usize,
    k_end_inner_offset: usize,
}

impl<'a, Key, Value> Iterator for KBucketsTableIter<'a, Key, Value>
where
    Key: KBucketKey,
{
    type Item = &'a (Key, Value);

    fn next(&mut self) -> Option<Self::Item> {
        if self.k_offset == self.k_end_offset && self.k_inner_offset == self.k_end_inner_offset {
            return None;
        }

        let k_bucket_offset = self.table.k_index[self.k_offset].expect("k-bucket not exists");

        let k_bucket = &self.table.buckets[k_bucket_offset];

        //  In the bucket, iterate in MRU order
        let item = &k_bucket.0[k_bucket.0.len() - self.k_inner_offset - 1];

        self.k_inner_offset += 1;

        if self.k_inner_offset == k_bucket.0.len() {
            self.k_inner_offset = 0;
            self.k_offset += 1;
        }

        Some(item)
    }
}

#[cfg(test)]
mod tests {}
