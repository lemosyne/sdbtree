use crate::error::Error;
use embedded_io::blocking::{Read, Write};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, mem};
use storage::Storage;

fn read_length_prefixed_bytes<S>(reader: &mut S::ReadHandle<'_>) -> Result<Vec<u8>, Error<S::Error>>
where
    S: Storage,
{
    let mut len_raw = [0; mem::size_of::<u64>()];
    reader.read_exact(&mut len_raw).map_err(|_| Error::Read)?;

    let len = u64::from_le_bytes(len_raw);
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error::Read)?;

    Ok(bytes)
}

fn write_length_prefixed_bytes<S>(
    writer: &mut S::WriteHandle<'_>,
    bytes: &[u8],
) -> Result<(), Error<S::Error>>
where
    S: Storage,
{
    writer
        .write_all(&(bytes.len() as u64).to_le_bytes())
        .map_err(|_| Error::Write)?;
    Ok(writer.write_all(bytes).map_err(|_| Error::Write)?)
}

pub enum Child<K, V> {
    Unloaded(u64),
    Loaded(Node<K, V>),
}

impl<K, V> Child<K, V> {
    pub fn as_option_owned(self) -> Option<Node<K, V>> {
        match self {
            Child::Unloaded(_) => None,
            Child::Loaded(node) => Some(node),
        }
    }

    pub fn as_option_mut(&mut self) -> Option<&mut Node<K, V>> {
        match *self {
            Child::Unloaded(_) => None,
            Child::Loaded(ref mut node) => Some(node),
        }
    }
}

pub(crate) struct Node<K, V> {
    pub(crate) id: u64,
    pub(crate) keys: Vec<K>,
    pub(crate) vals: Vec<V>,
    pub(crate) children: Vec<Child<K, V>>,
}

impl<K, V> Node<K, V> {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            keys: Vec::new(),
            vals: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn is_full(&self, degree: usize) -> bool {
        self.keys.len() == 2 * degree - 1
    }

    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    pub fn load<S>(id: u64, storage: &mut S) -> Result<Self, Error<S::Error>>
    where
        for<'de> K: Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        // Acquire a read handle.
        let mut reader = storage.read_handle(&id)?;

        // Read the fields, each of which is serialized as a length-prefixed array of bytes.
        let keys_raw = read_length_prefixed_bytes::<S>(&mut reader)?;
        let vals_raw = read_length_prefixed_bytes::<S>(&mut reader)?;
        let children_raw = read_length_prefixed_bytes::<S>(&mut reader)?;

        // The array of children will be serialized as a vector of IDs.
        let children: Vec<u64> =
            bincode::deserialize(&children_raw).map_err(|_| Error::Deserialization)?;

        Ok(Self {
            id,
            keys: bincode::deserialize(&keys_raw).map_err(|_| Error::Deserialization)?,
            vals: bincode::deserialize(&vals_raw).map_err(|_| Error::Deserialization)?,
            children: children.iter().map(|id| Child::Unloaded(*id)).collect(),
        })
    }

    pub fn persist<S>(&self, storage: &mut S) -> Result<u64, Error<S::Error>>
    where
        K: Serialize,
        V: Serialize,
        S: Storage<Id = u64>,
    {
        // Recursively persist children.
        for child in &self.children {
            match child {
                Child::Loaded(node) => {
                    node.persist(storage)?;
                }
                _ => {}
            }
        }

        // Serialize the keys and values.
        let keys_raw = bincode::serialize(&self.keys).map_err(|_| Error::Serialization)?;
        let vals_raw = bincode::serialize(&self.vals).map_err(|_| Error::Serialization)?;

        // Serialize the children IDs.
        let children_raw = bincode::serialize(
            &self
                .children
                .iter()
                .map(|child| match child {
                    Child::Loaded(node) => node.id,
                    Child::Unloaded(id) => *id,
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::Serialization)?;

        // Acquire a write handle.
        let mut writer = storage.write_handle(&self.id)?;

        // Write each of the fields as a length-prefixed array of bytes.
        write_length_prefixed_bytes::<S>(&mut writer, &keys_raw)?;
        write_length_prefixed_bytes::<S>(&mut writer, &vals_raw)?;
        write_length_prefixed_bytes::<S>(&mut writer, &children_raw)?;

        Ok(self.id)
    }

    fn find_index(&self, k: &K) -> usize
    where
        K: Ord,
    {
        let mut size = self.len();
        let mut left = 0;
        let mut right = size;

        while left < right {
            let mid = left + size / 2;

            match self.keys[mid].cmp(k) {
                Ordering::Equal => return mid,
                Ordering::Less => left = mid + 1,
                Ordering::Greater => right = mid,
            }

            size = right - left;
        }

        left
    }

    pub(crate) fn access_child<S>(
        &mut self,
        idx: usize,
        storage: &mut S,
    ) -> Result<&mut Node<K, V>, Error<S::Error>>
    where
        for<'de> K: Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        match self.children[idx] {
            Child::Unloaded(id) => {
                self.children[idx] = Child::Loaded(Node::load(id, storage)?);
            }
            _ => {}
        }
        Ok(self.children[idx].as_option_mut().unwrap())
    }

    pub fn get<S>(
        &mut self,
        k: &K,
        storage: &mut S,
    ) -> Result<Option<(usize, &Node<K, V>)>, Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        let mut node = self;
        loop {
            let idx = node.find_index(k);
            if idx < node.len() && node.keys[idx] == *k {
                return Ok(Some((idx, node)));
            } else if node.is_leaf() {
                return Ok(None);
            } else {
                node = node.access_child(idx, storage)?;
            }
        }
    }

    pub fn get_mut<S>(
        &mut self,
        k: &K,
        storage: &mut S,
    ) -> Result<Option<(usize, &mut Node<K, V>)>, Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        let mut node = self;
        loop {
            let idx = node.find_index(k);
            if idx < node.len() && node.keys[idx] == *k {
                return Ok(Some((idx, node)));
            } else if node.is_leaf() {
                return Ok(None);
            } else {
                node = node.access_child(idx, storage)?;
            }
        }
    }

    pub fn split_child<S>(
        &mut self,
        idx: usize,
        degree: usize,
        storage: &mut S,
    ) -> Result<(), Error<S::Error>>
    where
        S: Storage<Id = u64>,
    {
        assert!(!self.is_full(degree));
        // assert!(self.children[idx].is_full(degree));

        let left = self.children[idx].as_option_mut().unwrap();
        let mut right = Self::new(storage.alloc_id()?);

        // Move the largest keys and values from the left to the right.
        right.vals.extend(left.vals.drain(degree..));
        right.keys.extend(left.keys.drain(degree..));

        // Take the median (separator) key and value from the left.
        let key = left.keys.pop().expect("couldn't pop median key");
        let val = left.vals.pop().expect("couldn't pop median value");

        // Take the left's largest children as well if not a leaf.
        if !left.is_leaf() {
            right.children.extend(left.children.drain(degree..));
        }

        // Insert new key, value, and right child into the root.
        self.keys.insert(idx, key);
        self.vals.insert(idx, val);
        self.children.insert(idx + 1, Child::Loaded(right));

        Ok(())
    }

    pub fn insert_nonfull<S>(
        &mut self,
        k: K,
        mut v: V,
        degree: usize,
        storage: &mut S,
    ) -> Result<Option<V>, Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        assert!(!self.is_full(degree));

        let mut node = self;
        loop {
            // Find index to insert key into or of the child to recurse down.
            let mut idx = node.find_index(&k);

            if node.is_leaf() {
                // Insert key and value into non-full node.
                if idx < node.len() && k == node.keys[idx] {
                    // The key already exists, so swap in the value.
                    mem::swap(&mut node.vals[idx], &mut v);
                    return Ok(Some(v));
                } else {
                    // The key doesn't exist yet.
                    node.keys.insert(idx, k);
                    node.vals.insert(idx, v);
                    return Ok(None);
                }
            } else {
                if node.access_child(idx, storage)?.is_full(degree) {
                    // Split the child and determine which child to recurse down.
                    node.split_child(idx, degree, storage)?;
                    if node.keys[idx] < k {
                        idx += 1;
                    }
                }
                node = node.access_child(idx, storage)?;
            }
        }
    }

    fn min_key<S>(&mut self, storage: &mut S) -> Result<&K, Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        let mut node = self;

        while !node.is_leaf() && !node.access_child(0, storage)?.is_empty() {
            node = node.children.first_mut().unwrap().as_option_mut().unwrap();
        }

        Ok(node.keys.first().unwrap())
    }

    fn max_key<S>(&mut self, storage: &mut S) -> Result<&K, Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        let mut node = self;

        while !node.is_leaf()
            && !node
                .access_child(node.children.len() - 1, storage)?
                .is_empty()
        {
            node = node.children.last_mut().unwrap().as_option_mut().unwrap();
        }

        Ok(node.keys.last().unwrap())
    }

    pub fn remove<S>(
        &mut self,
        k: &K,
        degree: usize,
        storage: &mut S,
    ) -> Result<Option<(K, V)>, Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        let mut idx = self.find_index(k);

        // Case 1: Key found in node and node is a leaf.
        if idx < self.len() && self.keys[idx] == *k && self.is_leaf() {
            let key = self.keys.remove(idx);
            let val = self.vals.remove(idx);
            return Ok(Some((key, val)));
        }

        // Case 2: Key found in node and node is an internal node.
        if idx < self.len() && self.keys[idx] == *k && !self.is_leaf() {
            if self.access_child(idx, storage)?.len() >= degree {
                // Case 2a: Child node that precedes k has at least t keys.
                let pred = &mut self.children[idx].as_option_mut().unwrap();

                // Replace key with the predecessor key and recursively delete it.
                // Safety: we won't ever use the reference past this point.
                let pred_key = pred.max_key(storage)? as *const _;
                let (mut pred_key, mut pred_val) = pred
                    .remove(unsafe { &*pred_key }, degree, storage)?
                    .unwrap();

                // The actual replacement.
                mem::swap(&mut self.keys[idx], &mut pred_key);
                mem::swap(&mut self.vals[idx], &mut pred_val);

                return Ok(Some((pred_key, pred_val)));
            } else if self.access_child(idx + 1, storage)?.len() >= degree {
                // Case 2b: Child node that succeeds k has at least t keys.
                let succ = &mut self.children[idx + 1].as_option_mut().unwrap();

                // Replace key with the successor key and recursively delete it.
                // Safety: we don't ever use the reference past this point.
                let succ_key = succ.min_key(storage)? as *const _;
                let (mut succ_key, mut succ_val) = succ
                    .remove(unsafe { &*succ_key }, degree, storage)?
                    .unwrap();

                // The actual replacement.
                mem::swap(&mut self.keys[idx], &mut succ_key);
                mem::swap(&mut self.vals[idx], &mut succ_val);

                return Ok(Some((succ_key, succ_val)));
            } else {
                // Case 2c: Successor and predecessor only have t - 1 keys.
                let key = self.keys.remove(idx);
                let val = self.vals.remove(idx);

                let mut succ = self.children.remove(idx + 1).as_option_owned().unwrap();
                let pred = &mut self.children[idx].as_option_mut().unwrap();

                // Merge keys, values, and children into predecessor.
                pred.keys.push(key);
                pred.vals.push(val);
                pred.keys.append(&mut succ.keys);
                pred.vals.append(&mut succ.vals);
                pred.children.append(&mut succ.children);
                assert!(pred.is_full(degree));

                // Deallocate the successor.
                // This is the only case in which a node completely disappears.
                storage.dealloc_id(succ.id)?;

                return pred.remove(k, degree, storage);
            }
        }

        // If on a leaf, then no appropriate subtree contains the key.
        if self.is_leaf() {
            return Ok(None);
        }

        // Case 3: Key not found in internal node.
        if self.access_child(idx, storage)?.len() + 1 == degree {
            if idx > 0 && self.access_child(idx - 1, storage)?.len() >= degree {
                // Case 3a: Immediate left sibling has at least t keys.

                // Move key and value from parent down to child.
                {
                    let parent_key = self.keys.remove(idx - 1);
                    let parent_val = self.vals.remove(idx - 1);

                    let mid = self.access_child(idx, storage)?;
                    mid.keys.insert(0, parent_key);
                    mid.vals.insert(0, parent_val);
                }

                // Move rightmost key and value in left sibling to parent.
                {
                    let left = self.access_child(idx - 1, storage)?;
                    let left_key = left.keys.pop().unwrap();
                    let left_val = left.vals.pop().unwrap();

                    self.keys.insert(idx - 1, left_key);
                    self.vals.insert(idx - 1, left_val);
                }

                // Move rightmost child in left sibling to child.
                let left = self.access_child(idx - 1, storage)?;
                if !left.is_leaf() {
                    let child = left.children.pop().unwrap();
                    self.access_child(idx, storage)?.children.insert(0, child);
                }
            } else if idx + 1 < self.children.len()
                && self.access_child(idx + 1, storage)?.len() >= degree
            {
                // Case 3a: Immediate right sibling has at least t keys.

                // Move key and value from parent down to child.
                {
                    let parent_key = self.keys.remove(idx);
                    let parent_val = self.vals.remove(idx);

                    let mid = self.access_child(idx, storage)?;
                    mid.keys.push(parent_key);
                    mid.vals.push(parent_val);
                }

                // Move leftmost key and value in right sibling to parent.
                {
                    let right = self.access_child(idx + 1, storage)?;
                    let right_key = right.keys.remove(0);
                    let right_val = right.vals.remove(0);

                    self.keys.insert(idx, right_key);
                    self.vals.insert(idx, right_val);
                }

                // Move leftmost child in right sibling to child.
                let right = self.access_child(idx + 1, storage)?;
                if !right.is_leaf() {
                    let child = right.children.remove(0);
                    self.access_child(idx, storage)?.children.push(child);
                }
            } else if idx > 0 {
                // Case 3b: Merge into left sibling.

                // Move key and value from parent down to left sibling (merged node).
                {
                    let parent_key = self.keys.remove(idx - 1);
                    let parent_val = self.vals.remove(idx - 1);

                    let mid = self.access_child(idx, storage)?;
                    let mut mid_keys = mid.keys.drain(..).collect();
                    let mut mid_vals = mid.vals.drain(..).collect();
                    let mut mid_children = mid.children.drain(..).collect();

                    let left = self.access_child(idx - 1, storage)?;
                    left.keys.push(parent_key);
                    left.vals.push(parent_val);

                    // Merge all keys, values, and children from child into left sibling.
                    left.keys.append(&mut mid_keys);
                    left.vals.append(&mut mid_vals);
                    left.children.append(&mut mid_children);
                }

                // Remove the merged child.
                self.children.remove(idx);

                // The only case where you fix the child to recurse down.
                idx -= 1;
            } else if idx + 1 < self.children.len() {
                // Case 3b: Merge into right sibling.

                // Move key and value from parent down to right sibling (merged node).
                {
                    let parent_key = self.keys.remove(idx);
                    let parent_val = self.vals.remove(idx);

                    let right = self.access_child(idx + 1, storage)?;
                    let mut right_keys = right.keys.drain(..).collect();
                    let mut right_vals = right.vals.drain(..).collect();
                    let mut right_children = right.children.drain(..).collect();

                    let mid = self.access_child(idx, storage)?;
                    mid.keys.push(parent_key);
                    mid.vals.push(parent_val);
                    mid.keys.append(&mut right_keys);
                    mid.vals.append(&mut right_vals);
                    mid.children.append(&mut right_children);
                }

                // Remove the right sibling.
                self.children.remove(idx + 1);
            }
        }

        self.access_child(idx, storage)?.remove(k, degree, storage)
    }

    pub fn clear<S>(&mut self, storage: &mut S) -> Result<(), Error<S::Error>>
    where
        for<'de> K: Ord + Deserialize<'de>,
        for<'de> V: Deserialize<'de>,
        S: Storage<Id = u64>,
    {
        for idx in 0..self.children.len() {
            self.access_child(idx, storage)?.clear(storage)?;
        }

        self.keys.clear();
        self.vals.clear();
        self.children.clear();

        Ok(())
    }

    // impl<K, V> Debug for Node<K, V>
    // where
    // K: Debug,
    // V: Debug,
    // {
    // fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    //     fn fmt_tree<K, V>(
    //         f: &mut Formatter,
    //         node: &Node<K, V>,
    //         prefix: String,
    //         last: bool,
    //         root: bool,
    //     ) -> fmt::Result
    //     where
    //         K: Debug,
    //         V: Debug,
    //     {
    //         if !root {
    //             write!(
    //                 f,
    //                 "{}{}",
    //                 prefix,
    //                 if last {
    //                     "└─── "
    //                 } else {
    //                     "├─── "
    //                 }
    //             )?;
    //         }

    //         writeln!(f, "{:?}", node.keys)?;
    //         // writeln!(
    //         //     f,
    //         //     "{:?}",
    //         //     node.keys.iter().zip(node.vals.iter()).collect::<Vec<_>>()
    //         // )?;

    //         if !node.is_leaf() {
    //             for (i, c) in node.children.iter().enumerate() {
    //                 let next_prefix = if root {
    //                     format!("{prefix}")
    //                 } else if last {
    //                     format!("{prefix}     ")
    //                 } else {
    //                     format!("{prefix}│    ")
    //                 };

    //                 fmt_tree(f, c, next_prefix, i + 1 == node.children.len(), false)?;
    //             }
    //         }

    //         Ok(())
    //     }

    //     fmt_tree(f, self, String::new(), true, true)
    // }
}
