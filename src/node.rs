use crate::{error::Error, utils, BlockId, Key, NodeId};
use crypter::Crypter;
use rand::{CryptoRng, RngCore};
use std::{cmp::Ordering, collections::HashSet, mem};
use storage::Storage;

pub enum Child<const KEY_SZ: usize> {
    Unloaded(u64),
    Loaded(Node<KEY_SZ>),
}

impl<const KEY_SZ: usize> Child<KEY_SZ> {
    pub fn as_option_owned(self) -> Option<Node<KEY_SZ>> {
        match self {
            Child::Unloaded(_) => None,
            Child::Loaded(node) => Some(node),
        }
    }

    pub fn as_option_mut(&mut self) -> Option<&mut Node<KEY_SZ>> {
        match *self {
            Child::Unloaded(_) => None,
            Child::Loaded(ref mut node) => Some(node),
        }
    }
}

pub(crate) struct Node<const KEY_SZ: usize> {
    pub(crate) id: NodeId,
    pub(crate) keys: Vec<BlockId>,
    pub(crate) vals: Vec<Key<KEY_SZ>>,
    pub(crate) children: Vec<Child<KEY_SZ>>,
    pub(crate) children_keys: Vec<Key<KEY_SZ>>,
}

impl<const KEY_SZ: usize> Node<KEY_SZ> {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            keys: Vec::new(),
            vals: Vec::new(),
            children: Vec::new(),
            children_keys: Vec::new(),
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

    pub fn load<C, S>(id: u64, key: Key<KEY_SZ>, storage: &mut S) -> Result<Self, Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        // Acquire a read handle.
        let mut reader = storage.read_handle(&id)?;

        // Read the fields, each of which is serialized as a length-prefixed array of bytes.
        let keys_raw = utils::read_length_prefixed_bytes::<C, S, KEY_SZ>(&mut reader, key)?;
        let vals_raw = utils::read_length_prefixed_bytes::<C, S, KEY_SZ>(&mut reader, key)?;
        let children_raw = utils::read_length_prefixed_bytes::<C, S, KEY_SZ>(&mut reader, key)?;
        let children_keys_raw =
            utils::read_length_prefixed_bytes::<C, S, KEY_SZ>(&mut reader, key)?;

        Ok(Self {
            id,
            keys: utils::deserialize_ids(&keys_raw),
            vals: utils::deserialize_keys(&vals_raw),
            children: utils::deserialize_ids(&children_raw)
                .into_iter()
                .map(|id| Child::Unloaded(id))
                .collect(),
            children_keys: utils::deserialize_keys(&children_keys_raw),
        })
    }

    pub fn persist<C, S>(&self, key: Key<KEY_SZ>, storage: &mut S) -> Result<u64, Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        // Recursively persist children.
        for (i, child) in self.children.iter().enumerate() {
            match child {
                Child::Loaded(node) => {
                    node.persist::<C, S>(self.children_keys[i], storage)?;
                }
                _ => {}
            }
        }

        // Serialize the keys and values.
        // This should really be done in one shot.
        let keys_raw = utils::serialize_ids(&self.keys);
        let vals_raw = utils::serialize_keys(&self.vals);
        let children_keys_raw = utils::serialize_keys(&self.children_keys);

        // Serialize the children IDs.
        let children_raw = utils::serialize_ids(
            &self
                .children
                .iter()
                .map(|child| match child {
                    Child::Loaded(node) => node.id,
                    Child::Unloaded(id) => *id,
                })
                .collect::<Vec<_>>(),
        );

        // Acquire a write handle.
        let mut writer = storage.write_handle(&self.id)?;

        // Write each of the fields as a length-prefixed array of bytes.
        utils::write_length_prefixed_bytes::<C, S, KEY_SZ>(&mut writer, &keys_raw, key)?;
        utils::write_length_prefixed_bytes::<C, S, KEY_SZ>(&mut writer, &vals_raw, key)?;
        utils::write_length_prefixed_bytes::<C, S, KEY_SZ>(&mut writer, &children_raw, key)?;
        utils::write_length_prefixed_bytes::<C, S, KEY_SZ>(&mut writer, &children_keys_raw, key)?;

        Ok(self.id)
    }

    fn find_index(&self, k: &BlockId) -> usize {
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

    fn access_child<C, S>(
        &mut self,
        idx: usize,
        storage: &mut S,
    ) -> Result<&mut Node<KEY_SZ>, Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        match self.children[idx] {
            Child::Unloaded(id) => {
                self.children[idx] =
                    Child::Loaded(Node::load::<C, S>(id, self.children_keys[idx], storage)?);
            }
            _ => {}
        }
        Ok(self.children[idx].as_option_mut().unwrap())
    }

    pub fn get<C, S>(
        &mut self,
        k: &BlockId,
        storage: &mut S,
    ) -> Result<Option<(usize, &Node<KEY_SZ>)>, Error<S::Error>>
    where
        C: Crypter,
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
                node = node.access_child::<C, S>(idx, storage)?;
            }
        }
    }

    pub fn get_mut<C, S>(
        &mut self,
        k: &BlockId,
        storage: &mut S,
    ) -> Result<Option<(usize, &mut Node<KEY_SZ>)>, Error<S::Error>>
    where
        C: Crypter,
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
                node = node.access_child::<C, S>(idx, storage)?;
            }
        }
    }

    pub fn split_child<R, S>(
        &mut self,
        idx: usize,
        degree: usize,
        storage: &mut S,
        for_update: bool,
        rng: &mut R,
        updated: &mut HashSet<NodeId>,
    ) -> Result<(), Error<S::Error>>
    where
        R: RngCore + CryptoRng,
        S: Storage<Id = u64>,
    {
        assert!(!self.is_full(degree));
        // assert!(self.children[idx].is_full(degree));

        let left = self.children[idx].as_option_mut().unwrap();
        let mut right = Self::new(storage.alloc_id()?);
        let right_key = utils::generate_key(rng);

        // Move the largest keys and values from the left to the right.
        right.vals.extend(left.vals.drain(degree..));
        right.keys.extend(left.keys.drain(degree..));

        // Take the median (separator) key and value from the left.
        let key = left.keys.pop().expect("couldn't pop median key");
        let val = left.vals.pop().expect("couldn't pop median value");

        // Take the left's largest children as well if not a leaf.
        if !left.is_leaf() {
            right.children.extend(left.children.drain(degree..));
            right
                .children_keys
                .extend(left.children_keys.drain(degree..));
        }

        // Mark all the nodes we touched.
        if for_update {
            updated.insert(self.id);
            updated.insert(left.id);
            updated.insert(right.id);
        }

        // Insert new key, value, right child, and its key into the root.
        self.keys.insert(idx, key);
        self.vals.insert(idx, val);
        self.children.insert(idx + 1, Child::Loaded(right));
        self.children_keys.insert(idx + 1, right_key);

        Ok(())
    }

    pub fn insert_nonfull<C, R, S>(
        &mut self,
        k: BlockId,
        mut v: Key<KEY_SZ>,
        degree: usize,
        storage: &mut S,
        for_update: bool,
        rng: &mut R,
        updated: &mut HashSet<NodeId>,
    ) -> Result<Option<Key<KEY_SZ>>, Error<S::Error>>
    where
        C: Crypter,
        R: RngCore + CryptoRng,
        S: Storage<Id = u64>,
    {
        assert!(!self.is_full(degree));

        let mut node = self;
        loop {
            // Find index to insert key into or of the child to recurse down.
            let mut idx = node.find_index(&k);

            // This node may not actually have any changes, but is along the path to the node
            // that will be updated, so it must be added.
            if for_update {
                updated.insert(node.id);
            }

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
                if node.access_child::<C, S>(idx, storage)?.is_full(degree) {
                    // Split the child and determine which child to recurse down.
                    node.split_child(idx, degree, storage, for_update, rng, updated)?;
                    if node.keys[idx] < k {
                        idx += 1;
                    }
                }
                node = node.access_child::<C, S>(idx, storage)?;
            }
        }
    }

    fn min_key<C, S>(&mut self, storage: &mut S) -> Result<&BlockId, Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        let mut node = self;

        while !node.is_leaf() && !node.access_child::<C, S>(0, storage)?.is_empty() {
            node = node.children.first_mut().unwrap().as_option_mut().unwrap();
        }

        Ok(node.keys.first().unwrap())
    }

    fn max_key<C, S>(&mut self, storage: &mut S) -> Result<&BlockId, Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        let mut node = self;

        while !node.is_leaf()
            && !node
                .access_child::<C, S>(node.children.len() - 1, storage)?
                .is_empty()
        {
            node = node.children.last_mut().unwrap().as_option_mut().unwrap();
        }

        Ok(node.keys.last().unwrap())
    }

    // TODO: This could be implemented better with less redundant inserts to updated.
    pub fn remove<C, S>(
        &mut self,
        k: &BlockId,
        degree: usize,
        storage: &mut S,
        updated: &mut HashSet<NodeId>,
    ) -> Result<Option<(BlockId, Key<KEY_SZ>)>, Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        // Update the nodes that were modified.
        updated.insert(self.id);

        let mut idx = self.find_index(k);

        // Case 1: Key found in node and node is a leaf.
        if idx < self.len() && self.keys[idx] == *k && self.is_leaf() {
            let key = self.keys.remove(idx);
            let val = self.vals.remove(idx);
            return Ok(Some((key, val)));
        }

        // Case 2: Key found in node and node is an internal node.
        if idx < self.len() && self.keys[idx] == *k && !self.is_leaf() {
            if self.access_child::<C, S>(idx, storage)?.len() >= degree {
                // Case 2a: Child node that precedes k has at least t keys.
                let pred = &mut self.children[idx].as_option_mut().unwrap();

                // Replace key with the predecessor key and recursively delete it.
                // Safety: we won't ever use the reference past this point.
                let pred_key = pred.max_key::<C, S>(storage)? as *const _;
                let (mut pred_key, mut pred_val) = pred
                    .remove::<C, S>(unsafe { &*pred_key }, degree, storage, updated)?
                    .unwrap();

                // The actual replacement.
                mem::swap(&mut self.keys[idx], &mut pred_key);
                mem::swap(&mut self.vals[idx], &mut pred_val);

                // Update the nodes that were modified.
                updated.insert(pred.id);

                return Ok(Some((pred_key, pred_val)));
            } else if self.access_child::<C, S>(idx + 1, storage)?.len() >= degree {
                // Case 2b: Child node that succeeds k has at least t keys.
                let succ = &mut self.children[idx + 1].as_option_mut().unwrap();

                // Replace key with the successor key and recursively delete it.
                // Safety: we don't ever use the reference past this point.
                let succ_key = succ.min_key::<C, S>(storage)? as *const _;
                let (mut succ_key, mut succ_val) = succ
                    .remove::<C, S>(unsafe { &*succ_key }, degree, storage, updated)?
                    .unwrap();

                // The actual replacement.
                mem::swap(&mut self.keys[idx], &mut succ_key);
                mem::swap(&mut self.vals[idx], &mut succ_val);

                // Update the nodes that were modified.
                updated.insert(succ.id);

                return Ok(Some((succ_key, succ_val)));
            } else {
                // Case 2c: Successor and predecessor only have t - 1 keys.
                let key = self.keys.remove(idx);
                let val = self.vals.remove(idx);

                let mut succ = self.children.remove(idx + 1).as_option_owned().unwrap();
                let _succ_key = self.children_keys.remove(idx + 1);

                let pred = &mut self.children[idx].as_option_mut().unwrap();

                // Merge keys, values, and children into predecessor.
                pred.keys.push(key);
                pred.vals.push(val);
                pred.keys.append(&mut succ.keys);
                pred.vals.append(&mut succ.vals);
                pred.children.append(&mut succ.children);
                pred.children_keys.append(&mut succ.children_keys);
                assert!(pred.is_full(degree));

                // Deallocate the successor.
                // This is the only case in which a node completely disappears.
                storage.dealloc_id(succ.id)?;

                // Update the nodes that were modified.
                // Since the successor doesn't exist anymore, we can remove it.
                updated.remove(&succ.id);
                updated.insert(pred.id);

                return pred.remove::<C, S>(k, degree, storage, updated);
            }
        }

        // If on a leaf, then no appropriate subtree contains the key.
        if self.is_leaf() {
            return Ok(None);
        }

        // Case 3: Key not found in internal node.
        if self.access_child::<C, S>(idx, storage)?.len() + 1 == degree {
            if idx > 0 && self.access_child::<C, S>(idx - 1, storage)?.len() >= degree {
                // Case 3a: Immediate left sibling has at least t keys.

                // Move key and value from parent down to child.
                {
                    let parent_key = self.keys.remove(idx - 1);
                    let parent_val = self.vals.remove(idx - 1);

                    let mid = self.access_child::<C, S>(idx, storage)?;
                    mid.keys.insert(0, parent_key);
                    mid.vals.insert(0, parent_val);

                    // Update the nodes that were modified.
                    updated.insert(mid.id);
                }

                // Move rightmost key and value in left sibling to parent.
                {
                    let left = self.access_child::<C, S>(idx - 1, storage)?;
                    let left_key = left.keys.pop().unwrap();
                    let left_val = left.vals.pop().unwrap();

                    // Update the nodes that were modified.
                    updated.insert(left.id);

                    self.keys.insert(idx - 1, left_key);
                    self.vals.insert(idx - 1, left_val);
                }

                // Move rightmost child in left sibling to child.
                let left = self.access_child::<C, S>(idx - 1, storage)?;
                if !left.is_leaf() {
                    let child = left.children.pop().unwrap();
                    let child_key = left.children_keys.pop().unwrap();

                    let mid = self.access_child::<C, S>(idx, storage)?;
                    mid.children.insert(0, child);
                    mid.children_keys.insert(0, child_key);
                }
            } else if idx + 1 < self.children.len()
                && self.access_child::<C, S>(idx + 1, storage)?.len() >= degree
            {
                // Case 3a: Immediate right sibling has at least t keys.

                // Move key and value from parent down to child.
                {
                    let parent_key = self.keys.remove(idx);
                    let parent_val = self.vals.remove(idx);

                    let mid = self.access_child::<C, S>(idx, storage)?;
                    mid.keys.push(parent_key);
                    mid.vals.push(parent_val);

                    // Update the nodes that were modified.
                    updated.insert(mid.id);
                }

                // Move leftmost key and value in right sibling to parent.
                {
                    let right = self.access_child::<C, S>(idx + 1, storage)?;
                    let right_key = right.keys.remove(0);
                    let right_val = right.vals.remove(0);

                    // Update the nodes that were modified.
                    updated.insert(right.id);

                    self.keys.insert(idx, right_key);
                    self.vals.insert(idx, right_val);
                }

                // Move leftmost child in right sibling to child.
                let right = self.access_child::<C, S>(idx + 1, storage)?;
                if !right.is_leaf() {
                    let child = right.children.remove(0);
                    let child_key = right.children_keys.remove(0);

                    let mid = self.access_child::<C, S>(idx, storage)?;
                    mid.children.push(child);
                    mid.children_keys.push(child_key);
                }
            } else if idx > 0 {
                // Case 3b: Merge into left sibling.

                // Move key and value from parent down to left sibling (merged node).
                {
                    let parent_key = self.keys.remove(idx - 1);
                    let parent_val = self.vals.remove(idx - 1);

                    let mid = self.access_child::<C, S>(idx, storage)?;
                    let mut mid_keys = mid.keys.drain(..).collect();
                    let mut mid_vals = mid.vals.drain(..).collect();
                    let mut mid_children = mid.children.drain(..).collect();
                    let mut mid_children_keys = mid.children_keys.drain(..).collect();

                    // Update the nodes that were modified.
                    updated.insert(mid.id);

                    let left = self.access_child::<C, S>(idx - 1, storage)?;
                    left.keys.push(parent_key);
                    left.vals.push(parent_val);

                    // Merge all keys, values, and children from child into left sibling.
                    left.keys.append(&mut mid_keys);
                    left.vals.append(&mut mid_vals);
                    left.children.append(&mut mid_children);
                    left.children_keys.append(&mut mid_children_keys);

                    // Update the nodes that were modified.
                    updated.insert(left.id);
                }

                // Remove the merged child.
                self.children.remove(idx);
                self.children_keys.remove(idx);

                // The only case where you fix the child to recurse down.
                idx -= 1;
            } else if idx + 1 < self.children.len() {
                // Case 3b: Merge into right sibling.

                // Move key and value from parent down to right sibling (merged node).
                {
                    let parent_key = self.keys.remove(idx);
                    let parent_val = self.vals.remove(idx);

                    let right = self.access_child::<C, S>(idx + 1, storage)?;
                    let mut right_keys = right.keys.drain(..).collect();
                    let mut right_vals = right.vals.drain(..).collect();
                    let mut right_children = right.children.drain(..).collect();
                    let mut right_children_keys = right.children_keys.drain(..).collect();

                    // Update the nodes that were modified.
                    updated.insert(right.id);

                    let mid = self.access_child::<C, S>(idx, storage)?;
                    mid.keys.push(parent_key);
                    mid.vals.push(parent_val);
                    mid.keys.append(&mut right_keys);
                    mid.vals.append(&mut right_vals);
                    mid.children.append(&mut right_children);
                    mid.children_keys.append(&mut right_children_keys);

                    // Update the nodes that were modified.
                    updated.insert(mid.id);
                }

                // Remove the right sibling.
                self.children.remove(idx + 1);
                self.children_keys.remove(idx + 1);
            }
        }

        self.access_child::<C, S>(idx, storage)?
            .remove::<C, S>(k, degree, storage, updated)
    }

    pub fn clear<C, S>(&mut self, storage: &mut S) -> Result<(), Error<S::Error>>
    where
        C: Crypter,
        S: Storage<Id = u64>,
    {
        for idx in 0..self.children.len() {
            self.access_child::<C, S>(idx, storage)?
                .clear::<C, S>(storage)?;
        }

        self.keys.clear();
        self.vals.clear();
        self.children.clear();
        self.children_keys.clear();

        Ok(())
    }

    pub fn commit<C, R, S>(
        &mut self,
        storage: &mut S,
        rng: &mut R,
        updated: &HashSet<NodeId>,
    ) -> Result<(), Error<S::Error>>
    where
        C: Crypter,
        R: RngCore + CryptoRng,
        S: Storage<Id = u64>,
    {
        // Update the keys for children that were updated.
        for idx in self
            .children
            .iter()
            .enumerate()
            .map(|(i, child)| match child {
                Child::Loaded(node) => (i, node.id),
                Child::Unloaded(id) => (i, *id),
            })
            .filter_map(|(idx, id)| updated.contains(&id).then_some(idx))
        {
            self.children_keys[idx] = utils::generate_key(rng);
        }

        // Only recurse down loaded nodes. If nodes were updated, they must have been brought in.
        for child in self.children.iter_mut() {
            match child {
                Child::Loaded(node) => node.commit::<C, R, S>(storage, rng, updated)?,
                _ => {}
            }
        }

        Ok(())
    }
}
