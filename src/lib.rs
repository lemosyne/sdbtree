pub mod error;
pub mod node;
#[cfg(test)]
mod test;
mod utils;

pub use storage; // For re-export

use crypter::{aes::Aes256Ctr, Crypter};
use embedded_io::{blocking::Seek, SeekFrom};
use error::Error;
use kms::KeyManagementScheme;
use node::{Child, Node};
use rand::{rngs::ThreadRng, CryptoRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    mem,
};
use storage::{dir::DirectoryStorage, Storage};

const DEFAULT_DEGREE: usize = 2;
const AES256CTR_KEY_SZ: usize = 32;

pub(crate) type Key<const N: usize> = [u8; N];
pub(crate) type BlockId = u64;
pub(crate) type NodeId = u64;

pub struct BKeyTree<
    R = ThreadRng,
    S = DirectoryStorage,
    C = Aes256Ctr,
    const KEY_SZ: usize = AES256CTR_KEY_SZ,
> {
    len: usize,
    degree: usize,
    updated: HashSet<NodeId>,
    updated_blocks: HashSet<BlockId>,
    in_flight_blocks: HashMap<BlockId, Key<KEY_SZ>>,
    root: Node<KEY_SZ>,
    meta_id: u64,
    storage: S,
    rng: R,
    cached_keys: HashMap<BlockId, Key<KEY_SZ>>,
    pd: PhantomData<C>,
}

struct BKeyTreeMeta<const KEY_SZ: usize = AES256CTR_KEY_SZ> {
    meta_id: u64,
    len: usize,
    degree: usize,
    updated: HashSet<NodeId>,
    updated_blocks: HashSet<BlockId>,
    in_flight_blocks: HashMap<BlockId, Key<KEY_SZ>>,
}

impl BKeyTree<ThreadRng, DirectoryStorage, Aes256Ctr, AES256CTR_KEY_SZ> {
    pub fn new(path: impl AsRef<str>) -> Result<Self, Error> {
        Self::with_degree(path, DEFAULT_DEGREE)
    }

    pub fn reload(
        root_id: u64,
        path: impl AsRef<str>,
        key: Key<AES256CTR_KEY_SZ>,
    ) -> Result<Self, Error> {
        Self::reload_with_storage(
            root_id,
            DirectoryStorage::new(path.as_ref()).map_err(|_| Error::Storage)?,
            key,
        )
    }

    pub fn with_degree(path: impl AsRef<str>, degree: usize) -> Result<Self, Error> {
        Self::with_storage_and_degree(
            DirectoryStorage::new(path.as_ref()).map_err(|_| Error::Storage)?,
            degree,
        )
    }
}

impl<R, S, C, const KEY_SZ: usize> BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn with_storage(storage: S) -> Result<Self, Error> {
        Self::with_storage_and_degree(storage, DEFAULT_DEGREE)
    }

    pub fn with_storage_and_degree(mut storage: S, degree: usize) -> Result<Self, Error> {
        Ok(Self {
            len: 0,
            degree,
            updated: HashSet::new(),
            updated_blocks: HashSet::new(),
            in_flight_blocks: HashMap::new(),
            root: Node::new(storage.alloc_id().map_err(|_| Error::Storage)?),
            meta_id: storage.alloc_id().map_err(|_| Error::Storage)?,
            storage,
            rng: R::default(),
            cached_keys: HashMap::new(),
            pd: PhantomData,
        })
    }

    pub fn reload_with_storage(
        id: NodeId,
        mut storage: S,
        key: Key<KEY_SZ>,
    ) -> Result<Self, Error> {
        // Load the root node.
        let root = Node::load::<C, S>(id, key, &mut storage)?;

        // Load the metadata.
        let meta = Self::load_meta(root.id, &mut storage)?;

        Ok(Self {
            len: meta.len,
            degree: meta.degree,
            updated: meta.updated,
            updated_blocks: meta.updated_blocks,
            in_flight_blocks: meta.in_flight_blocks,
            root,
            meta_id: meta.meta_id,
            rng: R::default(),
            storage,
            cached_keys: HashMap::new(),
            pd: PhantomData,
        })
    }

    fn load_meta(root_id: u64, storage: &mut S) -> Result<BKeyTreeMeta<KEY_SZ>, Error>
    where
        S: Storage<Id = u64>,
    {
        let meta_id = {
            let mut reader = storage.read_handle(&root_id).map_err(|_| Error::Storage)?;
            reader
                .seek(SeekFrom::End(-1 * mem::size_of::<u64>() as i64))
                .map_err(|_| Error::Seek)?;
            utils::read_u64::<S>(&mut reader)?
        };

        let mut reader = storage.read_handle(&meta_id).map_err(|_| Error::Storage)?;

        let len = utils::read_u64::<S>(&mut reader)?;
        let degree = utils::read_u64::<S>(&mut reader)?;

        let updated_raw = utils::read_length_prefixed_bytes_clear::<S>(&mut reader)?;
        let updated = bincode::deserialize(&updated_raw).map_err(|_| Error::Deserialization)?;

        let updated_blocks_raw = utils::read_length_prefixed_bytes_clear::<S>(&mut reader)?;
        let updated_blocks =
            bincode::deserialize(&updated_blocks_raw).map_err(|_| Error::Deserialization)?;

        let in_flight_blocks_raw = utils::read_length_prefixed_bytes_clear::<S>(&mut reader)?;
        let in_flight_blocks = utils::deserialize_keys_map::<KEY_SZ>(&in_flight_blocks_raw);

        Ok(BKeyTreeMeta {
            meta_id,
            len: len as usize,
            degree: degree as usize,
            updated,
            updated_blocks,
            in_flight_blocks,
        })
    }

    fn persist_meta(&mut self) -> Result<(), Error>
    where
        S: Storage<Id = u64>,
    {
        {
            let mut writer = self
                .storage
                .write_handle(&self.root.id)
                .map_err(|_| Error::Storage)?;
            writer.seek(SeekFrom::End(0)).map_err(|_| Error::Seek)?;
            utils::write_u64::<S>(&mut writer, self.meta_id)?;
        }

        let mut writer = self
            .storage
            .write_handle(&self.meta_id)
            .map_err(|_| Error::Storage)?;

        utils::write_u64::<S>(&mut writer, self.len as u64)?;
        utils::write_u64::<S>(&mut writer, self.degree as u64)?;

        let updated_raw = bincode::serialize(&self.updated).map_err(|_| Error::Serialization)?;
        utils::write_length_prefixed_bytes_clear::<S>(&mut writer, &updated_raw)?;

        let updated_blocks_raw =
            bincode::serialize(&self.updated_blocks).map_err(|_| Error::Serialization)?;
        utils::write_length_prefixed_bytes_clear::<S>(&mut writer, &updated_blocks_raw)?;

        let in_flight_blocks_raw = utils::serialize_keys_map(&self.in_flight_blocks);
        utils::write_length_prefixed_bytes_clear::<S>(&mut writer, &in_flight_blocks_raw)?;

        Ok(())
    }

    fn persist_meta_to<T: Storage<Id = u64>>(&mut self, storage: &mut T) -> Result<(), Error> {
        {
            let mut writer = storage
                .write_handle(&self.root.id)
                .map_err(|_| Error::Storage)?;
            writer.seek(SeekFrom::End(0)).map_err(|_| Error::Seek)?;
            utils::write_u64::<T>(&mut writer, self.meta_id)?;
        }

        let mut writer = storage
            .write_handle(&self.meta_id)
            .map_err(|_| Error::Storage)?;

        utils::write_u64::<T>(&mut writer, self.len as u64)?;
        utils::write_u64::<T>(&mut writer, self.degree as u64)?;

        let updated_raw = bincode::serialize(&self.updated).map_err(|_| Error::Serialization)?;
        utils::write_length_prefixed_bytes_clear::<T>(&mut writer, &updated_raw)?;

        let updated_blocks_raw =
            bincode::serialize(&self.updated_blocks).map_err(|_| Error::Serialization)?;
        utils::write_length_prefixed_bytes_clear::<T>(&mut writer, &updated_blocks_raw)?;

        let in_flight_blocks_raw = utils::serialize_keys_map(&self.in_flight_blocks);
        utils::write_length_prefixed_bytes_clear::<T>(&mut writer, &in_flight_blocks_raw)?;

        Ok(())
    }

    pub fn load(&mut self, id: NodeId, key: Key<KEY_SZ>) -> Result<(), Error> {
        // Load the root node.
        let root = Node::load::<C, S>(id, key, &mut self.storage)?;

        // Load the metadata.
        let meta = Self::load_meta(root.id, &mut self.storage)?;

        // Update state after the fallible operations.
        self.root = root;
        self.meta_id = meta.meta_id;
        self.len = meta.len;
        self.degree = meta.degree;
        self.updated = meta.updated;
        self.updated_blocks = meta.updated_blocks;
        self.in_flight_blocks = meta.in_flight_blocks;

        Ok(())
    }

    pub fn persist(&mut self, key: Key<KEY_SZ>) -> Result<(), Error> {
        // Persist the root node.
        self.root
            .persist::<C, S>(key, &mut self.storage)
            .map_err(|_| Error::Storage)?;

        // Persist the metadata.
        self.persist_meta()?;

        Ok(())
    }

    pub fn persist_to<T: Storage<Id = u64>>(
        &mut self,
        key: Key<KEY_SZ>,
        storage: &mut T,
    ) -> Result<(), Error> {
        // Persist the root node.
        self.root
            .persist::<C, T>(key, storage)
            .map_err(|_| Error::Storage)?;

        // Persist the metadata.
        self.persist_meta_to(storage)?;

        Ok(())
    }

    pub fn persist_block(&mut self, block: &BlockId, key: Key<KEY_SZ>) -> Result<bool, Error> {
        // If the block is in-flight, insert without marking nodes in the path as updated.
        if let Some(block_key) = self.in_flight_blocks.remove(block) {
            self.insert_no_update(*block, block_key)?;
        }

        // Persist the block, persisting any nodes along the way.
        let res = self
            .root
            .persist_block::<C, S>(block, key, &mut self.storage)?;

        // Persist the metadata if we persisted the block.
        if res {
            self.persist_meta()?;
        }

        Ok(res)
    }

    pub fn persist_block_to<T: Storage<Id = u64>>(
        &mut self,
        block: &BlockId,
        key: Key<KEY_SZ>,
        storage: &mut T,
    ) -> Result<bool, Error> {
        // If the block is in-flight, insert without marking nodes in the path as updated.
        if let Some(block_key) = self.in_flight_blocks.remove(block) {
            self.insert_no_update(*block, block_key)?;
        }

        // Persist the block, persisting any nodes along the way.
        let res = self.root.persist_block::<C, T>(block, key, storage)?;

        // Persist the metadata if we persisted the block.
        if res {
            self.persist_meta_to(storage)?;
        }

        Ok(res)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn root_id(&self) -> u64 {
        self.root.id
    }

    pub fn contains(&mut self, k: &BlockId) -> Result<bool, Error> {
        Ok(self.get(k)?.is_some())
    }

    pub fn get(&mut self, k: &BlockId) -> Result<Option<&Key<KEY_SZ>>, Error> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &node.vals[idx]))
    }

    pub fn get_node(&mut self, k: &BlockId) -> Result<Option<&Node<KEY_SZ>>, Error> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(_, node)| node))
    }

    pub fn get_mut(&mut self, k: &BlockId) -> Result<Option<&mut Key<KEY_SZ>>, Error> {
        Ok(self
            .root
            .get_mut::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &mut node.vals[idx]))
    }

    pub fn get_key_value(
        &mut self,
        k: &BlockId,
    ) -> Result<Option<(&BlockId, &Key<KEY_SZ>)>, Error> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| (&node.keys[idx], &node.vals[idx])))
    }

    /// Inserts a key while marking any of the nodes touched on the way down as updated.
    pub fn insert(&mut self, k: BlockId, v: Key<KEY_SZ>) -> Result<Option<Key<KEY_SZ>>, Error> {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);

            self.updated.insert(self.root.id);
            self.updated.insert(new_root.id);

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.split_child(
                0,
                self.degree,
                &mut self.storage,
                &mut self.rng,
                &mut self.updated,
                true,
            )?;
        }

        let res = self.root.insert_nonfull::<C, R, S>(
            k,
            v,
            self.degree,
            &mut self.storage,
            &mut self.rng,
            &mut self.updated,
            true,
        )?;

        if res.is_none() {
            self.len += 1;
        }

        Ok(res)
    }

    /// Inserts a key without marking any of the nodes touched on the way down as updated.
    pub fn insert_no_update(
        &mut self,
        k: BlockId,
        v: Key<KEY_SZ>,
    ) -> Result<Option<Key<KEY_SZ>>, Error> {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);
            let new_root_key = self.generate_key();

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.children_keys.push(new_root_key);

            self.root.split_child(
                0,
                self.degree,
                &mut self.storage,
                &mut self.rng,
                &mut self.updated,
                false,
            )?;
        }

        let res = self.root.insert_nonfull::<C, R, S>(
            k,
            v,
            self.degree,
            &mut self.storage,
            &mut self.rng,
            &mut self.updated,
            false,
        )?;

        if res.is_none() {
            self.len += 1;
        }

        Ok(res)
    }

    /// Removes and marks nodes as updated.
    pub fn remove(&mut self, k: &BlockId) -> Result<Option<Key<KEY_SZ>>, Error> {
        Ok(self.remove_entry(k)?.map(|(_, val)| val))
    }

    /// Removes an entry and marks nodes as updated.
    pub fn remove_entry(&mut self, k: &BlockId) -> Result<Option<(BlockId, Key<KEY_SZ>)>, Error> {
        // We do this to make it easier to mark updated nodes when removing.
        if !self.contains(k)? {
            return Ok(None);
        }

        if let Some(entry) =
            self.root
                .remove::<C, S>(k, self.degree, &mut self.storage, &mut self.updated, true)?
        {
            if !self.root.is_leaf() && self.root.is_empty() {
                self.root = self.root.children.pop().unwrap().as_option_owned().unwrap();
            }
            self.len -= 1;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Removes without marking nodes as updated.
    pub fn remove_no_update(&mut self, k: &BlockId) -> Result<Option<Key<KEY_SZ>>, Error> {
        Ok(self.remove_entry_no_update(k)?.map(|(_, val)| val))
    }

    /// Removes an entry without marking nodes as updated.
    pub fn remove_entry_no_update(
        &mut self,
        k: &BlockId,
    ) -> Result<Option<(BlockId, Key<KEY_SZ>)>, Error> {
        if !self.contains(k)? {
            return Ok(None);
        }

        if let Some(entry) =
            self.root
                .remove::<C, S>(k, self.degree, &mut self.storage, &mut self.updated, false)?
        {
            if !self.root.is_leaf() && self.root.is_empty() {
                self.root = self.root.children.pop().unwrap().as_option_owned().unwrap();
            }
            self.len -= 1;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn clear(&mut self) -> Result<NodeId, Error> {
        self.len = 0;
        self.root.clear::<C, S>(&mut self.storage)?;
        self.root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);
        Ok(self.root.id)
    }

    fn generate_key(&mut self) -> Key<KEY_SZ> {
        let mut key = [0; KEY_SZ];
        self.rng.fill_bytes(&mut key);
        key
    }
}

impl<R, S, C, const KEY_SZ: usize> KeyManagementScheme for BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    type Key = Key<KEY_SZ>;
    type KeyId = BlockId;
    type Error = Error;

    fn derive(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        if let Some(key) = self.cached_keys.get(&block_id) {
            return Ok(*key);
        }

        if let Some(key) = self.get(&block_id)? {
            return Ok(*key);
        }

        if let Some(key) = self.in_flight_blocks.get(&block_id) {
            return Ok(*key);
        }

        let key = self.generate_key();
        self.in_flight_blocks.insert(block_id, key);
        self.cached_keys.insert(block_id, key);

        Ok(key)
    }

    fn update(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        let key = self.derive(block_id)?;
        self.updated_blocks.insert(block_id);
        Ok(key)
    }

    // TODO: Fix in key management trait that commit can be fallible.
    fn commit(
        &mut self,
        _rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<(Self::KeyId, Self::Key)>, Self::Error> {
        // Add any in-flight blocks that haven't been updated.
        let inflight_blocks = self
            .in_flight_blocks
            .iter()
            .filter_map(|(k, v)| (!self.updated_blocks.contains(k)).then_some((*k, *v)))
            .collect::<Vec<_>>();

        for (block, key) in inflight_blocks.into_iter() {
            self.insert(block, key)?;
        }

        // Build our vector of blocks and pre-commit keys.
        let mut res = vec![];
        for block in self.updated_blocks.clone() {
            let key = self.derive(block)?;
            res.push((block, key));
        }

        // This will commit our changes, changing keys as necesssary to updated nodes as blocks.
        self.root
            .commit::<C, R, S>(
                &mut self.storage,
                &mut self.rng,
                &self.updated,
                &self.updated_blocks,
            )
            .unwrap();

        // Clear out our cached updates.
        self.updated.clear();
        self.in_flight_blocks.clear();
        self.updated_blocks.clear();
        self.cached_keys.clear();

        Ok(res)
    }
}
